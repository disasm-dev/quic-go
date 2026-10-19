package quic

import (
	"fmt"
	"math/rand/v2"

	"github.com/sardanioss/quic-go/internal/ackhandler"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/wire"
	"github.com/sardanioss/quic-go/quicvarint"
)

// Chrome's client Initial packets, as built by quiche.
//
// quiche does two things to a ClientHello, and ChromeStyleInitialPackets turns
// both on.
//
// It lays out a ClientHello too big for one packet so that the first packet
// carries the start and the end of it, and the packets after carry the middle
// in order (QuicPacketCreator::MultiPacketChaosProtect). The start is the
// fixed header plus the length of the first extension, about 55 bytes and
// some randomness on top, so no one packet parses on its own.
//
// Then, as each client Initial packet is serialized, QuicChaosProtector
// rebuilds it: CRYPTO frames split at random points, PING frames added,
// the packet's padding broken up and spread between frames, and everything
// shuffled. The packet stays the same size; the frame overhead the splits add
// comes out of the padding.
//
// Both are ports of quiche's code, randomness included, so the distributions
// match rather than just the general shape. The previous version cut the
// ClientHello into equal 75-byte pieces with a PING after every second one and
// five single padding bytes at fixed places, which is one fixed pattern where
// Chrome never sends the same packet twice.

// cryptoFrameOverhead is quiche's QuicFramer::GetMinCryptoFrameSize: the frame
// type, then offset and length as varints.
func cryptoFrameOverhead(offset protocol.ByteCount, length int) int {
	return 1 + quicvarint.Len(uint64(offset)) + quicvarint.Len(uint64(length))
}

// chromeClientHelloLayout is MultiPacketChaosProtect's arithmetic. For a
// ClientHello of helloLen bytes, starting at offset 0, and a first packet with
// room for capacity bytes of frames, it returns how long the leading and the
// trailing CRYPTO frame in that first packet are. ok is false when quiche would
// not do this: the whole ClientHello fits in the first packet, or the packets
// are too small for it.
//
// Every later packet takes one CRYPTO frame filling the packet, so the packet
// count comes out the same as without the split and the data is shared out
// evenly between the packets, the first one's two frame headers included:
//
//	size_t num_packets = (write_length + first_packet_occupied_space +
//	                      max_crypto_data_length_other_packets - 1) /
//	                     max_crypto_data_length_other_packets;
//	size_t data_in_other_packets =
//	    (write_length + first_packet_occupied_space + num_packets - 1) /
//	    num_packets;
//	...
//	size_t first_frame_length =
//	    kMinFirstFrameLength +
//	    (random_->InsecureRandUint64() % kFirstFrameLengthRandom);
func chromeClientHelloLayout(helloLen, capacity int, rng *rand.Rand) (firstLen, lastLen int, ok bool) {
	const (
		minFirstFrameLength    = 55 // kMinFirstFrameLength
		firstFrameLengthRandom = 32 // kFirstFrameLengthRandom
	)
	minFrameSize := cryptoFrameOverhead(protocol.ByteCount(helloLen-1), helloLen)
	if capacity < 2*minFrameSize {
		return 0, 0, false
	}
	firstPacket := capacity - 2*minFrameSize // max_crypto_data_length_first_packet
	otherPackets := capacity - minFrameSize  // max_crypto_data_length_other_packets
	if helloLen <= firstPacket {
		return 0, 0, false
	}
	occupied := otherPackets - firstPacket
	numPackets := (helloLen + occupied + otherPackets - 1) / otherPackets
	dataInOther := (helloLen + occupied + numPackets - 1) / numPackets
	if dataInOther < occupied {
		return 0, 0, false
	}
	dataInFirst := dataInOther - occupied
	firstLen = minFirstFrameLength + int(rng.Uint64()%firstFrameLengthRandom)
	if helloLen <= firstLen || dataInFirst <= firstLen {
		return 0, 0, false
	}
	return firstLen, dataInFirst - firstLen, true
}

// chaosItem is one entry of a packet being chaos protected.
type chaosItem struct {
	kind    chaosKind
	crypto  wire.CryptoFrame // chaosCrypto
	frame   wire.Frame       // chaosOther, and the ACK
	padding int              // chaosPadding
}

type chaosKind uint8

const (
	chaosCrypto chaosKind = iota
	chaosPing
	chaosPadding
	chaosAck
	chaosOther
)

// appendChaosProtectedPayload writes a client Initial payload the way
// QuicChaosProtector::BuildDataPacket does:
//
//	SplitCryptoFrame();
//	AddPingFrames();
//	SpreadPadding();
//	ReorderFrames();
//
// It writes exactly pl.length+paddingLen bytes, as the unprotected payload
// would. applies is false, and nothing is written, where quiche would not
// protect the packet: no CRYPTO frame, or no padding to work with.
//
// Only the bytes change. pl.frames keeps the frames as they were packed, which
// is what loss recovery tracks; quiche too retransmits the original frames
// rather than the pieces.
func appendChaosProtectedPayload(raw []byte, pl payload, paddingLen protocol.ByteCount, rng *rand.Rand, v protocol.Version) (out []byte, applies bool, _ error) {
	if paddingLen <= 0 || len(pl.streamFrames) > 0 {
		return raw, false, nil
	}
	items := make([]chaosItem, 0, 2*len(pl.frames)+24)
	if pl.ack != nil {
		items = append(items, chaosItem{kind: chaosAck, frame: pl.ack})
	}
	var cryptoStart, cryptoEnd protocol.ByteCount
	hasCrypto := false
	for _, f := range pl.frames {
		cf, ok := f.Frame.(*wire.CryptoFrame)
		if !ok {
			items = append(items, chaosItem{kind: chaosOther, frame: f.Frame})
			continue
		}
		end := cf.Offset + protocol.ByteCount(len(cf.Data))
		if !hasCrypto {
			cryptoStart, cryptoEnd = cf.Offset, end
		} else {
			cryptoStart, cryptoEnd = min(cryptoStart, cf.Offset), max(cryptoEnd, end)
		}
		hasCrypto = true
		items = append(items, chaosItem{kind: chaosCrypto, crypto: *cf})
	}
	if !hasCrypto {
		return raw, false, nil
	}
	remaining := int(paddingLen)

	// SplitCryptoFrame: between 2 and 10 attempts, each picking an entry at
	// random and splitting it if it is a CRYPTO frame with 2 or more bytes.
	maxOverhead := cryptoFrameOverhead(cryptoEnd, int(cryptoEnd-cryptoStart))
	numAdded := 2 + rng.Uint64()%9
	for range numAdded {
		if remaining < maxOverhead {
			break
		}
		idx := rng.Uint64() % uint64(len(items))
		if items[idx].kind != chaosCrypto {
			continue
		}
		cf := &items[idx].crypto
		n := len(cf.Data)
		if n <= 1 {
			continue
		}
		oldOverhead := cryptoFrameOverhead(cf.Offset, n)
		keep := 1 + int(rng.Uint64()%uint64(n-1))
		tail := wire.CryptoFrame{Offset: cf.Offset + protocol.ByteCount(keep), Data: cf.Data[keep:]}
		cf.Data = cf.Data[:keep]
		remaining -= cryptoFrameOverhead(tail.Offset, len(tail.Data))
		remaining -= cryptoFrameOverhead(cf.Offset, keep)
		remaining += oldOverhead
		items = append(items, chaosItem{kind: chaosCrypto, crypto: tail})
	}

	// AddPingFrames: between 2 and 10, one padding byte each.
	if remaining != 0 {
		numPings := min(2+int(rng.Uint64()%9), remaining)
		for range numPings {
			items = append(items, chaosItem{kind: chaosPing})
		}
		remaining -= numPings
	}

	// SpreadPadding: ahead of each entry, anything from none to all of what
	// is left, never ahead of an ACK; whatever remains goes at the end.
	spread := make([]chaosItem, 0, 2*len(items)+1)
	for _, it := range items {
		pad := int(rng.Uint64() % uint64(remaining+1))
		if pad > 0 && it.kind != chaosAck {
			spread = append(spread, chaosItem{kind: chaosPadding, padding: pad})
			remaining -= pad
		}
		spread = append(spread, it)
	}
	if remaining > 0 {
		spread = append(spread, chaosItem{kind: chaosPadding, padding: remaining})
	}
	items = spread

	// ReorderFrames: Fisher-Yates from the back, skipping any swap that would
	// move an ACK.
	for i := len(items) - 1; i > 0; i-- {
		j := rng.Uint64() % uint64(i+1)
		if items[i].kind != chaosAck && items[j].kind != chaosAck {
			items[i], items[j] = items[j], items[i]
		}
	}

	start := len(raw)
	for _, it := range items {
		var err error
		switch it.kind {
		case chaosCrypto:
			raw, err = it.crypto.Append(raw, v)
		case chaosPing:
			raw, err = (&wire.PingFrame{}).Append(raw, v)
		case chaosPadding:
			raw = append(raw, make([]byte, it.padding)...)
		default:
			raw, err = it.frame.Append(raw, v)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if got, want := protocol.ByteCount(len(raw)-start), pl.length+paddingLen; got != want {
		return nil, false, fmt.Errorf("chaos protector BUG: wrote %d bytes, want %d", got, want)
	}
	return raw, true, nil
}

// chromeFirstPacketFrames packs the first Initial packet of a ClientHello too
// big for one packet: the leading and the trailing CRYPTO frame of
// chromeClientHelloLayout. It returns nil when the layout does not apply, and
// the caller packs the packet as usual.
func (p *packetPacker) chromeFirstPacketFrames(capacity protocol.ByteCount, handler ackhandler.FrameHandler, v protocol.Version) ([]ackhandler.Frame, protocol.ByteCount) {
	s := p.initialStream
	if s == nil || !s.isClient || !s.clientHelloComplete || s.scramble || s.writeOffset != 0 || len(s.writeBuf) == 0 {
		return nil, 0
	}
	firstLen, lastLen, ok := chromeClientHelloLayout(len(s.writeBuf), int(capacity), &p.rand)
	if !ok {
		return nil, 0
	}
	first := s.popFront(protocol.ByteCount(firstLen))
	last := s.popBack(protocol.ByteCount(lastLen))
	frames := []ackhandler.Frame{
		{Frame: first, Handler: handler},
		{Frame: last, Handler: handler},
	}
	return frames, first.Length(v) + last.Length(v)
}
