package quic

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/sardanioss/quic-go/internal/ackhandler"
	"github.com/sardanioss/quic-go/internal/protocol"
	"github.com/sardanioss/quic-go/internal/wire"
	"github.com/sardanioss/quic-go/quicvarint"

	"github.com/stretchr/testify/require"
)

// A 1900-byte ClientHello in 1250-byte packets: 1215 bytes of frames fit in
// each, so quiche shares the hello out as 948 bytes in the first packet (two
// frames) and 952 in the second, and the first frame is 55 to 86 bytes.
func TestChromeClientHelloLayout(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	seen := map[int]bool{}
	for range 2000 {
		first, last, ok := chromeClientHelloLayout(1900, 1215, rng)
		require.True(t, ok)
		require.GreaterOrEqual(t, first, 55)
		require.LessOrEqual(t, first, 86)
		require.Equal(t, 948, first+last)
		seen[first] = true
	}
	require.Len(t, seen, 32, "every first-frame length from 55 to 86 should come up")

	// It fits in one packet: no layout, the ordinary packing applies.
	_, _, ok := chromeClientHelloLayout(1100, 1215, rng)
	require.False(t, ok)
}

type chaosFrame struct {
	kind   string // "crypto", "ping", "pad", "ack"
	offset protocol.ByteCount
	data   []byte
	pad    int
}

// walkPayload decodes a payload byte by byte, keeping PADDING runs, which a
// frame parser skips.
func walkPayload(t *testing.T, b []byte) []chaosFrame {
	t.Helper()
	var out []chaosFrame
	parser := wire.NewFrameParser(false, false, false)
	for len(b) > 0 {
		switch b[0] {
		case 0x00:
			n := 0
			for n < len(b) && b[n] == 0 {
				n++
			}
			out = append(out, chaosFrame{kind: "pad", pad: n})
			b = b[n:]
		case 0x01:
			out = append(out, chaosFrame{kind: "ping"})
			b = b[1:]
		case 0x06:
			offset, l1, err := quicvarint.Parse(b[1:])
			require.NoError(t, err)
			length, l2, err := quicvarint.Parse(b[1+l1:])
			require.NoError(t, err)
			start := 1 + l1 + l2
			out = append(out, chaosFrame{kind: "crypto", offset: protocol.ByteCount(offset), data: b[start : start+int(length)]})
			b = b[start+int(length):]
		case 0x02:
			_, n, err := parser.ParseAckFrame(wire.FrameTypeAck, b[1:], protocol.EncryptionInitial, protocol.Version1)
			require.NoError(t, err)
			out = append(out, chaosFrame{kind: "ack"})
			b = b[1+n:]
		default:
			t.Fatalf("unexpected frame type %#x", b[0])
		}
	}
	return out
}

func testChaosPayload(withAck bool) (payload, []byte) {
	hello := make([]byte, 1900)
	for i := range hello {
		hello[i] = byte(i*7 + 3)
	}
	var pl payload
	if withAck {
		pl.ack = &wire.AckFrame{AckRanges: []wire.AckRange{{Smallest: 1, Largest: 3}}}
		pl.length += pl.ack.Length(protocol.Version1)
	}
	for _, f := range []*wire.CryptoFrame{
		{Offset: 0, Data: hello[:70]},
		{Offset: 1022, Data: hello[1022:]},
	} {
		pl.frames = append(pl.frames, ackhandler.Frame{Frame: f})
		pl.length += f.Length(protocol.Version1)
	}
	return pl, hello
}

// Whatever the draw, the protected payload is the same length as the plain
// one, carries exactly the same CRYPTO bytes, has 2 to 10 PINGs, and keeps an
// ACK first. Across draws the layout differs.
func TestChaosProtectorKeepsThePayloadIntact(t *testing.T) {
	for _, withAck := range []bool{false, true} {
		t.Run(fmt.Sprintf("ack=%v", withAck), func(t *testing.T) {
			layouts := map[string]bool{}
			for seed := range uint64(500) {
				pl, hello := testChaosPayload(withAck)
				const padding = 250
				rng := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
				out, applied, err := appendChaosProtectedPayload(nil, pl, padding, rng, protocol.Version1)
				require.NoError(t, err)
				require.True(t, applied)
				require.Len(t, out, int(pl.length)+padding)

				frames := walkPayload(t, out)
				got := make([]byte, len(hello))
				covered := make([]bool, len(hello))
				var pings, cryptos int
				var shape bytes.Buffer
				for i, f := range frames {
					switch f.kind {
					case "crypto":
						cryptos++
						for j, c := range f.data {
							require.False(t, covered[int(f.offset)+j], "byte %d sent twice", int(f.offset)+j)
							covered[int(f.offset)+j] = true
							got[int(f.offset)+j] = c
						}
					case "ping":
						pings++
					case "ack":
						require.Zero(t, i, "the ACK moved from the front")
					}
					shape.WriteString(f.kind[:1])
				}
				for j := range hello {
					inFrames := j < 70 || j >= 1022
					require.Equal(t, inFrames, covered[j], "byte %d", j)
					if inFrames {
						require.Equal(t, hello[j], got[j])
					}
				}
				require.GreaterOrEqual(t, pings, 2)
				require.LessOrEqual(t, pings, 10)
				require.GreaterOrEqual(t, cryptos, 2)
				layouts[shape.String()] = true
			}
			require.Greater(t, len(layouts), 400, "chaos protection keeps producing the same packet")
		})
	}
}

// quiche only protects a packet with a CRYPTO frame and padding to spend.
func TestChaosProtectorNeedsCryptoAndPadding(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	pl, _ := testChaosPayload(false)
	_, applied, err := appendChaosProtectedPayload(nil, pl, 0, rng, protocol.Version1)
	require.NoError(t, err)
	require.False(t, applied, "no padding, nothing to protect with")

	ping := payload{frames: []ackhandler.Frame{{Frame: &wire.PingFrame{}}}, length: 1}
	_, applied, err = appendChaosProtectedPayload(nil, ping, 100, rng, protocol.Version1)
	require.NoError(t, err)
	require.False(t, applied, "no CRYPTO frame")
}
