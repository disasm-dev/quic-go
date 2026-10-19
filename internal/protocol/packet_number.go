package protocol

// A PacketNumber in QUIC
type PacketNumber int64

// InvalidPacketNumber is a packet number that is never sent.
// In QUIC, 0 is a valid packet number.
const InvalidPacketNumber PacketNumber = -1

// PacketNumberLen is the length of the packet number in bytes
type PacketNumberLen uint8

const (
	// PacketNumberLen1 is a packet number length of 1 byte
	PacketNumberLen1 PacketNumberLen = 1
	// PacketNumberLen2 is a packet number length of 2 bytes
	PacketNumberLen2 PacketNumberLen = 2
	// PacketNumberLen3 is a packet number length of 3 bytes
	PacketNumberLen3 PacketNumberLen = 3
	// PacketNumberLen4 is a packet number length of 4 bytes
	PacketNumberLen4 PacketNumberLen = 4
)

// DecodePacketNumber calculates the packet number based its length and the last seen packet number
// This function is taken from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3.
func DecodePacketNumber(length PacketNumberLen, largest PacketNumber, truncated PacketNumber) PacketNumber {
	expected := largest + 1
	win := PacketNumber(1 << (length * 8))
	hwin := win / 2
	mask := win - 1
	candidate := (expected & ^mask) | truncated
	if candidate <= expected-hwin && candidate < 1<<62-win {
		return candidate + win
	}
	if candidate > expected+hwin && candidate >= win {
		return candidate - win
	}
	return candidate
}

// PacketNumberLengthForDelta is the packet number length for a packet delta
// packets ahead of what the peer is awaiting, chosen as quiche does: the
// shortest encoding of four times delta. That is QuicFramer's
// GetMinPacketNumberLength, which never picks 3 bytes.
func PacketNumberLengthForDelta(delta PacketNumber) PacketNumberLen {
	switch d := 4 * delta; {
	case d < 1<<8:
		return PacketNumberLen1
	case d < 1<<16:
		return PacketNumberLen2
	default:
		return PacketNumberLen4
	}
}
