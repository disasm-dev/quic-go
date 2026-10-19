package protocol

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInvalidPacketNumberIsSmallerThanAllValidPacketNumbers(t *testing.T) {
	require.Less(t, InvalidPacketNumber, PacketNumber(0))
}

func TestPacketNumberLenHasCorrectValue(t *testing.T) {
	require.EqualValues(t, 1, PacketNumberLen1)
	require.EqualValues(t, 2, PacketNumberLen2)
	require.EqualValues(t, 3, PacketNumberLen3)
	require.EqualValues(t, 4, PacketNumberLen4)
}

func TestDecodePacketNumber(t *testing.T) {
	require.Equal(t, PacketNumber(255), DecodePacketNumber(PacketNumberLen1, 10, 255))
	require.Equal(t, PacketNumber(0), DecodePacketNumber(PacketNumberLen1, 10, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 127, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 128, 0))
	require.Equal(t, PacketNumber(256), DecodePacketNumber(PacketNumberLen1, 256+126, 0))
	require.Equal(t, PacketNumber(512), DecodePacketNumber(PacketNumberLen1, 256+127, 0))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff, 0xffff))
	require.Equal(t, PacketNumber(0xffff), DecodePacketNumber(PacketNumberLen2, 0xffff+1, 0xffff))

	// example from https://www.rfc-editor.org/rfc/rfc9000.html#section-a.3
	require.Equal(t, PacketNumber(0xa82f9b32), DecodePacketNumber(PacketNumberLen2, 0xa82f30ea, 0x9b32))
}

func TestPacketNumberLengthForDelta(t *testing.T) {
	// quiche: the shortest encoding of four times the delta, 1, 2 or 4 bytes.
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForDelta(0))
	require.Equal(t, PacketNumberLen1, PacketNumberLengthForDelta(63))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForDelta(64))
	require.Equal(t, PacketNumberLen2, PacketNumberLengthForDelta(1<<14-1))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForDelta(1<<14))
	require.Equal(t, PacketNumberLen4, PacketNumberLengthForDelta(1<<30))
}
