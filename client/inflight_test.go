// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package client

import (
	"testing"

	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/stretchr/testify/require"
)

func TestInflightSet(t *testing.T) {
	cl, _, _ := newTestClient()

	r := cl.State.Inflight.Set(packets.Packet{PacketID: 1})
	require.True(t, r)
	require.NotNil(t, cl.State.Inflight.internal[1])
	require.NotEqual(t, 0, cl.State.Inflight.internal[1].PacketID)

	r = cl.State.Inflight.Set(packets.Packet{PacketID: 1})
	require.False(t, r)
}

func TestInflightGet(t *testing.T) {
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 2})

	msg, ok := cl.State.Inflight.Get(2)
	require.True(t, ok)
	require.NotEqual(t, 0, msg.PacketID)
}

func TestInflightGetAllAndImmediate(t *testing.T) {
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 1, Created: 1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 2, Created: 2})
	cl.State.Inflight.Set(packets.Packet{PacketID: 3, Created: 3, Expiry: -1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 4, Created: 4, Expiry: -1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 5, Created: 5})

	require.Equal(t, []packets.Packet{
		{PacketID: 1, Created: 1},
		{PacketID: 2, Created: 2},
		{PacketID: 3, Created: 3, Expiry: -1},
		{PacketID: 4, Created: 4, Expiry: -1},
		{PacketID: 5, Created: 5},
	}, cl.State.Inflight.GetAll(false))

	require.Equal(t, []packets.Packet{
		{PacketID: 3, Created: 3, Expiry: -1},
		{PacketID: 4, Created: 4, Expiry: -1},
	}, cl.State.Inflight.GetAll(true))
}

func TestInflightLen(t *testing.T) {
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 2})
	require.Equal(t, 1, cl.State.Inflight.Len())
}

func TestInflightClone(t *testing.T) {
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 2})
	require.Equal(t, 1, cl.State.Inflight.Len())

	cloned := cl.State.Inflight.Clone()
	require.NotNil(t, cloned)
	require.NotSame(t, cloned, cl.State.Inflight)
}

func TestInflightDelete(t *testing.T) {
	cl, _, _ := newTestClient()

	cl.State.Inflight.Set(packets.Packet{PacketID: 3})
	require.NotNil(t, cl.State.Inflight.internal[3])

	r := cl.State.Inflight.Delete(3)
	require.True(t, r)
	require.Equal(t, uint16(0), cl.State.Inflight.internal[3].PacketID)

	_, ok := cl.State.Inflight.Get(3)
	require.False(t, ok)

	r = cl.State.Inflight.Delete(3)
	require.False(t, r)
}

func TestResetReceiveQuota(t *testing.T) {
	i := NewInflights()
	require.Equal(t, int32(0), i.MaximumReceiveQuota())
	require.Equal(t, int32(0), i.ReceiveQuota())
	i.ResetReceiveQuota(6)
	require.Equal(t, int32(6), i.MaximumReceiveQuota())
	require.Equal(t, int32(6), i.ReceiveQuota())
}

func TestReceiveQuota(t *testing.T) {
	i := NewInflights()
	i.receiveQuotaState.value = 4
	i.receiveQuotaState.maximum = 5
	require.Equal(t, int32(5), i.MaximumReceiveQuota())
	require.Equal(t, int32(4), i.ReceiveQuota())

	// Return 1
	i.IncreaseReceiveQuota()
	require.Equal(t, int32(5), i.MaximumReceiveQuota())
	require.Equal(t, int32(5), i.ReceiveQuota())

	// Try to go over max limit
	i.IncreaseReceiveQuota()
	require.Equal(t, int32(5), i.MaximumReceiveQuota())
	require.Equal(t, int32(5), i.ReceiveQuota())

	// Reset to max 1
	i.ResetReceiveQuota(1)
	require.Equal(t, int32(1), i.MaximumReceiveQuota())
	require.Equal(t, int32(1), i.ReceiveQuota())

	// Take 1
	i.DecreaseReceiveQuota()
	require.Equal(t, int32(1), i.MaximumReceiveQuota())
	require.Equal(t, int32(0), i.ReceiveQuota())

	// Try to go below zero
	i.DecreaseReceiveQuota()
	require.Equal(t, int32(1), i.MaximumReceiveQuota())
	require.Equal(t, int32(0), i.ReceiveQuota())
}

func TestResetSendQuota(t *testing.T) {
	i := NewInflights()
	require.Equal(t, int32(0), i.MaximumSendQuota())
	require.Equal(t, int32(0), i.SendQuota())
	i.ResetSendQuota(6)
	require.Equal(t, int32(6), i.MaximumSendQuota())
	require.Equal(t, int32(6), i.SendQuota())
}

func TestSendQuota(t *testing.T) {
	i := NewInflights()
	i.sendQuotaState.value = 4
	i.sendQuotaState.maximum = 5
	require.Equal(t, int32(5), i.MaximumSendQuota())
	require.Equal(t, int32(4), i.SendQuota())

	// Return 1
	i.IncreaseSendQuota()
	require.Equal(t, int32(5), i.MaximumSendQuota())
	require.Equal(t, int32(5), i.SendQuota())

	// Try to go over max limit
	i.IncreaseSendQuota()
	require.Equal(t, int32(5), i.MaximumSendQuota())
	require.Equal(t, int32(5), i.SendQuota())

	// Reset to max 1
	i.ResetSendQuota(1)
	require.Equal(t, int32(1), i.MaximumSendQuota())
	require.Equal(t, int32(1), i.SendQuota())

	// Take 1
	i.DecreaseSendQuota()
	require.Equal(t, int32(1), i.MaximumSendQuota())
	require.Equal(t, int32(0), i.SendQuota())

	// Try to go below zero
	i.DecreaseSendQuota()
	require.Equal(t, int32(1), i.MaximumSendQuota())
	require.Equal(t, int32(0), i.SendQuota())
}

func TestNextImmediate(t *testing.T) {
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 1, Created: 1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 2, Created: 2})
	cl.State.Inflight.Set(packets.Packet{PacketID: 3, Created: 3, Expiry: -1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 4, Created: 4, Expiry: -1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 5, Created: 5})

	pk, ok := cl.State.Inflight.NextImmediate()
	require.True(t, ok)
	require.Equal(t, packets.Packet{PacketID: 3, Created: 3, Expiry: -1}, pk)

	r := cl.State.Inflight.Delete(3)
	require.True(t, r)

	pk, ok = cl.State.Inflight.NextImmediate()
	require.True(t, ok)
	require.Equal(t, packets.Packet{PacketID: 4, Created: 4, Expiry: -1}, pk)

	r = cl.State.Inflight.Delete(4)
	require.True(t, r)

	_, ok = cl.State.Inflight.NextImmediate()
	require.False(t, ok)
}
