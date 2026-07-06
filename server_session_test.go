// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/stretchr/testify/require"
)

func TestInheritClientSession(t *testing.T) {
	s := newServer()

	n := time.Now().Unix()

	existing, _, _ := newTestClient()
	existing.Net.Transport = nil
	existing.ID = "mochi"
	existing.State.Subscriptions.Add("a/b/c", packets.Subscription{Filter: "a/b/c", Qos: 1})
	existing.State.Inflight = NewInflights()
	existing.State.Inflight.Set(packets.Packet{PacketID: 1, Created: n - 1})
	existing.State.Inflight.Set(packets.Packet{PacketID: 2, Created: n - 2})

	s.Clients.Add(existing)

	cl, _, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5

	require.Equal(t, 0, cl.State.Inflight.Len())
	require.Equal(t, 0, cl.State.Subscriptions.Len())

	// Inherit existing client properties
	b := s.inheritClientSession(packets.Packet{Connect: packets.ConnectParams{ClientIdentifier: "mochi"}}, cl)
	require.True(t, b)
	require.Equal(t, 2, cl.State.Inflight.Len())
	require.Equal(t, 1, cl.State.Subscriptions.Len())

	// On clean, clear existing properties
	cl, _, _ = newTestClient()
	cl.Properties.ProtocolVersion = 5
	b = s.inheritClientSession(packets.Packet{Connect: packets.ConnectParams{ClientIdentifier: "mochi", Clean: true}}, cl)
	require.False(t, b)
	require.Equal(t, 0, cl.State.Inflight.Len())
	require.Equal(t, 0, cl.State.Subscriptions.Len())
}

func TestServerImportSessionNilInputs(t *testing.T) {
	s := newServer()
	cl := s.NewClient(nil, "test", "client-nil", false)

	require.NoError(t, s.ImportSession(nil, nil))
	require.NoError(t, s.ImportSession(cl, nil))
	require.NoError(t, s.ImportSession(nil, &SessionSnapshot{ClientID: "client-nil"}))
}

func TestServerTakeoverSessionNotFound(t *testing.T) {
	s := newServer()

	snapshot, err := s.TakeoverSession("missing-client")
	require.Nil(t, snapshot)
	require.ErrorIs(t, err, ErrSessionNotFound)
}

func TestServerImportSessionRestoresInflightQuotas(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.ReceiveMaximum = 7

	cl := s.NewClient(nil, "test", "client-quota", false)
	cl.ID = "client-quota"
	cl.Properties.Props.ReceiveMaximum = 3

	snapshot := &SessionSnapshot{
		ClientID: cl.ID,
		Inflight: []packets.Packet{
			{
				FixedHeader: packets.FixedHeader{Type: packets.Publish, Qos: 1},
				TopicName:   "devices/1/up",
				Payload:     []byte("payload"),
				PacketID:    3,
			},
		},
	}

	err := s.ImportSession(cl, snapshot)
	require.NoError(t, err)
	require.Equal(t, 1, cl.State.Inflight.Len())
	require.Equal(t, int32(7), cl.State.Inflight.ReceiveQuota())
	require.Equal(t, int32(7), cl.State.Inflight.MaximumReceiveQuota())
	require.Equal(t, int32(3), cl.State.Inflight.SendQuota())
	require.Equal(t, int32(3), cl.State.Inflight.MaximumSendQuota())
}

func TestInheritClientSessionRestoresInflightQuotas(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.ReceiveMaximum = 6

	existing, r, _ := newTestClient()
	existing.Stop(nil)
	r.Close() // Close the pipe to ensure WriteLoop exits
	time.Sleep(10 * time.Millisecond) // Wait for WriteLoop to fully exit
	existing.ops.options.Capabilities.ReceiveMaximum = 6
	existing.Net.Transport = nil
	existing.ID = "client-quota-inherit"
	existing.State.Inflight = NewInflights()
	existing.State.Inflight.ResetReceiveQuota(0)
	existing.State.Inflight.ResetSendQuota(0)
	existing.State.Inflight.Set(packets.Packet{
		FixedHeader: packets.FixedHeader{Type: packets.Publish, Qos: 1},
		TopicName:   "devices/1/down",
		Payload:     []byte("payload"),
		PacketID:    4,
	})
	s.Clients.Add(existing)

	cl, _, _ := newTestClient()
	cl.ops.options.Capabilities.ReceiveMaximum = 6
	cl.ID = existing.ID
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Props.ReceiveMaximum = 2

	sessionPresent := s.inheritClientSession(packets.Packet{Connect: packets.ConnectParams{ClientIdentifier: existing.ID}}, cl)
	require.True(t, sessionPresent)
	require.Equal(t, 1, cl.State.Inflight.Len())
	require.Equal(t, int32(6), cl.State.Inflight.ReceiveQuota())
	require.Equal(t, int32(6), cl.State.Inflight.MaximumReceiveQuota())
	require.Equal(t, int32(2), cl.State.Inflight.SendQuota())
	require.Equal(t, int32(2), cl.State.Inflight.MaximumSendQuota())
}

func TestServerImportSession(t *testing.T) {
	s := newServer()
	cl := s.NewClient(nil, "test", "client-2", false)
	cl.ID = "client-2"

	snapshot := &SessionSnapshot{
		ClientID:     cl.ID,
		NextPacketID: 12,
		Subscriptions: []packets.Subscription{
			{Filter: "devices/#", Qos: 1},
		},
		Inflight: []packets.Packet{
			{
				FixedHeader: packets.FixedHeader{Type: packets.Publish, Qos: 1},
				TopicName:   "devices/1/up",
				Payload:     []byte("payload"),
				PacketID:    3,
			},
		},
	}

	err := s.ImportSession(cl, snapshot)
	require.NoError(t, err)
	require.Equal(t, uint32(12), cl.State.packetID)
	require.Len(t, cl.State.Subscriptions.GetAll(), 1)
	require.Equal(t, 1, cl.State.Inflight.Len())

	_, ok := s.Topics.Subscribers("devices/1/up").Subscriptions[cl.ID]
	require.True(t, ok)
}

func TestServerClearExpiredInflights(t *testing.T) {
	s := New(nil)
	require.NotNil(t, s)
	s.Options.Capabilities.MaximumMessageExpiryInterval = 4

	n := time.Now().Unix()
	cl, _, _ := newTestClient()
	cl.ops.info = s.Info

	cl.State.Inflight.Set(packets.Packet{PacketID: 1, Expiry: n - 1})
	cl.State.Inflight.Set(packets.Packet{PacketID: 2, Expiry: n - 2})
	cl.State.Inflight.Set(packets.Packet{PacketID: 3, Created: n - 3}) // within bounds
	cl.State.Inflight.Set(packets.Packet{PacketID: 5, Created: n - 5}) // over max server expiry limit
	cl.State.Inflight.Set(packets.Packet{PacketID: 7, Created: n})

	s.Clients.Add(cl)

	require.Len(t, cl.State.Inflight.GetAll(false), 5)
	s.clearExpiredInflights(n)
	require.Len(t, cl.State.Inflight.GetAll(false), 2)
	require.Equal(t, int64(-3), s.Info.Inflight)

	s.Options.Capabilities.MaximumMessageExpiryInterval = 0
	cl.State.Inflight.Set(packets.Packet{PacketID: 8, Expiry: n - 8})
	s.clearExpiredInflights(n)
	require.Len(t, cl.State.Inflight.GetAll(false), 3)
}

func TestServerClearExpiredRetained(t *testing.T) {
	s := New(nil)
	require.NotNil(t, s)
	s.Options.Capabilities.MaximumMessageExpiryInterval = 4

	n := time.Now().Unix()
	s.Topics.Retained.Add("a/b/c", packets.Packet{ProtocolVersion: 5, Created: n, Expiry: n - 1})
	s.Topics.Retained.Add("d/e/f", packets.Packet{ProtocolVersion: 5, Created: n, Expiry: n - 2})
	s.Topics.Retained.Add("g/h/i", packets.Packet{ProtocolVersion: 5, Created: n - 3}) // within bounds
	s.Topics.Retained.Add("j/k/l", packets.Packet{ProtocolVersion: 5, Created: n - 5}) // over max server expiry limit
	s.Topics.Retained.Add("m/n/o", packets.Packet{ProtocolVersion: 5, Created: n})

	require.Len(t, s.Topics.Retained.GetAll(), 5)
	s.clearExpiredRetainedMessages(n)
	require.Len(t, s.Topics.Retained.GetAll(), 2)

	s.Topics.Retained.Add("p/q/r", packets.Packet{Created: n, Expiry: n - 1})
	s.Topics.Retained.Add("s/t/u", packets.Packet{Created: n, Expiry: n - 2}) // expiry is ineffective for v3.
	s.Topics.Retained.Add("v/w/x", packets.Packet{Created: n - 3})            // within bounds for v3
	s.Topics.Retained.Add("y/z/1", packets.Packet{Created: n - 5})            // over max server expiry limit
	require.Len(t, s.Topics.Retained.GetAll(), 6)
	s.clearExpiredRetainedMessages(n)
	require.Len(t, s.Topics.Retained.GetAll(), 5)

	s.Options.Capabilities.MaximumMessageExpiryInterval = 0
	s.Topics.Retained.Add("2/3/4", packets.Packet{Created: n - 8})
	s.clearExpiredRetainedMessages(n)
	require.Len(t, s.Topics.Retained.GetAll(), 6)
}

func TestServerClearExpiredClients(t *testing.T) {
	s := New(nil)
	require.NotNil(t, s)

	n := time.Now().Unix()

	cl, _, _ := newTestClient()
	cl.ID = "cl"
	s.Clients.Add(cl)

	// No Expiry
	cl0, _, _ := newTestClient()
	cl0.ID = "c0"
	cl0.State.disconnected = n - 10
	cl0.State.cancelOpen()
	cl0.Properties.ProtocolVersion = 5
	cl0.Properties.Props.SessionExpiryInterval = 12
	cl0.Properties.Props.SessionExpiryIntervalFlag = true
	s.Clients.Add(cl0)

	// Normal Expiry
	cl1, _, _ := newTestClient()
	cl1.ID = "c1"
	cl1.State.disconnected = n - 10
	cl1.State.cancelOpen()
	cl1.Properties.ProtocolVersion = 5
	cl1.Properties.Props.SessionExpiryInterval = 8
	cl1.Properties.Props.SessionExpiryIntervalFlag = true
	s.Clients.Add(cl1)

	// No Expiry, indefinite session
	cl2, _, _ := newTestClient()
	cl2.ID = "c2"
	cl2.State.disconnected = n - 10
	cl2.State.cancelOpen()
	cl2.Properties.ProtocolVersion = 5
	cl2.Properties.Props.SessionExpiryInterval = 0
	cl2.Properties.Props.SessionExpiryIntervalFlag = true
	s.Clients.Add(cl2)

	require.Equal(t, 4, s.Clients.Len())

	s.clearExpiredClients(n)
	require.Equal(t, 2, s.Clients.Len())
}
