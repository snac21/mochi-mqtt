// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/stretchr/testify/require"
)

func TestServerUnsubscribeClient(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	pk := packets.Subscription{Filter: "a/b/c", Qos: 1}
	cl.State.Subscriptions.Add("a/b/c", pk)
	s.Topics.Subscribe(cl.ID, pk)
	subs := s.Topics.Subscribers("a/b/c")
	require.Equal(t, 1, len(subs.Subscriptions))
	s.UnsubscribeClient(cl)
	subs = s.Topics.Subscribers("a/b/c")
	require.Equal(t, 0, len(subs.Subscriptions))
}

func TestServerProcessPacketSubscribe(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeMqtt5).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackMqtt5).RawBytes, buf)
}

func TestServerProcessPacketSubscribePacketIDInUse(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.State.Inflight.Set(packets.Packet{PacketID: 15, FixedHeader: packets.FixedHeader{Type: packets.Publish}})

	pkx := *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeMqtt5).Packet
	pkx.PacketID = 15
	go func() {
		err := s.processPacket(cl, pkx)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackPacketIDInUse).RawBytes, buf)
}

func TestServerProcessPacketSubscribeInvalid(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5

	err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeSpecQosMustPacketID).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationNoPacketID)
}

func TestServerProcessPacketSubscribeInvalidFilter(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeInvalidFilter).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackInvalidFilter).RawBytes, buf)
}

func TestServerProcessPacketSubscribeInvalidSharedNoLocal(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeInvalidSharedNoLocal).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackInvalidSharedNoLocal).RawBytes, buf)
}

func TestServerProcessSubscribeWithRetain(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribe).Packet)
		require.NoError(t, err)

		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, append(
		packets.TPacketData[packets.Suback].Get(packets.TSuback).RawBytes,
		packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).RawBytes...,
	), buf)
}

func TestServerProcessSubscribeDowngradeQos(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.MaximumQos = 1
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeMany).Packet)
		require.NoError(t, err)

		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{0, 1, 1}, buf[4:])
}

func TestServerProcessSubscribeWithRetainHandling1(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c"})
	s.Clients.Add(cl)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeRetainHandling1).Packet)
		require.NoError(t, err)

		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSuback).RawBytes, buf)
}

func TestServerProcessSubscribeWithRetainHandling2(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeRetainHandling2).Packet)
		require.NoError(t, err)

		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSuback).RawBytes, buf)
}

func TestServerProcessSubscribeWithNotRetainAsPublished(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeRetainAsPublished).Packet)
		require.NoError(t, err)

		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, append(
		packets.TPacketData[packets.Suback].Get(packets.TSuback).RawBytes,
		packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).RawBytes...,
	), buf)
}

func TestServerProcessSubscribeNoConnection(t *testing.T) {
	s := newServer()
	cl, r, _ := newTestClient()
	_ = r.Close()
	err := s.processSubscribe(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribe).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestServerProcessSubscribeACLCheckDeny(t *testing.T) {
	s := New(&Options{
		Logger: logger,
	})
	_ = s.Serve()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5

	go func() {
		err := s.processSubscribe(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribe).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackDeny).RawBytes, buf)
}

func TestServerProcessSubscribeACLCheckDenyObscure(t *testing.T) {
	s := New(&Options{
		Logger: logger,
	})
	_ = s.Serve()
	s.Options.Capabilities.Compatibilities.ObscureNotAuthorized = true
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5

	go func() {
		err := s.processSubscribe(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribe).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackUnspecifiedErrorMqtt5).RawBytes, buf)
}

func TestServerProcessSubscribeErrorDowngrade(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 3
	cl.State.packetID = 1 // just to match the same packet id (7) in the fixtures

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribeInvalidSharedNoLocal).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Suback].Get(packets.TSubackUnspecifiedError).RawBytes, buf)
}

func TestServerProcessPacketUnsubscribe(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b", Qos: 0})
	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Unsubscribe].Get(packets.TUnsubscribeMqtt5).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Unsuback].Get(packets.TUnsubackMqtt5).RawBytes, buf)
	require.Equal(t, int64(-1), atomic.LoadInt64(&s.Info.Subscriptions))
}

func TestServerProcessPacketUnsubscribePackedIDInUse(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.State.Inflight.Set(packets.Packet{PacketID: 15, FixedHeader: packets.FixedHeader{Type: packets.Publish}})
	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Unsubscribe].Get(packets.TUnsubscribeMqtt5).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Unsuback].Get(packets.TUnsubackPacketIDInUse).RawBytes, buf)
	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Subscriptions))
}

func TestServerProcessPacketUnsubscribeInvalid(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	err := s.processPacket(cl, *packets.TPacketData[packets.Unsubscribe].Get(packets.TUnsubscribeSpecQosMustPacketID).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationNoPacketID)
}

func TestServerSubscribe(t *testing.T) {
	handler := func(cl *Client, sub packets.Subscription, pk packets.Packet) {}

	s := newServerWithInlineClient()
	require.NotNil(t, s)

	tt := []struct {
		desc       string
		filter     string
		identifier int
		handler    InlineSubFn
		expect     error
	}{
		{
			desc:       "subscribe",
			filter:     "a/b/c",
			identifier: 1,
			handler:    handler,
			expect:     nil,
		},
		{
			desc:       "re-subscribe",
			filter:     "a/b/c",
			identifier: 1,
			handler:    handler,
			expect:     nil,
		},
		{
			desc:       "subscribe d/e/f",
			filter:     "d/e/f",
			identifier: 1,
			handler:    handler,
			expect:     nil,
		},
		{
			desc:       "re-subscribe d/e/f by different identifier",
			filter:     "d/e/f",
			identifier: 2,
			handler:    handler,
			expect:     nil,
		},
		{
			desc:       "subscribe different handler",
			filter:     "a/b/c",
			identifier: 1,
			handler:    func(cl *Client, sub packets.Subscription, pk packets.Packet) {},
			expect:     nil,
		},
		{
			desc:       "subscribe $SYS/info",
			filter:     "$SYS/info",
			identifier: 1,
			handler:    handler,
			expect:     nil,
		},
		{
			desc:       "subscribe invalid ###",
			filter:     "###",
			identifier: 1,
			handler:    handler,
			expect:     packets.ErrTopicFilterInvalid,
		},
		{
			desc:       "subscribe invalid handler",
			filter:     "a/b/c",
			identifier: 1,
			handler:    nil,
			expect:     packets.ErrInlineSubscriptionHandlerInvalid,
		},
	}

	for _, tx := range tt {
		t.Run(tx.desc, func(t *testing.T) {
			require.Equal(t, tx.expect, s.Subscribe(tx.filter, tx.identifier, tx.handler))
		})
	}
}

func TestServerSubscribeNoInlineClient(t *testing.T) {
	s := newServer()
	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {})
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInlineClientNotEnabled)
}

func TestServerUnsubscribe(t *testing.T) {
	handler := func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		// handler logic
	}

	s := newServerWithInlineClient()
	err := s.Subscribe("a/b/c", 1, handler)
	require.Nil(t, err)

	err = s.Subscribe("d/e/f", 1, handler)
	require.Nil(t, err)

	err = s.Subscribe("d/e/f", 2, handler)
	require.Nil(t, err)

	err = s.Unsubscribe("a/b/c", 1)
	require.Nil(t, err)

	err = s.Unsubscribe("d/e/f", 1)
	require.Nil(t, err)

	err = s.Unsubscribe("d/e/f", 2)
	require.Nil(t, err)

	err = s.Unsubscribe("not/exist", 1)
	require.Nil(t, err)

	err = s.Unsubscribe("#/#/invalid", 1)
	require.Equal(t, packets.ErrTopicFilterInvalid, err)
}

func TestServerUnsubscribeNoInlineClient(t *testing.T) {
	s := newServer()
	err := s.Unsubscribe("a/b/c", 1)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInlineClientNotEnabled)
}

func TestServerSubscribeWithRetain(t *testing.T) {
	s := newServerWithInlineClient()
	subNumber := 1
	finishCh := make(chan bool, subNumber)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "a/b/c", sub.Filter)
		require.Equal(t, 1, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)
	require.Equal(t, true, <-finishCh)
}

func TestServerSubscribeWithRetainDifferentFilter(t *testing.T) {
	s := newServerWithInlineClient()
	subNumber := 2
	finishCh := make(chan bool, subNumber)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)
	retained = s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishCopyBasic).Packet)
	require.Equal(t, int64(1), retained)

	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "a/b/c", sub.Filter)
		require.Equal(t, 1, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)

	err = s.Subscribe("z/e/n", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("mochi mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "z/e/n", sub.Filter)
		require.Equal(t, 1, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)

	for i := 0; i < subNumber; i++ {
		require.Equal(t, true, <-finishCh)
	}
}

func TestServerSubscribeWithRetainDifferentIdentifier(t *testing.T) {
	s := newServerWithInlineClient()
	subNumber := 2
	finishCh := make(chan bool, subNumber)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "a/b/c", sub.Filter)
		require.Equal(t, 1, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)

	err = s.Subscribe("a/b/c", 2, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "a/b/c", sub.Filter)
		require.Equal(t, 2, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)

	for i := 0; i < subNumber; i++ {
		require.Equal(t, true, <-finishCh)
	}
}
