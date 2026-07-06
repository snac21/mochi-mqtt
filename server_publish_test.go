// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/mochi-mqtt/server/v2/system"

	"github.com/stretchr/testify/require"
)

func TestServerProcessPacketPublishInvalid(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()

	err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishInvalidQosMustPacketID).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationNoPacketID)
}

func TestInjectPacketPublishAndReceive(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	sender, _, w1 := newTestClient()
	sender.Net.Inline = true
	sender.ID = "sender"
	s.Clients.Add(sender)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		err := s.InjectPacket(sender, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		require.NoError(t, err)
		_ = w1.Close()
		time.Sleep(time.Millisecond * 10)
		_ = w2.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
}

func TestServerPublishAndReceive(t *testing.T) {
	s := newServerWithInlineClient()

	_ = s.Serve()
	defer s.Close()

	sender, _, w1 := newTestClient()
	sender.Net.Inline = true
	sender.ID = "sender"
	s.Clients.Add(sender)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		err := s.Publish(pkx.TopicName, pkx.Payload, pkx.FixedHeader.Retain, pkx.FixedHeader.Qos)
		require.NoError(t, err)
		_ = w1.Close()
		time.Sleep(time.Millisecond * 10)
		_ = w2.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
}

func TestServerDispatchClusterPublish(t *testing.T) {
	s := newServerWithInlineClient()
	finishCh := make(chan bool, 1)

	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, "a/b/c", pk.TopicName)
		finishCh <- true
	})
	require.NoError(t, err)

	err = s.DispatchClusterPublish(*packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	require.NoError(t, err)
	require.True(t, <-finishCh)
}

func TestServerDispatchClusterPublishInvalidPacketType(t *testing.T) {
	s := newServer()
	err := s.DispatchClusterPublish(packets.Packet{
		FixedHeader: packets.FixedHeader{
			Type: packets.Subscribe,
		},
	})
	require.ErrorIs(t, err, ErrClusterDispatchRequiresPublish)
}

func TestServerPublishNoInlineClient(t *testing.T) {
	s := newServer()
	pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
	err := s.Publish(pkx.TopicName, pkx.Payload, pkx.FixedHeader.Retain, pkx.FixedHeader.Qos)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrInlineClientNotEnabled)
}

func TestInjectPacketPublishInvalidTopic(t *testing.T) {
	s := newServer()
	defer s.Close()
	cl, _, _ := newTestClient()
	cl.Net.Inline = true
	pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
	pkx.TopicName = "$SYS/test"
	err := s.InjectPacket(cl, pkx)
	require.NoError(t, err) // bypass topic validity and acl checks
}

func TestServerProcessPacketPublishAndReceive(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	sender, _, w1 := newTestClient()
	sender.ID = "sender"
	s.Clients.Add(sender)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))
	require.Equal(t, 0, len(s.Topics.Messages("a/b/c")))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		err := s.processPacket(sender, *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
		require.NoError(t, err)
		time.Sleep(time.Millisecond * 10)
		_ = w1.Close()
		_ = w2.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
	require.Equal(t, 1, len(s.Topics.Messages("a/b/c")))
}

func TestServerProcessPublishAckFailure(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	cl, _, w := newTestClient()
	s.Clients.Add(cl)

	_ = w.Close()
	err := s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestServerProcessPublishOnPublishAckErrorRWError(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	hook.fail = true
	hook.err = packets.ErrUnspecifiedError
	err := s.AddHook(hook, nil)
	require.NoError(t, err)

	cl, _, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)
	_ = w.Close()

	err = s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)
}

func TestServerProcessPublishOnPublishAckErrorContinue(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	hook.fail = true
	hook.err = packets.ErrPayloadFormatInvalid
	err := s.AddHook(hook, nil)
	require.NoError(t, err)
	_ = s.Serve()
	defer s.Close()

	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPubackUnexpectedError).RawBytes, buf)
}

func TestServerProcessPublishOnPublishPkIgnore(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	hook.fail = true
	hook.err = packets.CodeSuccessIgnore
	err := s.AddHook(hook, nil)
	require.NoError(t, err)
	_ = s.Serve()
	defer s.Close()

	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))
	require.Equal(t, 0, len(s.Topics.Messages("a/b/c")))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		require.NoError(t, err)
		_ = w.Close()
		_ = w2.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPuback).RawBytes, buf)
	require.Equal(t, []byte{}, <-receiverBuf)
	require.Equal(t, 0, len(s.Topics.Messages("a/b/c")))
}

func TestServerProcessPublishMqtt5Qos1PubackSuccessReasonCode(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1Mqtt5).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPubackMqtt5).RawBytes, buf)
	require.GreaterOrEqual(t, len(buf), 5)
	require.Equal(t, packets.CodeSuccess.Code, buf[4])
	require.NotEqual(t, packets.QosCodes[1].Code, buf[4])
}

func TestServerProcessPacketPublishMaximumReceive(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.State.Inflight.ResetReceiveQuota(0)
	s.Clients.Add(cl)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		require.Error(t, err)
		require.ErrorIs(t, err, packets.ErrReceiveMaximum)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectReceiveMaximum).RawBytes, buf)
}

func TestServerProcessPublishInvalidTopic(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()
	cl, _, _ := newTestClient()
	err := s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishSpecDenySysTopic).Packet)
	require.NoError(t, err) // $SYS Topics should be ignored?
}

func TestServerProcessPublishACLCheckDeny(t *testing.T) {
	tt := []struct {
		name             string
		protocolVersion  byte
		pk               packets.Packet
		expectErr        error
		expectReponse    []byte
		expectDisconnect bool
	}{
		{
			name:             "v4_QOS0",
			protocolVersion:  4,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet,
			expectErr:        nil,
			expectReponse:    nil,
			expectDisconnect: false,
		},
		{
			name:             "v4_QOS1",
			protocolVersion:  4,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet,
			expectErr:        packets.ErrNotAuthorized,
			expectReponse:    nil,
			expectDisconnect: true,
		},
		{
			name:             "v4_QOS2",
			protocolVersion:  4,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet,
			expectErr:        packets.ErrNotAuthorized,
			expectReponse:    nil,
			expectDisconnect: true,
		},
		{
			name:             "v5_QOS0",
			protocolVersion:  5,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).Packet,
			expectErr:        nil,
			expectReponse:    nil,
			expectDisconnect: false,
		},
		{
			name:             "v5_QOS1",
			protocolVersion:  5,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1Mqtt5).Packet,
			expectErr:        nil,
			expectReponse:    packets.TPacketData[packets.Puback].Get(packets.TPubrecMqtt5NotAuthorized).RawBytes,
			expectDisconnect: false,
		},
		{
			name:             "v5_QOS2",
			protocolVersion:  5,
			pk:               *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2Mqtt5).Packet,
			expectErr:        nil,
			expectReponse:    packets.TPacketData[packets.Pubrec].Get(packets.TPubrecMqtt5NotAuthorized).RawBytes,
			expectDisconnect: false,
		},
	}

	for _, tx := range tt {
		t.Run(tx.name, func(t *testing.T) {
			cc := NewDefaultServerCapabilities()
			s := New(&Options{
				Logger:       logger,
				Capabilities: cc,
			})
			_ = s.AddHook(new(DenyHook), nil)
			_ = s.Serve()
			defer s.Close()

			cl, r, w := newTestClient()
			cl.Properties.ProtocolVersion = tx.protocolVersion
			s.Clients.Add(cl)

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := s.processPublish(cl, tx.pk)
				require.ErrorIs(t, err, tx.expectErr)
				_ = w.Close()
			}()

			buf, err := io.ReadAll(r)
			require.NoError(t, err)

			if tx.expectReponse != nil {
				require.Equal(t, tx.expectReponse, buf)
			}

			wg.Wait()
			require.Equal(t, tx.expectDisconnect, cl.Closed())
		})
	}
}

func TestServerProcessPublishRejectPacketQos0(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, buf)
	require.NoError(t, <-done)
}

func TestServerProcessPublishRejectPacketMqtt5Qos1Puback(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)
	cl.Properties.ProtocolVersion = 5

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	requireRejectAck(t, buf, packets.Puback)
	require.NoError(t, <-done)
}

func TestServerProcessPublishRejectPacketMqtt5Qos2Pubrec(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)
	cl.Properties.ProtocolVersion = 5

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	requireRejectAck(t, buf, packets.Pubrec)
	require.NoError(t, <-done)
}

func TestServerProcessPublishRejectPacketMqtt3Qos1Disconnects(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{packets.Disconnect << 4, 0}, buf)
	require.ErrorIs(t, <-done, packets.ErrRejectPacket)
	require.True(t, cl.Closed())
}

func TestServerProcessPublishHookNonCodeErrorReturns(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	require.NoError(t, s.AddHook(hook, nil))
	require.NoError(t, s.Serve())
	defer s.Close()

	hook.fail = true
	hook.err = io.ErrUnexpectedEOF

	cl, _, _ := newTestClient()
	receiver, _, _ := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	err := s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	require.ErrorIs(t, err, io.ErrUnexpectedEOF)
	require.Empty(t, s.Topics.Messages("a/b/c"))
}

func TestServerProcessPublishRejectPacketMqtt3Qos2Disconnects(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{packets.Disconnect << 4, 0}, buf)
	require.ErrorIs(t, <-done, packets.ErrRejectPacket)
	require.True(t, cl.Closed())
}

func TestServerProcessPublishRejectPacketNotPublished(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)
	cl.Properties.ProtocolVersion = 5

	receiver, _, _ := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c"})

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	requireRejectAck(t, buf, packets.Puback)
	require.NoError(t, <-done)

	require.Empty(t, s.Topics.Messages("a/b/c"))
}

func TestServerProcessPublishDifferentReasonCodes(t *testing.T) {
	testCases := []struct {
		name       string
		reasonCode packets.Code
		qos        byte
		expectAck  byte
	}{
		{
			name:       "NotAuthorized QoS1",
			reasonCode: packets.ErrNotAuthorized,
			qos:        1,
			expectAck:  packets.Puback,
		},
		{
			name:       "TopicNameInvalid QoS2",
			reasonCode: packets.ErrTopicNameInvalid,
			qos:        2,
			expectAck:  packets.Pubrec,
		},
		{
			name:       "QuotaExceeded QoS1",
			reasonCode: packets.ErrQuotaExceeded,
			qos:        1,
			expectAck:  packets.Puback,
		},
		{
			name:       "PayloadFormatInvalid QoS2",
			reasonCode: packets.ErrPayloadFormatInvalid,
			qos:        2,
			expectAck:  packets.Pubrec,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s := newServer()
			hook := new(modifiedHookBase)
			require.NoError(t, s.AddHook(hook, nil))
			require.NoError(t, s.Serve())
			defer s.Close()

			hook.fail = true
			hook.err = tc.reasonCode

			cl, r, w := newTestClient()
			cl.Properties.ProtocolVersion = 5

			var pk packets.Packet
			if tc.qos == 1 {
				pk = *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
			} else {
				pk = *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet
			}

			done := make(chan error, 1)
			go func() {
				done <- s.processPublish(cl, pk)
				_ = w.Close()
			}()

			buf, err := io.ReadAll(r)
			require.NoError(t, err)
			require.GreaterOrEqual(t, len(buf), 5)
			require.Equal(t, tc.expectAck<<4, buf[0])
			require.Equal(t, tc.reasonCode.Code, buf[4])
			require.NoError(t, <-done)
		})
	}
}

func TestServerProcessPublishRejectPacketWriteFailure(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	require.NoError(t, s.AddHook(hook, nil))
	require.NoError(t, s.Serve())
	defer s.Close()

	hook.fail = true
	hook.err = packets.ErrRejectPacket

	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5

	_ = w.Close()

	err := s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	require.Error(t, err)

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, buf)
}

func TestServerProcessPublishRejectPacketReceiveQuotaLeak(t *testing.T) {
	s, cl, r, w := newRejectPacketServer(t)
	cl.Properties.ProtocolVersion = 5

	// Set initial receive quota
	initialQuota := int32(10)
	cl.State.Inflight.ResetReceiveQuota(initialQuota)

	// Send a QoS 1 message that will be rejected
	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	requireRejectAck(t, buf, packets.Puback)
	require.NoError(t, <-done)

	// According to MQTT 5.0 spec section 4.9, when a PUBACK/PUBREC with error code
	// is sent, the flow is complete and quota should be restored.
	// The quota is temporarily consumed during processing, but restored after sending error ACK.
	currentQuota := cl.State.Inflight.ReceiveQuota()

	t.Logf("Initial quota: %d, Current quota: %d", initialQuota, currentQuota)

	// Quota should be restored after sending error ACK (flow complete)
	require.Equal(t, initialQuota, currentQuota,
		"Receive quota should be restored after sending error ACK")
}

func TestServerProcessPublishMqtt3Qos0WithReasonCode(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	require.NoError(t, s.AddHook(hook, nil))
	require.NoError(t, s.Serve())
	defer s.Close()

	hook.fail = true
	hook.err = packets.ErrRejectPacket

	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 3

	done := make(chan error, 1)
	go func() {
		done <- s.processPublish(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Empty(t, buf)
	require.NoError(t, <-done)
	require.False(t, cl.Closed())
}

func TestServerProcessPacketPublishQos0(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{}, buf)
}

func TestServerProcessPacketPublishQos1PacketIDInUse(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: 7, FixedHeader: packets.FixedHeader{Type: packets.Publish}})
	atomic.StoreInt64(&s.Info.Inflight, 1)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPuback).RawBytes, buf)
	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Inflight))
}

func TestServerProcessPacketPublishQos2PacketIDInUse(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.State.Inflight.Set(packets.Packet{PacketID: 7, FixedHeader: packets.FixedHeader{Type: packets.Pubrec}})
	atomic.StoreInt64(&s.Info.Inflight, 1)

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2Mqtt5).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Pubrec].Get(packets.TPubrecMqtt5IDInUse).RawBytes, buf)
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.Inflight))
}

func TestServerProcessPacketPublishQos1(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPuback).RawBytes, buf)
}

func TestServerProcessPacketPublishQos2(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Pubrec].Get(packets.TPubrec).RawBytes, buf)
}

func TestServerProcessPacketPublishDowngradeQos(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.MaximumQos = 1
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos2).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Puback].Get(packets.TPuback).RawBytes, buf)
}

func TestPublishToSubscribersSelfNoLocal(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", NoLocal: true})
	require.True(t, subbed)

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		pkx.Origin = cl.ID
		s.publishToSubscribers(pkx)
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	require.Equal(t, []byte{}, <-receiverBuf)
}

func TestPublishToSubscribers(t *testing.T) {
	s := newServer()
	cl, r1, w1 := newTestClient()
	cl.ID = "cl1"
	cl2, r2, w2 := newTestClient()
	cl2.ID = "cl2"
	cl3, r3, w3 := newTestClient()
	cl3.ID = "cl3"
	s.Clients.Add(cl)
	s.Clients.Add(cl2)
	s.Clients.Add(cl3)
	require.True(t, s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c"}))
	require.True(t, s.Topics.Subscribe(cl2.ID, packets.Subscription{Filter: SharePrefix + "/tmp/a/b/c"}))
	require.True(t, s.Topics.Subscribe(cl3.ID, packets.Subscription{Filter: SharePrefix + "/tmp/a/b/c"}))

	cl1Recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r1)
		require.NoError(t, err)
		cl1Recv <- buf
	}()

	cl2Recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		cl2Recv <- buf
	}()

	cl3Recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r3)
		require.NoError(t, err)
		cl3Recv <- buf
	}()

	go func() {
		s.publishToSubscribers(*packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		time.Sleep(time.Millisecond)
		_ = w1.Close()
		_ = w2.Close()
		_ = w3.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-cl1Recv)
	rcv2 := <-cl2Recv
	rcv3 := <-cl3Recv

	ok := false
	if len(rcv2) > 0 {
		require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, rcv2)
		require.Equal(t, []byte{}, rcv3)
		ok = true
	} else if len(rcv3) > 0 {
		require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, rcv3)
		require.Equal(t, []byte{}, rcv2)
		ok = true
	}
	require.True(t, ok)
}

func TestPublishToSubscribersMessageExpiryDelta(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.MaximumMessageExpiryInterval = 86400
	cl, r1, w1 := newTestClient()
	cl.ID = "cl1"
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)
	require.True(t, s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c"}))

	cl1Recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r1)
		require.NoError(t, err)
		cl1Recv <- buf
	}()

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		pkx.Created = time.Now().Unix() - 30
		s.publishToSubscribers(pkx)
		time.Sleep(time.Millisecond)
		_ = w1.Close()
	}()

	b := <-cl1Recv
	pk := new(packets.Packet)
	pk.ProtocolVersion = 5
	require.Equal(t, uint32(s.Options.Capabilities.MaximumMessageExpiryInterval-30), binary.BigEndian.Uint32(b[11:15]))
}

func TestPublishToSubscribersIdentifiers(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)
	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/+", Identifier: 2})
	require.True(t, subbed)
	subbed = s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/#", Identifier: 3})
	require.True(t, subbed)
	subbed = s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "d/e/f", Identifier: 4})
	require.True(t, subbed)

	go func() {
		s.publishToSubscribers(*packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishSubscriberIdentifier).RawBytes, <-receiverBuf)
}

func TestPublishToSubscribersPkIgnore(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "#", Identifier: 1})
	require.True(t, subbed)

	go func() {
		pk := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		pk.Ignore = true
		s.publishToSubscribers(pk)
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	require.Equal(t, []byte{}, <-receiverBuf)
}

func TestPublishToClientServerDowngradeQos(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.MaximumQos = 1

	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	_, ok := cl.State.Inflight.Get(1)
	require.False(t, ok)
	cl.State.packetID = 6 // just to match the same packet id (7) in the fixtures

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
		pkx.FixedHeader.Qos = 2
		_, _ = s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 2}, pkx)
		time.Sleep(time.Microsecond * 100)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).RawBytes, <-receiverBuf)
}

func TestPublishToClientSubscriptionDowngradeQos(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.MaximumQos = 2

	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	_, ok := cl.State.Inflight.Get(1)
	require.False(t, ok)
	cl.State.packetID = 6 // just to match the same packet id (7) in the fixtures

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
		pkx.FixedHeader.Qos = 2
		_, _ = s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 1}, pkx)
		time.Sleep(time.Microsecond * 100)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).RawBytes, <-receiverBuf)
}

func TestPublishToClientExceedClientWritesPending(t *testing.T) {
	var sendQuota uint16 = 5
	s := newServer()

	_, w := net.Pipe()
	cl := newTcpClient(w, &ops{
		info:  new(system.Info),
		hooks: new(Hooks),
		log:   logger,
		options: &Options{
			Capabilities: &Capabilities{
				MaximumClientWritesPending: 3,
				maximumPacketID:            10,
			},
		},
	})
	cl.Properties.Props.ReceiveMaximum = sendQuota
	cl.State.Inflight.ResetSendQuota(int32(cl.Properties.Props.ReceiveMaximum))

	s.Clients.Add(cl)

	for i := int32(0); i < cl.ops.options.Capabilities.MaximumClientWritesPending; i++ {
		cl.State.outbound <- new(packets.Packet)
		atomic.AddInt32(&cl.State.outboundQty, 1)
	}

	id, _ := cl.NextPacketID()
	cl.State.Inflight.Set(packets.Packet{PacketID: uint16(id)})
	cl.State.Inflight.DecreaseSendQuota()
	sendQuota--

	_, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 2}, packets.Packet{})
	require.Error(t, err)
	require.ErrorIs(t, packets.ErrPendingClientWritesExceeded, err)
	require.Equal(t, int32(sendQuota), cl.State.Inflight.SendQuota())

	_, err = s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 2}, packets.Packet{FixedHeader: packets.FixedHeader{Qos: 1}})
	require.Error(t, err)
	require.ErrorIs(t, packets.ErrPendingClientWritesExceeded, err)
	require.Equal(t, int32(sendQuota), cl.State.Inflight.SendQuota())
}

func TestPublishToClientServerTopicAlias(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Props.TopicAliasMaximum = 5
	s.Clients.Add(cl)

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).Packet
		_, _ = s.publishToClient(cl, packets.Subscription{Filter: pkx.TopicName}, pkx)
		_, _ = s.publishToClient(cl, packets.Subscription{Filter: pkx.TopicName}, pkx)
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	ret := <-receiverBuf
	pk1 := make([]byte, len(packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).RawBytes))
	pk2 := make([]byte, len(packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).RawBytes)-5)
	copy(pk1, ret[:len(packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).RawBytes)])
	copy(pk2, ret[len(packets.TPacketData[packets.Publish].Get(packets.TPublishBasicMqtt5).RawBytes):])
	require.Equal(t, append(pk1, pk2...), ret)
}

func TestPublishToClientMqtt3RetainFalseLeverageNoConn(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Net.Transport = nil

	out, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", RetainAsPublished: true}, *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.False(t, out.FixedHeader.Retain)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.CodeDisconnect)
}

func TestPublishToClientMqtt5RetainAsPublishedTrueLeverageNoConn(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.Net.Transport = nil

	out, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", RetainAsPublished: true}, *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.True(t, out.FixedHeader.Retain)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.CodeDisconnect)
}

func TestPublishToClientExceedMaximumInflight(t *testing.T) {
	const MaxInflight uint16 = 5
	s := newServer()
	cl, _, _ := newTestClient()
	s.Options.Capabilities.MaximumInflight = MaxInflight
	cl.ops.options.Capabilities.MaximumInflight = MaxInflight
	for i := uint16(0); i < MaxInflight; i++ {
		cl.State.Inflight.Set(packets.Packet{PacketID: i})
	}

	_, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 1}, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrQuotaExceeded)
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.InflightDropped))
}

func TestPublishToClientExhaustedPacketID(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	for i := uint32(0); i <= cl.ops.options.Capabilities.maximumPacketID; i++ {
		cl.State.Inflight.Set(packets.Packet{PacketID: uint16(i)})
	}

	_, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c", Qos: 1}, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrQuotaExceeded)
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.InflightDropped))
}

func TestPublishToClientACLNotAuthorized(t *testing.T) {
	s := New(&Options{
		Logger: logger,
	})
	err := s.AddHook(new(DenyHook), nil)
	require.NoError(t, err)
	cl, _, _ := newTestClient()

	_, err = s.publishToClient(cl, packets.Subscription{Filter: "a/b/c"}, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrNotAuthorized)
}

func TestPublishToClientNoConn(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Net.Transport = nil

	_, err := s.publishToClient(cl, packets.Subscription{Filter: "a/b/c"}, *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.CodeDisconnect)
}

func TestProcessPublishWithTopicAlias(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 0})
	require.True(t, subbed)

	cl2, _, w2 := newTestClient()
	cl2.Properties.ProtocolVersion = 5
	cl2.State.TopicAliases.Inbound.Set(1, "a/b/c")

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishMqtt5).Packet
		pkx.Properties.SubscriptionIdentifier = []int{} // must not contain from client to server
		pkx.TopicName = ""
		pkx.Properties.TopicAlias = 1
		_ = s.processPacket(cl2, pkx)
		time.Sleep(time.Millisecond)
		_ = w2.Close()
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, buf)
}

func TestPublishToSubscribersExhaustedSendQuota(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	setTestInflightQuotas(cl.State.Inflight, 0, cl.State.Inflight.ReceiveQuota())

	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 2})
	require.True(t, subbed)

	// coverage: subscriber publish errors are non-returnable
	// can we hook into log/slog ?
	_ = r.Close()
	pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
	pkx.PacketID = 0
	s.publishToSubscribers(pkx)
	time.Sleep(time.Millisecond)
	_ = w.Close()
}

func TestSendQueuedMessagesRespectsSendQuota(t *testing.T) {
	s := newServer()
	cl := newTcpClient(nil, &ops{
		info:  new(system.Info),
		hooks: new(Hooks),
		log:   logger,
		options: &Options{
			Capabilities: &Capabilities{
				MaximumClientWritesPending: 3,
			},
		},
	})
	cl.ID = "receiver"
	cl.State.Inflight.ResetSendQuota(1)
	cl.State.Inflight.Set(packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Publish, Qos: 1}, PacketID: 1, Created: 1, Expiry: -1})
	cl.State.Inflight.Set(packets.Packet{FixedHeader: packets.FixedHeader{Type: packets.Publish, Qos: 1}, PacketID: 2, Created: 2, Expiry: -1})

	s.sendQueuedMessages(cl)

	require.Len(t, cl.State.outbound, 1)
	require.Equal(t, int32(0), cl.State.Inflight.SendQuota())

	first, ok := cl.State.Inflight.Get(1)
	require.True(t, ok)
	require.GreaterOrEqual(t, first.Expiry, int64(0))

	second, ok := cl.State.Inflight.Get(2)
	require.True(t, ok)
	require.Equal(t, int64(-1), second.Expiry)
}

func TestPublishToSubscribersExhaustedPacketIDs(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	for i := uint32(0); i <= cl.ops.options.Capabilities.maximumPacketID; i++ {
		cl.State.Inflight.Set(packets.Packet{PacketID: 1})
	}

	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 2})
	require.True(t, subbed)

	// coverage: subscriber publish errors are non-returnable
	// can we hook into log/slog ?
	_ = r.Close()
	pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
	pkx.PacketID = 0
	s.publishToSubscribers(pkx)
	time.Sleep(time.Millisecond)
	_ = w.Close()
}

func TestPublishToSubscribersNoConnection(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)
	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 2})
	require.True(t, subbed)

	// coverage: subscriber publish errors are non-returnable
	// can we hook into log/slog ?
	_ = r.Close()
	s.publishToSubscribers(*packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	time.Sleep(time.Millisecond)
	_ = w.Close()
}

func TestPublishRetainedToClient(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	subbed := s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 2})
	require.True(t, subbed)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetainMqtt5).Packet)
	require.Equal(t, int64(1), retained)

	go func() {
		s.publishRetainedToClient(cl, packets.Subscription{Filter: "a/b/c"}, false)
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).RawBytes, buf)
}

func TestPublishRetainedToClientIsShared(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	s.Clients.Add(cl)

	sub := packets.Subscription{Filter: SharePrefix + "/test/a/b/c"}
	subbed := s.Topics.Subscribe(cl.ID, sub)
	require.True(t, subbed)

	go func() {
		s.publishRetainedToClient(cl, sub, false)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{}, buf)
}

func TestPublishRetainedToClientError(t *testing.T) {
	s := newServer()
	cl, _, w := newTestClient()
	s.Clients.Add(cl)

	sub := packets.Subscription{Filter: "a/b/c"}
	subbed := s.Topics.Subscribe(cl.ID, sub)
	require.True(t, subbed)

	retained := s.Topics.RetainMessage(*packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), retained)

	_ = w.Close()
	s.publishRetainedToClient(cl, sub, false)
}

func TestServerProcessPublishRetainedMessageExpiryInterval(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	cl, _, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)

	pk := *packets.TPacketData[packets.Publish].Get(packets.TPublishRetainMqtt5).Packet
	pk.TopicName = "retain/expiry/test"
	pk.Properties.MessageExpiryInterval = 1

	require.NoError(t, s.processPublish(cl, pk))

	retained, ok := s.Topics.Retained.Get(pk.TopicName)
	require.True(t, ok)
	require.Equal(t, int64(1), retained.Expiry-retained.Created)
	require.Greater(t, retained.Expiry, int64(0))

	s.clearExpiredRetainedMessages(retained.Expiry + 1)
	_, ok = s.Topics.Retained.Get(pk.TopicName)
	require.False(t, ok)
}

func TestPublishToInlineSubscriber(t *testing.T) {
	s := newServerWithInlineClient()
	finishCh := make(chan bool)
	err := s.Subscribe("a/b/c", 1, func(cl *Client, sub packets.Subscription, pk packets.Packet) {
		require.Equal(t, []byte("hello mochi"), pk.Payload)
		require.Equal(t, InlineClientId, cl.ID)
		require.Equal(t, LocalListener, cl.Net.Listener)
		require.Equal(t, "a/b/c", sub.Filter)
		require.Equal(t, 1, sub.Identifier)
		finishCh <- true
	})
	require.Nil(t, err)

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		s.publishToSubscribers(pkx)
	}()

	require.Equal(t, true, <-finishCh)
}

func TestPublishToInlineSubscribersDifferentFilter(t *testing.T) {
	s := newServerWithInlineClient()
	subNumber := 2
	finishCh := make(chan bool, subNumber)

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

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		s.publishToSubscribers(pkx)

		pkx = *packets.TPacketData[packets.Publish].Get(packets.TPublishCopyBasic).Packet
		s.publishToSubscribers(pkx)
	}()

	for i := 0; i < subNumber; i++ {
		require.Equal(t, true, <-finishCh)
	}
}

func TestPublishToInlineSubscribersDifferentIdentifier(t *testing.T) {
	s := newServerWithInlineClient()
	subNumber := 2
	finishCh := make(chan bool, subNumber)

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

	go func() {
		pkx := *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet
		s.publishToSubscribers(pkx)
	}()

	for i := 0; i < subNumber; i++ {
		require.Equal(t, true, <-finishCh)
	}
}
