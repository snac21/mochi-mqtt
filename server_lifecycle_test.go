// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/hooks/storage"
	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/mochi-mqtt/server/v2/system"
	"github.com/mochi-mqtt/server/v2/transport"

	"github.com/stretchr/testify/require"
)

func TestOptionsSetDefaults(t *testing.T) {
	opts := &Options{}
	opts.ensureDefaults()

	require.Equal(t, defaultSysTopicInterval, opts.SysTopicResendInterval)
	require.Equal(t, NewDefaultServerCapabilities(), opts.Capabilities)

	opts = new(Options)
	opts.ensureDefaults()
	require.Equal(t, defaultSysTopicInterval, opts.SysTopicResendInterval)
}

func TestNew(t *testing.T) {
	s := New(nil)
	require.NotNil(t, s)
	require.NotNil(t, s.Clients)
	require.NotNil(t, s.Listeners)
	require.NotNil(t, s.Topics)
	require.NotNil(t, s.Info)
	require.NotNil(t, s.Log)
	require.NotNil(t, s.Options)
	require.NotNil(t, s.loop)
	require.NotNil(t, s.loop.sysTopics)
	require.NotNil(t, s.loop.inflightExpiry)
	require.NotNil(t, s.loop.clientExpiry)
	require.NotNil(t, s.hooks)
	require.NotNil(t, s.hooks.Log)
	require.NotNil(t, s.done)
	require.Nil(t, s.inlineClient)
	require.Equal(t, 0, s.Clients.Len())
}

func TestNewWithInlineClient(t *testing.T) {
	s := New(&Options{
		InlineClient: true,
	})
	require.NotNil(t, s.inlineClient)
	require.Equal(t, 1, s.Clients.Len())
}

func TestNewNilOpts(t *testing.T) {
	s := New(nil)
	require.NotNil(t, s)
	require.NotNil(t, s.Options)
}

func TestProcessDisconnectClearsWill(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.Will = Will{
		Flag:      1,
		TopicName: "will/topic",
		Payload:   []byte("offline"),
	}

	err := s.processDisconnect(cl, packets.Packet{
		FixedHeader: packets.FixedHeader{Type: packets.Disconnect},
	})

	require.NoError(t, err)
	require.ErrorIs(t, cl.StopCause(), packets.CodeDisconnect)
	require.Zero(t, cl.Properties.Will.Flag)
	require.Empty(t, cl.Properties.Will.TopicName)
	require.Empty(t, cl.Properties.Will.Payload)
}

func TestServerNewClient(t *testing.T) {
	s := New(nil)
	s.Log = logger
	r, _ := net.Pipe()

	cl := s.NewTcpClient(r, "testing", "test", false)
	require.NotNil(t, cl)
	require.Equal(t, "test", cl.ID)
	require.Equal(t, "testing", cl.Net.Listener)
	require.False(t, cl.Net.Inline)
	require.NotNil(t, cl.State.Inflight.internal)
	require.NotNil(t, cl.State.Subscriptions)
	require.NotNil(t, cl.State.TopicAliases)
	require.Equal(t, defaultKeepalive, cl.State.Keepalive)
	require.Equal(t, defaultClientProtocolVersion, cl.Properties.ProtocolVersion)
	require.NotNil(t, cl.Net.Transport)
	tcpTr, ok := cl.Net.Transport.(*transport.TCPTransport)
	require.True(t, ok)
	require.NotNil(t, tcpTr.Bconn)
	require.NotNil(t, cl.ops)
	require.Equal(t, s.Log, cl.ops.log)
}

func TestServerNewClientInline(t *testing.T) {
	s := New(nil)
	cl := s.NewTcpClient(nil, "testing", "test", true)
	require.True(t, cl.Net.Inline)
}

func TestServerAddHook(t *testing.T) {
	s := New(nil)

	s.Log = logger
	require.NotNil(t, s)

	require.Equal(t, int64(0), s.hooks.Len())
	err := s.AddHook(new(HookBase), nil)
	require.NoError(t, err)
	require.Equal(t, int64(1), s.hooks.Len())
}

func TestServerAddListener(t *testing.T) {
	s := newServer()
	defer s.Close()

	require.NotNil(t, s)

	err := s.AddListener(listeners.NewMockListener("t1", ":1882"))
	require.NoError(t, err)

	// add existing listener
	err = s.AddListener(listeners.NewMockListener("t1", ":1882"))
	require.Error(t, err)
	require.Equal(t, ErrListenerIDExists, err)
}

func TestServerAddHooksFromConfig(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)
	s.Log = logger

	hooks := []HookLoadConfig{
		{Hook: new(modifiedHookBase)},
	}

	err := s.AddHooksFromConfig(hooks)
	require.NoError(t, err)
}

func TestServerAddHooksFromConfigError(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)
	s.Log = logger

	hooks := []HookLoadConfig{
		{Hook: new(modifiedHookBase), Config: map[string]interface{}{}},
	}

	err := s.AddHooksFromConfig(hooks)
	require.Error(t, err)
}

func TestServerAddListenerInitFailure(t *testing.T) {
	s := newServer()
	defer s.Close()

	require.NotNil(t, s)

	m := listeners.NewMockListener("t1", ":1882")
	m.ErrListen = true
	err := s.AddListener(m)
	require.Error(t, err)
}

func TestServerAddListenersFromConfig(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)
	s.Log = logger

	lc := []listeners.Config{
		{Type: listeners.TypeTCP, ID: "tcp", Address: ":1883"},
		{Type: listeners.TypeWS, ID: "ws", Address: ":1882"},
		{Type: listeners.TypeHealthCheck, ID: "health", Address: ":1881"},
		{Type: listeners.TypeSysInfo, ID: "info", Address: ":1880"},
		{Type: listeners.TypeUnix, ID: "unix", Address: "mochi.sock"},
		{Type: listeners.TypeMock, ID: "mock", Address: "0"},
		{Type: "unknown", ID: "unknown"},
	}

	err := s.AddListenersFromConfig(lc)
	require.NoError(t, err)
	require.Equal(t, 6, s.Listeners.Len())

	tcp, _ := s.Listeners.Get("tcp")
	require.Equal(t, "[::]:1883", tcp.Address())

	ws, _ := s.Listeners.Get("ws")
	require.Equal(t, ":1882", ws.Address())

	health, _ := s.Listeners.Get("health")
	require.Equal(t, ":1881", health.Address())

	info, _ := s.Listeners.Get("info")
	require.Equal(t, ":1880", info.Address())

	unix, _ := s.Listeners.Get("unix")
	require.Equal(t, "mochi.sock", unix.Address())

	mock, _ := s.Listeners.Get("mock")
	require.Equal(t, "0", mock.Address())
}

func TestServerAddListenersFromConfigError(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)
	s.Log = logger

	lc := []listeners.Config{
		{Type: listeners.TypeTCP, ID: "tcp", Address: "x"},
	}

	err := s.AddListenersFromConfig(lc)
	require.Error(t, err)
	require.Equal(t, 0, s.Listeners.Len())
}

func TestServerServe(t *testing.T) {
	s := newServer()
	defer s.Close()

	require.NotNil(t, s)

	err := s.AddListener(listeners.NewMockListener("t1", ":1882"))
	require.NoError(t, err)

	err = s.Serve()
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	require.Equal(t, 1, s.Listeners.Len())
	listener, ok := s.Listeners.Get("t1")

	require.Equal(t, true, ok)
	require.Equal(t, true, listener.(*listeners.MockListener).IsServing())
}

func TestServerServeFromConfig(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)

	s.Options.Listeners = []listeners.Config{
		{Type: listeners.TypeMock, ID: "mock", Address: "0"},
	}

	s.Options.Hooks = []HookLoadConfig{
		{Hook: new(modifiedHookBase)},
	}

	err := s.Serve()
	require.NoError(t, err)

	time.Sleep(time.Millisecond)

	require.Equal(t, 1, s.Listeners.Len())
	listener, ok := s.Listeners.Get("mock")

	require.Equal(t, true, ok)
	require.Equal(t, true, listener.(*listeners.MockListener).IsServing())
}

func TestServerServeFromConfigListenerError(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)

	s.Options.Listeners = []listeners.Config{
		{Type: listeners.TypeTCP, ID: "tcp", Address: "x"},
	}

	err := s.Serve()
	require.Error(t, err)
}

func TestServerServeFromConfigHookError(t *testing.T) {
	s := newServer()
	defer s.Close()
	require.NotNil(t, s)

	s.Options.Hooks = []HookLoadConfig{
		{Hook: new(modifiedHookBase), Config: map[string]interface{}{}},
	}

	err := s.Serve()
	require.Error(t, err)
}

func TestServerServeReadStoreFailure(t *testing.T) {
	s := newServer()
	defer s.Close()

	require.NotNil(t, s)

	err := s.AddListener(listeners.NewMockListener("t1", ":1882"))
	require.NoError(t, err)

	hook := new(modifiedHookBase)
	hook.failAt = 1
	err = s.AddHook(hook, nil)
	require.NoError(t, err)

	err = s.Serve()
	require.Error(t, err)
}

func TestServerEventLoop(t *testing.T) {
	s := newServer()
	defer s.Close()

	s.loop.sysTopics = time.NewTicker(time.Millisecond)
	s.loop.inflightExpiry = time.NewTicker(time.Millisecond)
	s.loop.clientExpiry = time.NewTicker(time.Millisecond)
	s.loop.retainedExpiry = time.NewTicker(time.Millisecond)
	s.loop.willDelaySend = time.NewTicker(time.Millisecond)
	go s.eventLoop()

	time.Sleep(time.Millisecond * 3)
}

func TestServerProcessPacketFailure(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	err := s.processPacket(cl, packets.Packet{})
	require.Error(t, err)
}

func TestServerProcessPacketPingreq(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Pingreq].Get(packets.TPingreq).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Pingresp].Get(packets.TPingresp).RawBytes, buf)
}

func TestServerProcessPacketPingreqError(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Stop(packets.CodeDisconnect)

	err := s.processPacket(cl, *packets.TPacketData[packets.Pingreq].Get(packets.TPingreq).Packet)
	require.Error(t, err)
	require.ErrorIs(t, cl.StopCause(), packets.CodeDisconnect)
}

func TestServerDeliverToClientID(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.ID = "target"
	s.Clients.Add(cl)

	receiverBuf := make(chan []byte, 1)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	err := s.DeliverToClientID(cl.ID, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	require.NoError(t, err)

	go func() {
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
}

func TestServerDeliverToClientIDClientNotFound(t *testing.T) {
	s := newServer()
	err := s.DeliverToClientID("missing", *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
	require.ErrorIs(t, err, ErrClientNotFound)
}

func TestInjectPacketError(t *testing.T) {
	s := newServer()
	defer s.Close()
	cl, _, _ := newTestClient()
	cl.Net.Inline = true
	pkx := *packets.TPacketData[packets.Subscribe].Get(packets.TSubscribe).Packet
	pkx.Filters = packets.Subscriptions{}
	err := s.InjectPacket(cl, pkx)
	require.Error(t, err)
}

func TestServerBuildAck(t *testing.T) {
	s := newServer()
	properties := packets.Properties{
		User: []packets.UserProperty{
			{Key: "hello", Val: "世界"},
		},
	}
	ack := s.buildAck(7, packets.Puback, 1, properties, packets.CodeGrantedQos1)
	require.Equal(t, packets.Puback, ack.FixedHeader.Type)
	require.Equal(t, uint8(1), ack.FixedHeader.Qos)
	require.Equal(t, packets.CodeGrantedQos1.Code, ack.ReasonCode)
	require.Equal(t, properties, ack.Properties)
}

func TestServerBuildAckError(t *testing.T) {
	s := newServer()
	properties := packets.Properties{
		User: []packets.UserProperty{
			{Key: "hello", Val: "世界"},
		},
	}
	ack := s.buildAck(7, packets.Puback, 1, properties, packets.ErrMalformedPacket)
	require.Equal(t, packets.Puback, ack.FixedHeader.Type)
	require.Equal(t, uint8(1), ack.FixedHeader.Qos)
	require.Equal(t, packets.ErrMalformedPacket.Code, ack.ReasonCode)
	properties.ReasonString = packets.ErrMalformedPacket.Reason
	require.Equal(t, properties, ack.Properties)
}

func TestServerBuildAckPahoCompatibility(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.Compatibilities.NoInheritedPropertiesOnAck = true
	properties := packets.Properties{
		User: []packets.UserProperty{
			{Key: "hello", Val: "世界"},
		},
	}
	ack := s.buildAck(7, packets.Puback, 1, properties, packets.CodeGrantedQos1)
	require.Equal(t, packets.Puback, ack.FixedHeader.Type)
	require.Equal(t, uint8(1), ack.FixedHeader.Qos)
	require.Equal(t, packets.CodeGrantedQos1.Code, ack.ReasonCode)
	require.Equal(t, packets.Properties{}, ack.Properties)
}

func TestServerProcessPacketAndNextImmediate(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	next := *packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet
	next.Expiry = -1
	cl.State.Inflight.Set(next)
	atomic.StoreInt64(&s.Info.Inflight, 1)
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.Inflight))
	require.Equal(t, int32(5), cl.State.Inflight.SendQuota())

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).RawBytes, buf)
	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Inflight))
	require.Equal(t, int32(4), cl.State.Inflight.SendQuota())
}

func TestNoRetainMessageIfUnavailable(t *testing.T) {
	s := newServer()
	s.Options.Capabilities.RetainAvailable = 0
	cl, _, _ := newTestClient()
	s.Clients.Add(cl)

	s.retainMessage(new(Client), *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Retained))
}

func TestNoRetainMessageIfPkIgnore(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	s.Clients.Add(cl)

	pk := *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet
	pk.Ignore = true
	s.retainMessage(new(Client), pk)
	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Retained))
}

func TestNoRetainMessage(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	s.Clients.Add(cl)

	s.retainMessage(new(Client), *packets.TPacketData[packets.Publish].Get(packets.TPublishRetain).Packet)
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.Retained))
}

func TestServerProcessPacketPuback(t *testing.T) {
	tt := ProtocolTest{
		{
			protocolVersion: 4,
			in:              packets.TPacketData[packets.Puback].Get(packets.TPuback),
		},
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Puback].Get(packets.TPubackMqtt5),
		},
	}

	for _, tx := range tt {
		t.Run(strconv.Itoa(int(tx.protocolVersion)), func(t *testing.T) {
			pID := uint16(7)
			s := newServer()
			cl, _, _ := newTestClient()
			setTestInflightQuotas(cl.State.Inflight, 3, 3)

			cl.State.Inflight.Set(packets.Packet{PacketID: pID})
			atomic.AddInt64(&s.Info.Inflight, 1)

			err := s.processPacket(cl, *tx.in.Packet)
			require.NoError(t, err)

			require.Equal(t, int32(4), cl.State.Inflight.SendQuota())
			require.Equal(t, int32(3), cl.State.Inflight.ReceiveQuota())

			require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Inflight))
			_, ok := cl.State.Inflight.Get(pID)
			require.False(t, ok)
		})
	}
}

func TestServerProcessPacketPubackNoPacketID(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	pk := *packets.TPacketData[packets.Puback].Get(packets.TPuback).Packet
	err := s.processPacket(cl, pk)
	require.NoError(t, err)

	require.Equal(t, int32(3), cl.State.Inflight.SendQuota())
	require.Equal(t, int32(3), cl.State.Inflight.ReceiveQuota())
}

func TestServerProcessPacketPubrec(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, r, w := newTestClient()
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	atomic.AddInt64(&s.Info.Inflight, 1)

	recv := make(chan []byte)
	go func() { // receive the ack
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrec].Get(packets.TPubrec).Packet)
	require.NoError(t, err)
	_ = w.Close()

	require.Equal(t, packets.TPacketData[packets.Pubrel].Get(packets.TPubrel).RawBytes, <-recv)

	require.Equal(t, int32(2), cl.State.Inflight.ReceiveQuota())
	require.Equal(t, int32(3), cl.State.Inflight.SendQuota())
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.Inflight))
	_, ok := cl.State.Inflight.Get(pID)
	require.True(t, ok)
}

func TestServerProcessPacketPubrecNoPacketID(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	recv := make(chan []byte)
	go func() { // receive the ack
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	pk := *packets.TPacketData[packets.Pubrec].Get(packets.TPubrec).Packet // not sending properties
	err := s.processPacket(cl, pk)
	require.NoError(t, err)
	_ = w.Close()

	require.Equal(t, packets.TPacketData[packets.Pubrel].Get(packets.TPubrelMqtt5AckNoPacket).RawBytes, <-recv)

	require.Equal(t, int32(3), cl.State.Inflight.SendQuota())
	require.Equal(t, int32(3), cl.State.Inflight.ReceiveQuota())
}

func TestServerProcessPacketPubrecInvalidReason(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrec].Get(packets.TPubrecInvalidReason).Packet)
	require.NoError(t, err)
	require.Equal(t, int64(-1), atomic.LoadInt64(&s.Info.Inflight))
	_, ok := cl.State.Inflight.Get(pID)
	require.False(t, ok)
}

func TestServerProcessPacketPubrecFailure(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	cl.Stop(packets.CodeDisconnect)
	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrec].Get(packets.TPubrec).Packet)
	require.Error(t, err)
	require.ErrorIs(t, cl.StopCause(), packets.CodeDisconnect)
}

func TestServerProcessPacketPubrel(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, r, w := newTestClient()
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	atomic.AddInt64(&s.Info.Inflight, 1)

	recv := make(chan []byte)
	go func() { // receive the ack
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrel].Get(packets.TPubrel).Packet)
	require.NoError(t, err)
	_ = w.Close()

	require.Equal(t, int32(4), cl.State.Inflight.ReceiveQuota())
	require.Equal(t, int32(4), cl.State.Inflight.SendQuota())

	require.Equal(t, packets.TPacketData[packets.Pubcomp].Get(packets.TPubcomp).RawBytes, <-recv)

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Inflight))
	_, ok := cl.State.Inflight.Get(pID)
	require.False(t, ok)
}

func TestServerProcessPacketPubrelNoPacketID(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	recv := make(chan []byte)
	go func() { // receive the ack
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	pk := *packets.TPacketData[packets.Pubrel].Get(packets.TPubrel).Packet // not sending properties
	err := s.processPacket(cl, pk)
	require.NoError(t, err)
	_ = w.Close()

	require.Equal(t, packets.TPacketData[packets.Pubcomp].Get(packets.TPubcompMqtt5AckNoPacket).RawBytes, <-recv)

	require.Equal(t, int32(3), cl.State.Inflight.SendQuota())
	require.Equal(t, int32(3), cl.State.Inflight.ReceiveQuota())
}

func TestServerProcessPacketPubrelFailure(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	cl.Stop(packets.CodeDisconnect)
	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrel].Get(packets.TPubrel).Packet)
	require.Error(t, err)
	require.ErrorIs(t, cl.StopCause(), packets.CodeDisconnect)
}

func TestServerProcessPacketPubrelBadReason(t *testing.T) {
	pID := uint16(7)
	s := newServer()
	cl, _, _ := newTestClient()
	cl.State.Inflight.Set(packets.Packet{PacketID: pID})
	err := s.processPacket(cl, *packets.TPacketData[packets.Pubrel].Get(packets.TPubrelInvalidReason).Packet)
	require.NoError(t, err)
	require.Equal(t, int64(-1), atomic.LoadInt64(&s.Info.Inflight))
	_, ok := cl.State.Inflight.Get(pID)
	require.False(t, ok)
}

func TestServerProcessPacketPubcomp(t *testing.T) {
	tt := ProtocolTest{
		{
			protocolVersion: 4,
			in:              packets.TPacketData[packets.Pubcomp].Get(packets.TPubcomp),
		},
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Pubcomp].Get(packets.TPubcompMqtt5),
		},
	}

	for _, tx := range tt {
		t.Run(strconv.Itoa(int(tx.protocolVersion)), func(t *testing.T) {
			pID := uint16(7)
			s := newServer()
			cl, _, _ := newTestClient()
			cl.Properties.ProtocolVersion = tx.protocolVersion
			setTestInflightQuotas(cl.State.Inflight, 3, 3)

			cl.State.Inflight.Set(packets.Packet{PacketID: pID})
			atomic.AddInt64(&s.Info.Inflight, 1)

			err := s.processPacket(cl, *tx.in.Packet)
			require.NoError(t, err)
			require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.Inflight))

			require.Equal(t, int32(4), cl.State.Inflight.ReceiveQuota())
			require.Equal(t, int32(4), cl.State.Inflight.SendQuota())

			_, ok := cl.State.Inflight.Get(pID)
			require.False(t, ok)
		})
	}
}

func TestServerProcessInboundQos2Flow(t *testing.T) {
	tt := ProtocolTest{
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Publish].Get(packets.TPublishQos2),
			out:             packets.TPacketData[packets.Pubrec].Get(packets.TPubrec),
			data: map[string]any{
				"sendquota": int32(3),
				"recvquota": int32(2),
				"inflight":  int64(1),
			},
		},
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Pubrel].Get(packets.TPubrel),
			out:             packets.TPacketData[packets.Pubcomp].Get(packets.TPubcomp),
			data: map[string]any{
				"sendquota": int32(4),
				"recvquota": int32(3),
				"inflight":  int64(0),
			},
		},
	}

	pID := uint16(7)
	s := newServer()
	cl, r, w := newTestClient()
	setTestInflightQuotas(cl.State.Inflight, 3, 3)

	for i, tx := range tt {
		t.Run("qos step"+strconv.Itoa(i), func(t *testing.T) {
			r, w = net.Pipe()
			cl.Net.Transport = transport.NewTCPTransport(w, 1024)

			recv := make(chan []byte)
			go func() { // receive the ack
				buf, err := io.ReadAll(r)
				require.NoError(t, err)
				recv <- buf
			}()

			err := s.processPacket(cl, *tx.in.Packet)
			require.NoError(t, err)
			_ = w.Close()

			require.Equal(t, tx.out.RawBytes, <-recv)
			if i == 0 {
				_, ok := cl.State.Inflight.Get(pID)
				require.True(t, ok)
			}

			require.Equal(t, tx.data["inflight"].(int64), atomic.LoadInt64(&s.Info.Inflight))
			require.Equal(t, tx.data["recvquota"].(int32), cl.State.Inflight.ReceiveQuota())
			require.Equal(t, tx.data["sendquota"].(int32), cl.State.Inflight.SendQuota())
		})
	}

	_, ok := cl.State.Inflight.Get(pID)
	require.False(t, ok)
}

func TestServerProcessOutboundQos2Flow(t *testing.T) {
	tt := ProtocolTest{
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Publish].Get(packets.TPublishQos2),
			out:             packets.TPacketData[packets.Publish].Get(packets.TPublishQos2),
			data: map[string]any{
				"sendquota": int32(2),
				"recvquota": int32(3),
				"inflight":  int64(1),
			},
		},
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Pubrec].Get(packets.TPubrec),
			out:             packets.TPacketData[packets.Pubrel].Get(packets.TPubrel),
			data: map[string]any{
				"sendquota": int32(2),
				"recvquota": int32(2),
				"inflight":  int64(1),
			},
		},
		{
			protocolVersion: 5,
			in:              packets.TPacketData[packets.Pubcomp].Get(packets.TPubcomp),
			data: map[string]any{
				"sendquota": int32(3),
				"recvquota": int32(3),
				"inflight":  int64(0),
			},
		},
	}

	pID := uint16(6)
	s := newServer()
	cl, _, _ := newTestClient()
	cl.State.packetID = uint32(6)
	setTestInflightQuotas(cl.State.Inflight, 3, 3)
	s.Clients.Add(cl)
	s.Topics.Subscribe(cl.ID, packets.Subscription{Filter: "a/b/c", Qos: 2})

	for i, tx := range tt {
		t.Run("qos step"+strconv.Itoa(i), func(t *testing.T) {
			r, w := net.Pipe()
			time.Sleep(time.Millisecond)
			cl.Net.Transport = transport.NewTCPTransport(w, 1024)

			recv := make(chan []byte)
			go func() { // receive the ack
				buf, err := io.ReadAll(r)
				require.NoError(t, err)
				recv <- buf
			}()

			if i == 0 {
				s.publishToSubscribers(*tx.in.Packet)
			} else {
				err := s.processPacket(cl, *tx.in.Packet)
				require.NoError(t, err)
			}

			time.Sleep(time.Millisecond)
			_ = w.Close()

			if i != 2 {
				require.Equal(t, tx.out.RawBytes, <-recv)
			}

			require.Equal(t, tx.data["inflight"].(int64), atomic.LoadInt64(&s.Info.Inflight))
			require.Equal(t, tx.data["recvquota"].(int32), cl.State.Inflight.ReceiveQuota())
			require.Equal(t, tx.data["sendquota"].(int32), cl.State.Inflight.SendQuota())
		})
	}

	_, ok := cl.State.Inflight.Get(pID)
	require.False(t, ok)
}

func TestServerReceivePacketError(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	err := s.receivePacket(cl, *packets.TPacketData[packets.Unsubscribe].Get(packets.TUnsubscribeSpecQosMustPacketID).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationNoPacketID)
}

func TestServerRecievePacketDisconnectClientZeroNonZero(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.Props.SessionExpiryInterval = 0
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Props.RequestProblemInfo = 0
	cl.Properties.Props.RequestProblemInfoFlag = true
	go func() {
		err := s.receivePacket(cl, *packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectMqtt5).Packet)
		require.Error(t, err)
		require.ErrorIs(t, err, packets.ErrProtocolViolationZeroNonZeroExpiry)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectZeroNonZeroExpiry).RawBytes, buf)
}

func TestServerRecievePacketDisconnectClient(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.DisconnectClient(cl, packets.CodeDisconnect)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes, buf)
}

func TestServerProcessPacketDisconnect(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.Props.SessionExpiryInterval = 30
	cl.Properties.ProtocolVersion = 5

	s.loop.willDelayed.Add(cl.ID, packets.Packet{TopicName: "a/b/c", Payload: []byte("hello")})
	require.Equal(t, 1, s.loop.willDelayed.Len())

	err := s.processPacket(cl, *packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectMqtt5).Packet)
	require.NoError(t, err)

	require.Equal(t, 0, s.loop.willDelayed.Len())
	require.True(t, cl.Closed())
	require.Equal(t, time.Now().Unix(), atomic.LoadInt64(&cl.State.disconnected))
}

func TestServerProcessPacketDisconnectNonZeroExpiryViolation(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.Props.SessionExpiryInterval = 0
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Props.RequestProblemInfo = 0
	cl.Properties.Props.RequestProblemInfoFlag = true

	err := s.processPacket(cl, *packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectMqtt5).Packet)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationZeroNonZeroExpiry)
}

func TestServerProcessPacketDisconnectDisconnectWithWillMessage(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	cl.Properties.Props.SessionExpiryInterval = 30
	cl.Properties.ProtocolVersion = 5

	s.loop.willDelayed.Add(cl.ID, packets.Packet{TopicName: "a/b/c", Payload: []byte("hello")})
	require.Equal(t, 1, s.loop.willDelayed.Len())

	err := s.processPacket(cl, *packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectMqtt5DisconnectWithWillMessage).Packet)
	require.Error(t, err)

	require.Equal(t, 1, s.loop.willDelayed.Len())
	require.False(t, cl.Closed())
}

func TestServerProcessPacketAuth(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()

	go func() {
		err := s.processPacket(cl, *packets.TPacketData[packets.Auth].Get(packets.TAuth).Packet)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, []byte{}, buf)
}

func TestServerProcessPacketAuthInvalidReason(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()
	pkx := *packets.TPacketData[packets.Auth].Get(packets.TAuth).Packet
	pkx.ReasonCode = 99
	err := s.processPacket(cl, pkx)
	require.Error(t, err)
	require.ErrorIs(t, packets.ErrProtocolViolationInvalidReason, err)
}

func TestServerProcessPacketAuthFailure(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()

	hook := new(modifiedHookBase)
	hook.fail = true
	err := s.AddHook(hook, nil)
	require.NoError(t, err)

	err = s.processAuth(cl, *packets.TPacketData[packets.Auth].Get(packets.TAuth).Packet)
	require.Error(t, err)
	require.ErrorIs(t, errTestHook, err)
}

func TestServerSendLWT(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	sender, _, w1 := newTestClient()
	sender.ID = "sender"
	sender.Properties.Will = Will{
		Flag:      1,
		TopicName: "a/b/c",
		Payload:   []byte("hello mochi"),
	}
	s.Clients.Add(sender)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c", Qos: 0})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))
	require.Equal(t, 0, len(s.Topics.Messages("a/b/c")))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		s.sendLWT(sender)
		time.Sleep(time.Millisecond * 10)
		_ = w1.Close()
		_ = w2.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
}

func TestServerSendLWTRetain(t *testing.T) {
	s := newServer()
	_ = s.Serve()
	defer s.Close()

	sender, _, w1 := newTestClient()
	sender.ID = "sender"
	sender.Properties.Will = Will{
		Flag:      1,
		TopicName: "a/b/c",
		Payload:   []byte("hello mochi"),
		Retain:    true,
	}
	s.Clients.Add(sender)

	receiver, r2, w2 := newTestClient()
	receiver.ID = "receiver"
	s.Clients.Add(receiver)
	s.Topics.Subscribe(receiver.ID, packets.Subscription{Filter: "a/b/c", Qos: 0})

	require.Equal(t, int64(0), atomic.LoadInt64(&s.Info.PacketsReceived))
	require.Equal(t, 0, len(s.Topics.Messages("a/b/c")))

	receiverBuf := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r2)
		require.NoError(t, err)
		receiverBuf <- buf
	}()

	go func() {
		s.sendLWT(sender)
		time.Sleep(time.Millisecond * 10)
		_ = w1.Close()
		_ = w2.Close()
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-receiverBuf)
}

func TestServerSendLWTDelayed(t *testing.T) {
	s := newServer()
	cl1, _, _ := newTestClient()
	cl1.ID = "cl1"
	cl1.Properties.Will = Will{
		Flag:              1,
		TopicName:         "a/b/c",
		Payload:           []byte("hello mochi"),
		Retain:            true,
		WillDelayInterval: 2,
	}
	s.Clients.Add(cl1)

	cl2, r, w := newTestClient()
	cl2.ID = "cl2"
	s.Clients.Add(cl2)
	require.True(t, s.Topics.Subscribe(cl2.ID, packets.Subscription{Filter: "a/b/c"}))

	go func() {
		s.sendLWT(cl1)
		pk, ok := s.loop.willDelayed.Get(cl1.ID)
		require.True(t, ok)
		pk.Expiry = time.Now().Unix() - 1 // set back expiry time
		s.loop.willDelayed.Add(cl1.ID, pk)
		require.Equal(t, 1, s.loop.willDelayed.Len())
		s.sendDelayedLWT(time.Now().Unix())
		require.Equal(t, 0, s.loop.willDelayed.Len())
		time.Sleep(time.Millisecond)
		_ = w.Close()
	}()

	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	require.Equal(t, packets.TPacketData[packets.Publish].Get(packets.TPublishBasic).RawBytes, <-recv)
}

func TestServerReadStore(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	_ = s.AddHook(hook, nil)

	hook.failAt = 1 // clients
	err := s.readStore()
	require.Error(t, err)

	hook.failAt = 2 // subscriptions
	err = s.readStore()
	require.Error(t, err)

	hook.failAt = 3 // inflight
	err = s.readStore()
	require.Error(t, err)

	hook.failAt = 4 // retained
	err = s.readStore()
	require.Error(t, err)

	hook.failAt = 5 // sys info
	err = s.readStore()
	require.Error(t, err)
}

func TestServerLoadClients(t *testing.T) {
	v := []storage.Client{
		{ID: "mochi"},
		{ID: "zen"},
		{ID: "mochi-co"},
		{ID: "v3-clean", ProtocolVersion: 4, Clean: true},
		{ID: "v3-not-clean", ProtocolVersion: 4, Clean: false},
		{
			ID:              "v5-clean",
			ProtocolVersion: 5,
			Clean:           true,
			Properties: storage.ClientProperties{
				SessionExpiryInterval: 10,
			},
		},
		{
			ID:              "v5-expire-interval-0",
			ProtocolVersion: 5,
			Properties: storage.ClientProperties{
				SessionExpiryInterval: 0,
			},
		},
		{
			ID:              "v5-expire-interval-not-0",
			ProtocolVersion: 5,
			Properties: storage.ClientProperties{
				SessionExpiryInterval: 10,
			},
		},
	}

	s := newServer()
	require.Equal(t, 0, s.Clients.Len())
	s.loadClients(v)
	require.Equal(t, 6, s.Clients.Len())
	cl, ok := s.Clients.Get("mochi")
	require.True(t, ok)
	require.Equal(t, "mochi", cl.ID)

	_, ok = s.Clients.Get("v3-clean")
	require.False(t, ok)
	_, ok = s.Clients.Get("v3-not-clean")
	require.True(t, ok)
	_, ok = s.Clients.Get("v5-clean")
	require.True(t, ok)
	_, ok = s.Clients.Get("v5-expire-interval-0")
	require.False(t, ok)
	_, ok = s.Clients.Get("v5-expire-interval-not-0")
	require.True(t, ok)
}

func TestServerLoadSubscriptions(t *testing.T) {
	v := []storage.Subscription{
		{ID: "sub1", Client: "mochi", Filter: "a/b/c"},
		{ID: "sub2", Client: "mochi", Filter: "d/e/f", Qos: 1},
		{ID: "sub3", Client: "mochi", Filter: "h/i/j", Qos: 2},
	}

	s := newServer()
	cl, _, _ := newTestClient()
	s.Clients.Add(cl)
	require.Equal(t, 0, cl.State.Subscriptions.Len())
	s.loadSubscriptions(v)
	require.Equal(t, 3, cl.State.Subscriptions.Len())
}

func TestServerLoadInflightMessages(t *testing.T) {
	s := newServer()
	s.loadClients([]storage.Client{
		{ID: "mochi"},
		{ID: "zen"},
		{ID: "mochi-co"},
	})

	require.Equal(t, 3, s.Clients.Len())

	v := []storage.Message{
		{Client: "mochi", Origin: "mochi", PacketID: 1, Payload: []byte("hello world"), TopicName: "a/b/c"},
		{Client: "mochi", Origin: "mochi", PacketID: 2, Payload: []byte("yes"), TopicName: "a/b/c"},
		{Client: "zen", Origin: "zen", PacketID: 3, Payload: []byte("hello world"), TopicName: "a/b/c"},
		{Client: "mochi-co", Origin: "mochi-co", PacketID: 4, Payload: []byte("hello world"), TopicName: "a/b/c"},
	}
	s.loadInflight(v)

	cl, ok := s.Clients.Get("mochi")
	require.True(t, ok)
	require.Equal(t, "mochi", cl.ID)

	msg, ok := cl.State.Inflight.Get(2)
	require.True(t, ok)
	require.Equal(t, []byte{'y', 'e', 's'}, msg.Payload)
	require.Equal(t, "a/b/c", msg.TopicName)

	cl, ok = s.Clients.Get("mochi-co")
	require.True(t, ok)
	msg, ok = cl.State.Inflight.Get(4)
	require.True(t, ok)
}

func TestServerLoadRetainedMessages(t *testing.T) {
	s := newServer()

	v := []storage.Message{
		{Origin: "mochi", FixedHeader: packets.FixedHeader{Retain: true}, Payload: []byte("hello world"), TopicName: "a/b/c"},
		{Origin: "mochi-co", FixedHeader: packets.FixedHeader{Retain: true}, Payload: []byte("yes"), TopicName: "d/e/f"},
		{Origin: "zen", FixedHeader: packets.FixedHeader{Retain: true}, Payload: []byte("hello world"), TopicName: "h/i/j"},
	}
	s.loadRetained(v)
	require.Equal(t, 1, len(s.Topics.Messages("a/b/c")))
	require.Equal(t, 1, len(s.Topics.Messages("d/e/f")))
	require.Equal(t, 1, len(s.Topics.Messages("h/i/j")))
	require.Equal(t, 0, len(s.Topics.Messages("w/x/y")))
}

func TestServerClose(t *testing.T) {
	s := newServer()

	hook := new(modifiedHookBase)
	_ = s.AddHook(hook, nil)

	cl, r, _ := newTestClient()
	cl.Net.Listener = "t1"
	cl.Properties.ProtocolVersion = 5
	s.Clients.Add(cl)

	err := s.AddListener(listeners.NewMockListener("t1", ":1882"))
	require.NoError(t, err)
	_ = s.Serve()

	// receive the disconnect
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r)
		require.NoError(t, err)
		recv <- buf
	}()

	time.Sleep(time.Millisecond)
	require.Equal(t, 1, s.Listeners.Len())

	listener, ok := s.Listeners.Get("t1")
	require.Equal(t, true, ok)
	require.Equal(t, true, listener.(*listeners.MockListener).IsServing())

	_ = s.Close()
	time.Sleep(time.Millisecond)
	require.Equal(t, false, listener.(*listeners.MockListener).IsServing())
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectShuttingDown).RawBytes, <-recv)
}

func TestLoadServerInfoRestoreOnRestart(t *testing.T) {
	s := New(nil)
	s.Options.Capabilities.Compatibilities.RestoreSysInfoOnRestart = true
	info := system.Info{
		BytesReceived: 60,
	}

	s.loadServerInfo(info)
	require.Equal(t, int64(60), s.Info.BytesReceived)
}

func TestItoa(t *testing.T) {
	i := int64(22)
	require.Equal(t, "22", Int64toa(i))
}

func TestMinimum(t *testing.T) {
	require.EqualValues(t, 0, minimum(0, 0))
	require.EqualValues(t, 1, minimum(0, 1))
	require.EqualValues(t, 1, minimum(1, 0))
	require.EqualValues(t, 10, minimum(10, 20))
	require.EqualValues(t, 20, minimum(30, 20))
	require.EqualValues(t, -1, minimum(-1, 0)) // negative values are not used, but included here for completeness
	require.EqualValues(t, -1, minimum(-1, 20))
	require.EqualValues(t, -2, minimum(-1, -2))
}
