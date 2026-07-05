// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/stretchr/testify/require"
)

func TestServerReadConnectionPacket(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r, _ := newTestClient()
	s.Clients.Add(cl)

	o := make(chan packets.Packet)
	go func() {
		pk, err := s.readConnectionPacket(cl)
		require.NoError(t, err)
		o <- pk
	}()

	go func() {
		_, _ = r.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).RawBytes)
		_ = r.Close()
	}()

	require.Equal(t, *packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet, <-o)
}

func TestServerReadConnectionPacketBadFixedHeader(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r, _ := newTestClient()
	s.Clients.Add(cl)

	o := make(chan error)
	go func() {
		_, err := s.readConnectionPacket(cl)
		o <- err
	}()

	go func() {
		_, _ = r.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMalFixedHeader).RawBytes)
		_ = r.Close()
	}()

	err := <-o
	require.Error(t, err)
	require.Equal(t, packets.ErrMalformedVariableByteInteger, err)
}

func TestServerReadConnectionPacketBadPacketType(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r, _ := newTestClient()
	s.Clients.Add(cl)

	go func() {
		_, _ = r.Write(packets.TPacketData[packets.Connack].Get(packets.TConnackAcceptedNoSession).RawBytes)
		_ = r.Close()
	}()

	_, err := s.readConnectionPacket(cl)
	require.Error(t, err)
	require.Equal(t, packets.ErrProtocolViolationRequireFirstConnect, err)
}

func TestServerReadConnectionPacketBadPacket(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r, _ := newTestClient()
	s.Clients.Add(cl)

	go func() {
		_, _ = r.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMalProtocolName).RawBytes)
		_ = r.Close()
	}()

	_, err := s.readConnectionPacket(cl)
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrMalformedProtocolName)
}

func TestEstablishConnection(t *testing.T) {
	s := newServer()
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.NoError(t, err)

	// Todo:
	// 		s.Clients is already empty here. Is it necessary to check v.StopCause()?

	// for _, v := range s.Clients.GetAll() {
	// 	require.ErrorIs(t, v.StopCause(), packets.CodeDisconnect) // true error is disconnect
	// }

	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackAcceptedNoSession).RawBytes, <-recv)

	_ = w.Close()
	_ = r.Close()

	// client must be deleted on session close if Clean = true
	_, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).Packet.Connect.ClientIdentifier)
	require.False(t, ok)
}

func TestEstablishConnectionAckFailure(t *testing.T) {
	s := newServer()
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
		_ = w.Close()
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)

	_ = r.Close()
}

func TestEstablishConnectionReadError(t *testing.T) {
	s := newServer()
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt5).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes) // second connect error
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.Error(t, err)

	// Retrieve the client corresponding to the Client Identifier.
	retrievedCl, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt5).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	require.ErrorIs(t, retrievedCl.StopCause(), packets.ErrProtocolViolationSecondConnect) // true error is disconnect

	ret := <-recv
	require.Equal(t, append(
		packets.TPacketData[packets.Connack].Get(packets.TConnackMinCleanMqtt5).RawBytes,
		packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectSecondConnect).RawBytes...),
		ret,
	)

	_ = w.Close()
	_ = r.Close()
}

func TestEstablishConnectionInheritExisting(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r0, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Username = []byte("mochi")
	cl.ID = packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier
	cl.State.Subscriptions.Add("a/b/c", packets.Subscription{Filter: "a/b/c", Qos: 1})
	cl.State.Inflight.Set(*packets.TPacketData[packets.Publish].Get(packets.TPublishQos1).Packet)
	s.Clients.Add(cl)

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		err := s.EstablishConnection("tcp", r)
		o <- err
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).RawBytes)
		time.Sleep(time.Millisecond) // we want to receive the queued inflight, so we need to wait a moment before sending the disconnect.
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the disconnect session takeover
	takeover := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r0)
		require.NoError(t, err)
		takeover <- buf
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.NoError(t, err)

	// Retrieve the client corresponding to the Client Identifier.
	retrievedCl, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	require.ErrorIs(t, retrievedCl.StopCause(), packets.CodeDisconnect) // true error is disconnect

	connackPlusPacket := append(
		packets.TPacketData[packets.Connack].Get(packets.TConnackAcceptedSessionExists).RawBytes,
		packets.TPacketData[packets.Publish].Get(packets.TPublishQos1Dup).RawBytes...,
	)
	require.Equal(t, connackPlusPacket, <-recv)
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnectTakeover).RawBytes, <-takeover)

	time.Sleep(time.Microsecond * 100)
	_ = w.Close()
	_ = r.Close()

	clw, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	require.NotEmpty(t, clw.State.Subscriptions)
	require.True(t, cl.IsTakenOver())

	// Prevent sequential takeover memory-bloom.
	require.Empty(t, cl.State.Subscriptions.GetAll())
}

func TestEstablishConnectionInheritExistingTrueTakeover(t *testing.T) {
	s := newServer()
	d := new(DelayHook)
	d.DisconnectDelay = time.Millisecond * 200
	_ = s.AddHook(d, nil)
	defer s.Close()

	// Clean session, 0 session expiry interval
	cl1RawBytes := []byte{
		packets.Connect << 4, 21, // Fixed header
		0, 4, // Protocol Name - MSB+LSB
		'M', 'Q', 'T', 'T', // Protocol Name
		5,      // Protocol Version
		1 << 1, // Packet Flags
		0, 30,  // Keepalive
		5,              // Properties length
		17, 0, 0, 0, 0, // Session Expiry Interval (17)
		0, 3, // Client ID - MSB+LSB
		'z', 'e', 'n', // Client ID "zen"
	}

	// Make first connection
	r1, w1 := net.Pipe()
	o1 := make(chan error)
	go func() {
		err := s.EstablishConnection("tcp", r1)
		o1 <- err
	}()
	go func() {
		_, _ = w1.Write(cl1RawBytes)
	}()

	// receive the first connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w1)
		require.NoError(t, err)
		recv <- buf
	}()

	// Get the first client pointer
	time.Sleep(time.Millisecond * 50)
	cl1, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectUserPass).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	cl1.State.Subscriptions.Add("a/b/c", packets.Subscription{Filter: "a/b/c", Qos: 1})
	cl1.State.Subscriptions.Add("d/e/f", packets.Subscription{Filter: "d/e/f", Qos: 0})
	time.Sleep(time.Millisecond * 50)

	// Make the second connection
	r2, w2 := net.Pipe()
	o2 := make(chan error)
	go func() {
		err := s.EstablishConnection("tcp", r2)
		o2 <- err
	}()
	go func() {
		x := packets.TPacketData[packets.Connect].Get(packets.TConnectUserPass).RawBytes[:]
		x[19] = '.' // differentiate username bytes in debugging
		_, _ = w2.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectUserPass).RawBytes)
	}()

	// receive the second connack
	recv2 := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w2)
		require.NoError(t, err)
		recv2 <- buf
	}()

	// Capture first Client pointer
	clp1, ok := s.Clients.Get("zen")
	require.True(t, ok)
	require.Empty(t, clp1.Properties.Username)
	require.NotEmpty(t, clp1.State.Subscriptions.GetAll())

	err1 := <-o1
	require.Error(t, err1)
	require.ErrorIs(t, err1, io.ErrClosedPipe)

	// Capture second Client pointer
	clp2, ok := s.Clients.Get("zen")
	require.True(t, ok)
	require.Equal(t, []byte(".ochi"), clp2.Properties.Username)
	require.NotEmpty(t, clp2.State.Subscriptions.GetAll())
	require.Empty(t, clp1.State.Subscriptions.GetAll())

	_, _ = w2.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	require.NoError(t, <-o2)

	require.True(t, clp1.IsTakenOver())
	require.False(t, clp2.IsTakenOver())
}

func TestEstablishConnectionResentPendingInflightsError(t *testing.T) {
	s := newServer()
	defer s.Close()

	n := time.Now().Unix()
	cl, r0, _ := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.ID = packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier
	cl.State.Inflight = NewInflights()
	cl.State.Inflight.Set(packets.Packet{PacketID: 2, Created: n - 2}) // no packet type
	s.Clients.Add(cl)

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).RawBytes)
	}()

	go func() {
		_, err := io.ReadAll(r0)
		require.NoError(t, err)
	}()

	go func() {
		_, err := io.ReadAll(w)
		require.NoError(t, err)
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrNoValidPacketAvailable)
}

func TestEstablishConnectionInheritExistingClean(t *testing.T) {
	s := newServer()
	defer s.Close()

	cl, r0, _ := newTestClient()
	cl.ID = packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier
	cl.Properties.Clean = true
	cl.State.Subscriptions.Add("a/b/c", packets.Subscription{Filter: "a/b/c", Qos: 1})
	s.Clients.Add(cl)

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the disconnect
	takeover := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(r0)
		require.NoError(t, err)
		takeover <- buf
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.NoError(t, err)

	// Retrieve the client corresponding to the Client Identifier.
	retrievedCl, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	require.ErrorIs(t, retrievedCl.StopCause(), packets.CodeDisconnect) // true error is disconnect

	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackAcceptedNoSession).RawBytes, <-recv)
	require.Equal(t, packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes, <-takeover)

	require.True(t, cl.IsTakenOver())

	_ = w.Close()
	_ = r.Close()

	clw, ok := s.Clients.Get(packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt311).Packet.Connect.ClientIdentifier)
	require.True(t, ok)
	require.Equal(t, 0, clw.State.Subscriptions.Len())

}

func TestEstablishConnectionBadAuthentication(t *testing.T) {
	s := New(&Options{
		Logger: logger,
	})
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrBadUsernameOrPassword)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackBadUsernamePasswordNoSession).RawBytes, <-recv)

	_ = w.Close()
	_ = r.Close()
}

func TestEstablishConnectionBadAuthenticationAckFailure(t *testing.T) {
	s := New(&Options{
		Logger: logger,
	})
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
		_ = w.Close()
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)

	_ = r.Close()
}

func TestServerEstablishConnectionInvalidConnect(t *testing.T) {
	s := newServer()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMalReservedBit).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, packets.ErrProtocolViolationReservedBit, err)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackProtocolViolationNoSession).RawBytes, <-recv)

	_ = r.Close()
}

func TestEstablishConnectionMaximumClientsReached(t *testing.T) {
	cc := NewDefaultServerCapabilities()
	cc.MaximumClients = 0
	s := New(&Options{
		Logger:       logger,
		Capabilities: cc,
	})
	_ = s.AddHook(new(AllowHook), nil)
	defer s.Close()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
	}()

	// receive the connack
	recv := make(chan []byte)
	go func() {
		buf, err := io.ReadAll(w)
		require.NoError(t, err)
		recv <- buf
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrServerBusy)

	_ = r.Close()
}

func TestServerEstablishConnectionZeroByteUsernameIsValid(t *testing.T) {
	s := newServer()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectZeroByteUsername).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	// receive the connack error
	go func() {
		_, err := io.ReadAll(w)
		require.NoError(t, err)
	}()

	err := <-o
	require.NoError(t, err)

	_ = r.Close()
}

func TestServerEstablishConnectionInvalidConnectAckFailure(t *testing.T) {
	s := newServer()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectMalReservedBit).RawBytes)
		_ = w.Close()
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, io.ErrClosedPipe)

	_ = r.Close()
}

func TestServerEstablishConnectionBadPacket(t *testing.T) {
	s := newServer()

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnackBadProtocolVersion).RawBytes)
		_, _ = w.Write(packets.TPacketData[packets.Disconnect].Get(packets.TDisconnect).RawBytes)
	}()

	err := <-o
	require.Error(t, err)
	require.ErrorIs(t, err, packets.ErrProtocolViolationRequireFirstConnect)

	_ = r.Close()
}

func TestServerEstablishConnectionOnConnectError(t *testing.T) {
	s := newServer()
	hook := new(modifiedHookBase)
	hook.fail = true
	err := s.AddHook(hook, nil)
	require.NoError(t, err)

	r, w := net.Pipe()
	o := make(chan error)
	go func() {
		o <- s.EstablishConnection("tcp", r)
	}()

	go func() {
		_, _ = w.Write(packets.TPacketData[packets.Connect].Get(packets.TConnectClean).RawBytes)
	}()

	err = <-o
	require.Error(t, err)
	require.ErrorIs(t, err, errTestHook)

	_ = r.Close()
}

func TestServerSendConnack(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	s.Options.Capabilities.MaximumQos = 1
	cl.Properties.Props = packets.Properties{
		AssignedClientID: "mochi",
	}
	go func() {
		err := s.SendConnack(cl, packets.CodeSuccess, true, nil)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackMinMqtt5).RawBytes, buf)
}

func TestServerSendConnackFailureReason(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	go func() {
		err := s.SendConnack(cl, packets.ErrUnspecifiedError, true, nil)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackInvalidMinMqtt5).RawBytes, buf)
}

func TestServerSendConnackWithServerKeepalive(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.State.Keepalive = 10
	cl.State.ServerKeepalive = true
	go func() {
		err := s.SendConnack(cl, packets.CodeSuccess, true, nil)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackServerKeepalive).RawBytes, buf)
}

func TestServerValidateConnect(t *testing.T) {
	packet := *packets.TPacketData[packets.Connect].Get(packets.TConnectMqtt5).Packet
	invalidBitPacket := packet
	invalidBitPacket.ReservedBit = 1
	packetCleanIdPacket := packet
	packetCleanIdPacket.Connect.Clean = false
	packetCleanIdPacket.Connect.ClientIdentifier = ""
	tt := []struct {
		desc         string
		client       *Client
		capabilities Capabilities
		packet       packets.Packet
		expect       packets.Code
	}{
		{
			desc:         "unsupported protocol version",
			client:       &Client{Properties: ClientProperties{ProtocolVersion: 3}},
			capabilities: Capabilities{MinimumProtocolVersion: 4},
			packet:       packet,
			expect:       packets.ErrUnsupportedProtocolVersion,
		},
		{
			desc:         "will qos not supported",
			client:       &Client{Properties: ClientProperties{Will: Will{Qos: 2}}},
			capabilities: Capabilities{MaximumQos: 1},
			packet:       packet,
			expect:       packets.ErrQosNotSupported,
		},
		{
			desc:         "retain not supported",
			client:       &Client{Properties: ClientProperties{Will: Will{Retain: true}}},
			capabilities: Capabilities{RetainAvailable: 0},
			packet:       packet,
			expect:       packets.ErrRetainNotSupported,
		},
		{
			desc:         "invalid packet validate",
			client:       &Client{Properties: ClientProperties{Will: Will{Retain: true}}},
			capabilities: Capabilities{RetainAvailable: 0},
			packet:       invalidBitPacket,
			expect:       packets.ErrProtocolViolationReservedBit,
		},
		{
			desc:         "mqtt3 clean no client id ",
			client:       &Client{Properties: ClientProperties{ProtocolVersion: 3}},
			capabilities: Capabilities{},
			packet:       packetCleanIdPacket,
			expect:       packets.ErrUnspecifiedError,
		},
	}

	s := newServer()
	for _, tx := range tt {
		t.Run(tx.desc, func(t *testing.T) {
			s.Options.Capabilities = &tx.capabilities
			err := s.validateConnect(tx.client, tx.packet)
			require.Error(t, err)
			require.ErrorIs(t, err, tx.expect)
		})
	}
}

func TestServerSendConnackAdjustedExpiryInterval(t *testing.T) {
	s := newServer()
	cl, r, w := newTestClient()
	cl.Properties.ProtocolVersion = 5
	cl.Properties.Props.SessionExpiryInterval = uint32(300)
	s.Options.Capabilities.MaximumSessionExpiryInterval = 120
	go func() {
		err := s.SendConnack(cl, packets.CodeSuccess, false, nil)
		require.NoError(t, err)
		_ = w.Close()
	}()

	buf, err := io.ReadAll(r)
	require.NoError(t, err)
	require.Equal(t, packets.TPacketData[packets.Connack].Get(packets.TConnackAcceptedAdjustedExpiryInterval).RawBytes, buf)
}

func TestServerProcessPacketConnect(t *testing.T) {
	s := newServer()
	cl, _, _ := newTestClient()

	err := s.processPacket(cl, *packets.TPacketData[packets.Connect].Get(packets.TConnectClean).Packet)
	require.Error(t, err)
}
