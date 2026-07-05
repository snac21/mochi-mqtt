// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2022 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/stretchr/testify/require"
)

var logger = slog.New(slog.NewTextHandler(io.Discard, nil))

type ProtocolTest []struct {
	protocolVersion byte
	in              packets.TPacketCase
	out             packets.TPacketCase
	data            map[string]any
}

type AllowHook struct {
	HookBase
}

func (h *AllowHook) SetOpts(l *slog.Logger, opts *HookOptions) {
	h.Log = l
	h.Opts = opts
}

func (h *AllowHook) ID() string {
	return "allow-all-auth"
}

func (h *AllowHook) Provides(b byte) bool {
	return bytes.Contains([]byte{OnConnectAuthenticate, OnACLCheck}, []byte{b})
}

func (h *AllowHook) OnConnectAuthenticate(cl *Client, pk packets.Packet) bool { return true }
func (h *AllowHook) OnACLCheck(cl *Client, topic string, write bool) bool     { return true }

type DenyHook struct {
	HookBase
}

func (h *DenyHook) SetOpts(l *slog.Logger, opts *HookOptions) {
	h.Log = l
	h.Opts = opts
}

func (h *DenyHook) ID() string {
	return "deny-all-auth"
}

func (h *DenyHook) Provides(b byte) bool {
	return bytes.Contains([]byte{OnConnectAuthenticate, OnACLCheck}, []byte{b})
}

func (h *DenyHook) OnConnectAuthenticate(cl *Client, pk packets.Packet) bool { return false }
func (h *DenyHook) OnACLCheck(cl *Client, topic string, write bool) bool     { return false }

type DelayHook struct {
	HookBase
	DisconnectDelay time.Duration
}

func (h *DelayHook) SetOpts(l *slog.Logger, opts *HookOptions) {
	h.Log = l
	h.Opts = opts
}

func (h *DelayHook) ID() string {
	return "delay-hook"
}

func (h *DelayHook) Provides(b byte) bool {
	return bytes.Contains([]byte{OnDisconnect}, []byte{b})
}

func (h *DelayHook) OnDisconnect(cl *Client, err error, expire bool) {
	time.Sleep(h.DisconnectDelay)
}

func newServer() *Server {
	cc := NewDefaultServerCapabilities()
	cc.MaximumMessageExpiryInterval = 0
	cc.ReceiveMaximum = 0
	s := New(&Options{
		Logger:       logger,
		Capabilities: cc,
	})
	_ = s.AddHook(new(AllowHook), nil)
	return s
}

func newServerWithInlineClient() *Server {
	cc := NewDefaultServerCapabilities()
	cc.MaximumMessageExpiryInterval = 0
	cc.ReceiveMaximum = 0
	s := New(&Options{
		Logger:       logger,
		Capabilities: cc,
		InlineClient: true,
	})
	_ = s.AddHook(new(AllowHook), nil)
	return s
}

// See https://github.com/mochi-mqtt/server/issues/173
// See https://github.com/mochi-mqtt/server/issues/178
func newRejectPacketServer(t *testing.T) (*Server, *Client, net.Conn, net.Conn) {
	t.Helper()

	s := newServer()
	hook := new(modifiedHookBase)
	require.NoError(t, s.AddHook(hook, nil))
	require.NoError(t, s.Serve())
	hook.fail = true
	hook.err = packets.ErrRejectPacket
	t.Cleanup(func() {
		_ = s.Close()
	})

	cl, r, w := newTestClient()
	return s, cl, r, w
}

func requireRejectAck(t *testing.T, buf []byte, packetType byte) {
	t.Helper()

	require.GreaterOrEqual(t, len(buf), 5)
	require.Equal(t, packetType<<4, buf[0])
	require.Equal(t, byte(0), buf[2])
	require.Equal(t, byte(7), buf[3])
	require.Equal(t, packets.ErrRejectPacket.Code, buf[4])
	require.Contains(t, string(buf), packets.ErrRejectPacket.Reason)
}
