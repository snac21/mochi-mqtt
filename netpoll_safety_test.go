// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package mqtt

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/listeners"
	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/stretchr/testify/require"
)

type CaptureHook struct {
	HookBase
	captured chan []byte
}

func (h *CaptureHook) ID() string {
	return "capture-hook"
}

func (h *CaptureHook) Provides(b byte) bool {
	return b == OnPublish
}

func (h *CaptureHook) OnPublish(cl *Client, pk packets.Packet) (packets.Packet, error) {
	h.captured <- pk.Payload
	return pk, nil
}

func newNetpollTestServer() *Server {
	cc := NewDefaultServerCapabilities()
	cc.MaximumMessageExpiryInterval = 0
	s := New(&Options{
		Capabilities: cc,
	})
	_ = s.AddHook(new(AllowHook), nil)
	return s
}

func netpollConnectBytes(clientID string) []byte {
	pk := packets.Packet{
		FixedHeader:     packets.FixedHeader{Type: packets.Connect},
		ProtocolVersion: 4,
		Connect: packets.ConnectParams{
			ProtocolName:     []byte("MQTT"),
			Clean:            true,
			Keepalive:        60,
			ClientIdentifier: clientID,
		},
	}

	var buf bytes.Buffer
	_ = pk.ConnectEncode(&buf)
	return buf.Bytes()
}

func startNetpollSafetyListener(t *testing.T, s *Server, id string) *listeners.Netpoll {
	t.Helper()

	require.NoError(t, s.Serve())
	t.Cleanup(func() {
		_ = s.Close()
	})

	l := listeners.NewNetpoll(listeners.Config{
		ID:      id,
		Address: "127.0.0.1:0",
	})
	require.NoError(t, s.AddListener(l))

	go l.Serve(s.EstablishConnection)
	return l
}

func TestNetpollRejectedConnectDoesNotDecrementExistingClientCount(t *testing.T) {
	s := newNetpollTestServer()
	s.Options.Capabilities.MaximumClients = 1
	atomic.StoreInt64(&s.Info.ClientsConnected, 1)
	l := startNetpollSafetyListener(t, s, "netpoll-safety-max-clients")

	conn, err := net.Dial("tcp", l.Address())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(netpollConnectBytes("maxed"))
	require.NoError(t, err)

	connack := make([]byte, 4)
	_, err = io.ReadFull(conn, connack)
	require.NoError(t, err)
	require.Equal(t, byte(packets.Connack<<4), connack[0])

	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, _ = conn.Read(make([]byte, 1))
	require.Equal(t, int64(1), atomic.LoadInt64(&s.Info.ClientsConnected))
}

func TestNetpollRejectsPacketsOverMaximumPacketSize(t *testing.T) {
	s := newNetpollTestServer()
	s.Options.Capabilities.MaximumPacketSize = 32

	capturedChan := make(chan []byte, 1)
	hook := &CaptureHook{captured: capturedChan}
	hook.SetOpts(s.Log, nil)
	require.NoError(t, s.AddHook(hook, nil))

	l := startNetpollSafetyListener(t, s, "netpoll-safety-max-packet")

	conn, err := net.Dial("tcp", l.Address())
	require.NoError(t, err)
	defer conn.Close()

	_, err = conn.Write(netpollConnectBytes("sized"))
	require.NoError(t, err)

	connack := make([]byte, 4)
	_, err = io.ReadFull(conn, connack)
	require.NoError(t, err)

	publishBytes := append([]byte{
		0x30, 69,
		0x00, 0x03, 'b', 'i', 'g',
	}, bytes.Repeat([]byte{'x'}, 64)...)
	_, err = conn.Write(publishBytes)
	require.NoError(t, err)

	select {
	case payload := <-capturedChan:
		t.Fatalf("oversized netpoll publish reached OnPublish: %q", payload)
	case <-time.After(200 * time.Millisecond):
	}
}

// TestNetpollPayloadDataSafety 针对性测试零拷贝数据生命周期篡改隐患
// 在同一个 Socket 上先发送一个 Publish，随后立刻发送大量的脏数据冲刷底层 LinkBuffer。
// 验证 Broker 中捕获到的 Payload 切片内容依然保持完整正确，不被网络层后续事件篡改。
func TestNetpollPayloadDataSafety(t *testing.T) {
	s := newNetpollTestServer()
	s.Log = slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))
	capturedChan := make(chan []byte, 1)
	hook := &CaptureHook{
		captured: capturedChan,
	}
	hook.SetOpts(s.Log, nil)
	err := s.AddHook(hook, nil)
	require.NoError(t, err)

	require.NoError(t, s.Serve())
	defer s.Close()

	l := listeners.NewNetpoll(listeners.Config{
		ID:      "netpoll-safety-1",
		Address: "127.0.0.1:0",
	})
	err = s.AddListener(l)
	require.NoError(t, err)

	// 启动网络事件分发
	go l.Serve(s.EstablishConnection)

	addr := l.Address()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	// 1. 发送 CONNECT 包
	connectBytes := []byte{
		0x10, 12, // CONNECT, 剩余长度 12
		0x00, 0x04, 'M', 'Q', 'T', 'T', // 协议名
		0x04,       // v3.1.1
		0x02,       // Clean Session
		0x00, 0x3c, // Keepalive 60
		0x00, 0x00, // ClientID (空)
	}
	_, err = conn.Write(connectBytes)
	require.NoError(t, err)

	// 接收 Connack
	connack := make([]byte, 4)
	_, err = conn.Read(connack)
	require.NoError(t, err)

	// 2. 发送 PUBLISH 报文：主题 "t", 载荷 "HELLO"
	// 固定头 0x30, 剩余长度 8
	// 主题长度 2, "t"
	// 载荷 "HELLO"
	publishBytes := []byte{
		0x30, 8,
		0x00, 0x01, 't',
		'H', 'E', 'L', 'L', 'O',
	}
	_, err = conn.Write(publishBytes)
	require.NoError(t, err)

	// 3. 立刻追加发送 2048 字节的无意义脏数据以强制冲刷底层缓存环
	garbage := make([]byte, 2048)
	for i := range garbage {
		garbage[i] = 0x5a // 'Z'
	}
	_, _ = conn.Write(garbage)

	// 4. 验证捕获到的 Payload 内容
	select {
	case payload := <-capturedChan:
		require.Equal(t, "HELLO", string(payload), "Payload data was corrupted/tampered by zero-copy recycle")
	case <-time.After(15 * time.Second):
		t.Fatal("Timeout waiting for OnPublish hook to capture payload")
	}
}

// TestNetpollKeepaliveRefresh 针对性测试活跃连接 Keepalive 刷新功能
// 保持极短的 2s 心跳设定，以 1s 间隔连续发送 PING 控制报文。
// 验证在活跃的消息传输状态下，客户端不会因为未刷新 Deadline 而被 Broker 心跳超时误踢。
func TestNetpollKeepaliveRefresh(t *testing.T) {
	s := newNetpollTestServer()
	require.NoError(t, s.Serve())
	defer s.Close()

	l := listeners.NewNetpoll(listeners.Config{
		ID:      "netpoll-safety-2",
		Address: "127.0.0.1:0",
	})
	err := s.AddListener(l)
	require.NoError(t, err)

	go l.Serve(s.EstablishConnection)

	addr := l.Address()
	conn, err := net.Dial("tcp", addr)
	require.NoError(t, err)
	defer conn.Close()

	// 1. 发送 CONNECT 包，Keepalive 设置为 2s
	connectBytes := []byte{
		0x10, 12,
		0x00, 0x04, 'M', 'Q', 'T', 'T',
		0x04,
		0x02,
		0x00, 0x02, // Keepalive = 2 seconds
		0x00, 0x00,
	}
	_, err = conn.Write(connectBytes)
	require.NoError(t, err)

	// 接收 Connack
	connack := make([]byte, 4)
	_, err = conn.Read(connack)
	require.NoError(t, err)

	// 2. 以 1s 间隔发送 4 次 PINGREQ 并读取 PINGRESP
	// 若刷新起作用，整条交互总计 4 秒以上，由于每次交互都延后了 Deadline，不会导致心跳超时断开。
	pingreq := []byte{0xc0, 0x00}
	for i := 0; i < 4; i++ {
		time.Sleep(1 * time.Second)
		_, err = conn.Write(pingreq)
		require.NoError(t, err, "Connection was abnormally closed by broker (write error)")

		resp := make([]byte, 2)
		_, err = conn.Read(resp)
		require.NoError(t, err, "Connection was abnormally closed by broker (read PINGRESP error)")
		require.Equal(t, byte(0xd0), resp[0], "Should receive PINGRESP")
	}
}
