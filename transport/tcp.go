// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
)

var _ Transport = (*TCPTransport)(nil) // compile-time interface check

// TCPTransport implements the blocking I/O transport layer based on the standard library net.Conn.
type TCPTransport struct {
	conn   net.Conn
	Bconn  *bufio.Reader // Exposed for backward compatibility with Mock tests
	outbuf *bytes.Buffer
}

func NewTCPTransport(conn net.Conn, readBufferSize int) *TCPTransport {
	return &TCPTransport{
		conn:  conn,
		Bconn: bufio.NewReaderSize(conn, readBufferSize),
	}
}

func (t *TCPTransport) ReadFixedHeader(maxPacketSize uint32) (fh packets.FixedHeader, bytesRead int, err error) {
	if t.Bconn == nil {
		return fh, 0, ErrConnectionClosed
	}

	b, err := t.Bconn.ReadByte()
	if err != nil {
		return fh, 0, err
	}

	err = fh.Decode(b)
	if err != nil {
		return fh, 0, err
	}

	var bu int
	fh.Remaining, bu, err = packets.DecodeLength(t.Bconn)
	if err != nil {
		return fh, 0, err
	}

	if maxPacketSize > 0 && uint32(fh.Remaining+1) > maxPacketSize {
		return fh, bu + 1, packets.ErrPacketTooLarge
	}

	return fh, bu + 1, nil
}

func (t *TCPTransport) ReadPacket(fh *packets.FixedHeader, protocolVersion byte) (pk packets.Packet, bytesRead int, err error) {
	if t.Bconn == nil {
		return pk, 0, ErrConnectionClosed
	}

	pk.ProtocolVersion = protocolVersion
	pk.FixedHeader = *fh

	var px []byte
	var n int
	if fh.Remaining > 0 {
		px = make([]byte, fh.Remaining)
		n, err = io.ReadFull(t.Bconn, px)
		if err != nil {
			return pk, 0, err
		}
	}

	err = DecodePacketPayload(&pk, px)
	return pk, n, err
}

func (t *TCPTransport) ReadPacketDirect(protocolVersion byte, maxPacketSize uint32) (packets.Packet, int, error) {
	return packets.Packet{}, 0, fmt.Errorf("ReadPacketDirect not supported for TCPTransport")
}

func (t *TCPTransport) Write(buf *bytes.Buffer, outboundQueueLen int, writeBufferSize int) (int64, error) {
	if outboundQueueLen == 0 {
		if t.outbuf == nil {
			return buf.WriteTo(t.conn)
		}

		n, _ := t.outbuf.Write(buf.Bytes())
		err := t.Flush()
		return int64(n), err
	}

	if t.outbuf == nil {
		if buf.Len() >= writeBufferSize {
			return buf.WriteTo(t.conn)
		}
		t.outbuf = new(bytes.Buffer)
	}

	n, _ := t.outbuf.Write(buf.Bytes())
	if t.outbuf.Len() < writeBufferSize {
		return int64(n), nil
	}

	err := t.Flush()
	return int64(n), err
}

func (t *TCPTransport) Flush() (err error) {
	if t.outbuf == nil {
		return
	}
	_, err = t.outbuf.WriteTo(t.conn)
	if err == nil {
		t.outbuf = nil
	}
	return
}

func (t *TCPTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *TCPTransport) SetDeadline(tim time.Time) error {
	if t.conn != nil {
		return t.conn.SetDeadline(tim)
	}
	return nil
}

func (t *TCPTransport) UnderlyingConn() any {
	return t.conn
}

func (t *TCPTransport) IsEventDriven() bool {
	return false
}
