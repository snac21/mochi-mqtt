// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package transport

import (
	"bytes"
	"errors"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
)

var (
	ErrConnectionClosed = errors.New("connection not open")
	ErrNotEnoughData    = errors.New("not enough data")
)

// Transport defines the abstract interface for the network transport layer, independent of Client sessions.
type Transport interface {
	// ReadFixedHeader reads the fixed header from the physical connection, returning the FixedHeader, bytes read, and error.
	ReadFixedHeader(maxPacketSize uint32) (packets.FixedHeader, int, error)

	// ReadPacket reads the remaining data from the connection and decodes the packet, returning the Packet, bytes read, and error.
	ReadPacket(fh *packets.FixedHeader, protocolVersion byte) (packets.Packet, int, error)

	// ReadPacketDirect is a direct decoding entry point for event-driven networks like Netpoll.
	ReadPacketDirect(protocolVersion byte, maxPacketSize uint32) (packets.Packet, int, error)

	// Write performs the write of raw packet bytes to the underlying connection.
	Write(buf *bytes.Buffer, outboundQueueLen int, writeBufferSize int) (int64, error)

	// Close closes the underlying physical connection.
	Close() error

	// SetDeadline sets the read and write deadlines associated with the connection.
	SetDeadline(t time.Time) error

	// UnderlyingConn returns the underlying physical connection object (net.Conn or netpoll.Connection) for advanced operations.
	UnderlyingConn() any
}
