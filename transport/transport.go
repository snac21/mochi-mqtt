// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package transport

import (
	"bytes"
	"errors"
	"fmt"
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

	// IsEventDriven returns true if the transport uses event-driven I/O (e.g. Netpoll).
	// Event-driven transports don't need a WriteLoop goroutine and write packets synchronously.
	IsEventDriven() bool

	// Flush flushes the write buffer to the underlying connection.
	Flush() error
}

// DecodePacketPayload decodes the packet payload based on the fixed header type.
// This is a shared helper used by both TCPTransport and NetpollTransport to avoid code duplication.
func DecodePacketPayload(pk *packets.Packet, px []byte) error {
	switch pk.FixedHeader.Type {
	case packets.Connect:
		return pk.ConnectDecode(px)
	case packets.Disconnect:
		return pk.DisconnectDecode(px)
	case packets.Connack:
		return pk.ConnackDecode(px)
	case packets.Publish:
		return pk.PublishDecode(px)
	case packets.Puback:
		return pk.PubackDecode(px)
	case packets.Pubrec:
		return pk.PubrecDecode(px)
	case packets.Pubrel:
		return pk.PubrelDecode(px)
	case packets.Pubcomp:
		return pk.PubcompDecode(px)
	case packets.Subscribe:
		return pk.SubscribeDecode(px)
	case packets.Suback:
		return pk.SubackDecode(px)
	case packets.Unsubscribe:
		return pk.UnsubscribeDecode(px)
	case packets.Unsuback:
		return pk.UnsubackDecode(px)
	case packets.Pingreq:
		return nil
	case packets.Pingresp:
		return nil
	case packets.Auth:
		return pk.AuthDecode(px)
	default:
		return fmt.Errorf("invalid packet type; %v", pk.FixedHeader.Type)
	}
}
