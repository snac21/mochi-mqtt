// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package transport

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/cloudwego/netpoll"
	"github.com/mochi-mqtt/server/v2/packets"
)

var _ Transport = (*NetpollTransport)(nil) // compile-time interface check

// NetpollTransport implements the non-blocking/event-driven transport layer based on cloudwego/netpoll.
type NetpollTransport struct {
	npConn netpoll.Connection
}

func NewNetpollTransport(conn netpoll.Connection) *NetpollTransport {
	return &NetpollTransport{
		npConn: conn,
	}
}

func (t *NetpollTransport) ReadFixedHeader(maxPacketSize uint32) (packets.FixedHeader, int, error) {
	return packets.FixedHeader{}, 0, fmt.Errorf("ReadFixedHeader not supported on netpoll")
}

func (t *NetpollTransport) ReadPacket(fh *packets.FixedHeader, protocolVersion byte) (packets.Packet, int, error) {
	return packets.Packet{}, 0, fmt.Errorf("ReadPacket not supported on netpoll")
}

func (t *NetpollTransport) ReadPacketDirect(protocolVersion byte, maxPacketSize uint32) (pk packets.Packet, bytesRead int, err error) {
	reader := t.npConn.Reader()
	peekLen := reader.Len()
	if peekLen > 5 {
		peekLen = 5
	}
	if peekLen < 2 {
		return pk, 0, ErrNotEnoughData
	}

	headerBytes, err := reader.Peek(peekLen)
	if err != nil {
		return pk, 0, err
	}

	fh := new(packets.FixedHeader)
	err = fh.Decode(headerBytes[0])
	if err != nil {
		return pk, 0, err
	}

	var remainingLength int
	var multiplier int = 1
	var lengthSize int = 0

	for i := 1; i < len(headerBytes); i++ {
		b := headerBytes[i]
		lengthSize++
		remainingLength += int(b&127) * multiplier
		if (b & 128) == 0 {
			break
		}
		multiplier *= 128
		if multiplier > 128*128*128 {
			return pk, 0, errors.New("remaining length exceeds max protocol size")
		}
	}

	if lengthSize > 0 && (headerBytes[lengthSize]&128) != 0 {
		return pk, 0, ErrNotEnoughData
	}

	fh.Remaining = remainingLength
	if maxPacketSize > 0 && uint32(fh.Remaining+1) > maxPacketSize {
		return pk, lengthSize + 1, packets.ErrPacketTooLarge
	}

	totalPacketLen := 1 + lengthSize + remainingLength
	if reader.Len() < totalPacketLen {
		return pk, 0, ErrNotEnoughData
	}

	_ = reader.Skip(1 + lengthSize)
	px, err := reader.ReadBinary(remainingLength)
	if err != nil {
		return pk, 0, err
	}

	pk.ProtocolVersion = protocolVersion
	pk.FixedHeader = *fh

	pxUsed := make([]byte, len(px))
	copy(pxUsed, px)

	err = DecodePacketPayload(&pk, pxUsed)
	return pk, totalPacketLen, err
}

func (t *NetpollTransport) Write(buf *bytes.Buffer, outboundQueueLen int, writeBufferSize int) (int64, error) {
	writer := t.npConn.Writer()
	_, err := writer.WriteBinary(buf.Bytes())
	if err == nil {
		err = writer.Flush()
	}
	return int64(buf.Len()), err
}

func (t *NetpollTransport) Close() error {
	if t.npConn != nil {
		return t.npConn.Close()
	}
	return nil
}

func (t *NetpollTransport) SetDeadline(tim time.Time) error {
	if t.npConn != nil {
		return t.npConn.SetDeadline(tim)
	}
	return nil
}

func (t *NetpollTransport) UnderlyingConn() any {
	return t.npConn
}

func (t *NetpollTransport) IsEventDriven() bool {
	return true
}

func (t *NetpollTransport) Flush() error {
	return nil
}
