// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package client

import (
	"net"

	"github.com/mochi-mqtt/server/v2/transport"
)

// NewTCPClient returns a new Client instance initialized with a TCP transport.
func NewTCPClient(c net.Conn, o *Ops) Client {
	cl := NewBaseClient(o)
	if c != nil {
		cl.Net = ClientConnection{
			Transport: transport.NewTCPTransport(c, o.ClientNetReadBufferSize),
			Remote:    c.RemoteAddr().String(),
		}
	}
	return cl
}
