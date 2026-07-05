// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package listeners

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/cloudwego/netpoll"
)

const TypeNetpoll = "netpoll"

// Netpoll is a high-performance network listener powered by ByteDance Netpoll (Reactor pattern).
type Netpoll struct {
	sync.RWMutex
	id         string            // the internal id of the listener
	address    string            // the network address to bind to
	listener   netpoll.Listener  // netpoll listener
	eventLoop  netpoll.EventLoop // netpoll event loop for non-blocking reactor I/O
	config     Config            // configuration values for the listener
	log        *slog.Logger      // server logger
	end        uint32            // ensure close methods are only called once
	onRequests sync.Map          // dispatcher: stores OnRequest event handlers for each connection to avoid timing issues with dynamic registration
	establish  atomic.Value      // lazy-loaded callback for connection establishment to eliminate concurrent write contention on eventLoop
}

// NewNetpoll initializes and returns a new Netpoll listener, listening on an address.
func NewNetpoll(config Config) *Netpoll {
	return &Netpoll{
		id:      config.ID,
		address: config.Address,
		config:  config,
	}
}

// RegisterOnRequest registers a custom readable event handler for a connection.
func (l *Netpoll) RegisterOnRequest(c netpoll.Connection, handler func(context.Context, netpoll.Connection) error) {
	l.onRequests.Store(c, handler)
}

// UnregisterOnRequest unregisters the event handler for a connection, called on disconnect or cleanup.
func (l *Netpoll) UnregisterOnRequest(c netpoll.Connection) {
	l.onRequests.Delete(c)
}

// ID returns the id of the listener.
func (l *Netpoll) ID() string {
	return l.id
}

// Address returns the address of the listener.
func (l *Netpoll) Address() string {
	if l.listener != nil {
		return l.listener.Addr().String()
	}
	return l.address
}

// Protocol returns the address of the listener.
func (l *Netpoll) Protocol() string {
	return "tcp"
}

// Init initializes the listener.
func (l *Netpoll) Init(log *slog.Logger) error {
	l.log = log

	var err error
	l.listener, err = netpoll.CreateListener("tcp", l.address)
	if err != nil {
		return err
	}

	l.eventLoop, err = netpoll.NewEventLoop(
		func(ctx context.Context, connection netpoll.Connection) error {
			// router: load the connection's readable event callback to avoid swallowing the initial event
			if handler, ok := l.onRequests.Load(connection); ok {
				return handler.(func(context.Context, netpoll.Connection) error)(ctx, connection)
			}
			return nil
		},
		netpoll.WithOnConnect(func(ctx context.Context, connection netpoll.Connection) context.Context {
			if atomic.LoadUint32(&l.end) == 1 {
				_ = connection.Close()
				return ctx
			}

			// Trigger the establish callback which routes to EstablishConnection in server.go
			if est := l.establish.Load(); est != nil {
				establish := est.(EstablishFn)
				err := establish(l.id, connection)
				if err != nil {
					l.log.Error("failed to establish netpoll connection", "error", err)
				}
			}
			return ctx
		}),
		netpoll.WithIdleTimeout(0),
	)
	return err
}

// Serve starts waiting for new TCP connections using netpoll reactor.
func (l *Netpoll) Serve(establish EstablishFn) {
	l.establish.Store(establish)

	err := l.eventLoop.Serve(l.listener)
	if err != nil {
		l.log.Error("netpoll event loop serve finished", "error", err)
	}
}

// Close closes the listener and any client connections.
func (l *Netpoll) Close(closeClients CloseFn) {
	l.Lock()
	defer l.Unlock()

	if atomic.CompareAndSwapUint32(&l.end, 0, 1) {
		closeClients(l.id)
	}

	if l.eventLoop != nil {
		_ = l.eventLoop.Shutdown(context.Background())
	}

	if l.listener != nil {
		_ = l.listener.Close()
	}
}
