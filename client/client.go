// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/mochi-mqtt/server/v2/transport"
)

const (
	defaultKeepalive             uint16 = 10
	defaultClientProtocolVersion byte   = 4
	minimumKeepalive             uint16 = 5
)

var (
	ErrMinimumKeepalive = errors.New("client keepalive is below minimum recommended value and may exhibit connection instability")
)

// Callbacks defines the statistical and hook actions required by Server, decoupling client package.
type Callbacks interface {
	OnPacketRead(cl Client, pk packets.Packet) (packets.Packet, error)
	OnPacketEncode(cl Client, pk packets.Packet) packets.Packet
	OnPacketSent(cl Client, pk packets.Packet, b []byte)
	OnQosDropped(cl Client, pk packets.Packet)
	OnQosComplete(cl Client, pk packets.Packet)
	AddBytesReceived(n int64)
	AddPacketsReceived(n int64)
	AddMessagesReceived(n int64)
	AddBytesSent(n int64)
	AddPacketsSent(n int64)
	AddMessagesSent(n int64)
	AddInflight(n int64)
}

// Ops contains configuration and event handlers passed from the Server.
type Ops struct {
	TopicAliasMaximum          uint16
	MaximumClientWritesPending int32
	ClientNetReadBufferSize    int
	ClientNetWriteBufferSize   int
	MaximumPacketSize          uint32
	MaximumPacketID            uint32
	MaximumInflight            uint16
	Callbacks                  Callbacks
	Log                        *slog.Logger
}

// Client defines the session interface of a connected MQTT client.
type Client interface {
	GetID() string
	GetConnection() *ClientConnection
	GetProperties() *ClientProperties
	GetState() *ClientState
	Read(packetHandler func(Client, packets.Packet) error) error
	WritePacket(pk packets.Packet) error
	Stop(err error)
	Closed() bool
	RefreshDeadline(keepalive uint16)
	ClearInflights()
	StopCause() error
	StopTime() int64
}

// Clients contains a map of the clients known by the broker.
type Clients struct {
	internal map[string]Client
	sync.RWMutex
}

// NewClients returns an instance of Clients.
func NewClients() *Clients {
	return &Clients{
		internal: make(map[string]Client),
	}
}

// Add adds a new client.
func (cl *Clients) Add(val Client) {
	cl.Lock()
	defer cl.Unlock()
	cl.internal[val.GetID()] = val
}

// GetAll returns all clients.
func (cl *Clients) GetAll() map[string]Client {
	cl.RLock()
	defer cl.RUnlock()
	m := map[string]Client{}
	for k, v := range cl.internal {
		m[k] = v
	}
	return m
}

// Get returns a client by ID.
func (cl *Clients) Get(id string) (Client, bool) {
	cl.RLock()
	defer cl.RUnlock()
	val, ok := cl.internal[id]
	return val, ok
}

// Len returns the length of clients map.
func (cl *Clients) Len() int {
	cl.RLock()
	defer cl.RUnlock()
	return len(cl.internal)
}

// Delete removes a client by ID.
func (cl *Clients) Delete(id string) {
	cl.Lock()
	defer cl.Unlock()
	delete(cl.internal, id)
}

// GetByListener returns clients matching a listener ID.
func (cl *Clients) GetByListener(id string) []Client {
	cl.RLock()
	defer cl.RUnlock()
	clients := make([]Client, 0, len(cl.internal))
	for _, client := range cl.internal {
		if client.GetConnection().Listener == id && !client.Closed() {
			clients = append(clients, client)
		}
	}
	return clients
}

// ClientConnection contains the connection transport and metadata.
type ClientConnection struct {
	Transport transport.Transport
	Remote    string
	Listener  string
	Inline    bool
}

// ClientProperties contains session properties.
type ClientProperties struct {
	Props           packets.Properties
	Will            Will
	Username        []byte
	ProtocolVersion byte
	Clean           bool
}

// Will contains Will/LWT configuration.
type Will struct {
	Payload           []byte
	User              []packets.UserProperty
	TopicName         string
	WillDelayInterval uint32
	Qos               byte
	Retain            bool
	Flag              uint32
}

// ClientState holds the operational state.
type ClientState struct {
	Inflight            *Inflight
	Subscriptions       *Subscriptions
	TopicAliases        TopicAliases
	Open                context.Context
	CancelOpen          context.CancelFunc
	stopCause           atomic.Value
	Disconnected        int64
	Outbound            chan *packets.Packet
	endOnce             sync.Once
	IsTakenOver         atomic.Bool
	PacketID            uint32
	OutboundQty         int32
	Keepalive           uint16
	ServerKeepalive     bool
	isStopping          uint32
	statConnIncrement   uint32
}

// BaseClient implements the Client interface.
type BaseClient struct {
	Properties   ClientProperties
	State        ClientState
	Net          ClientConnection
	ID           string
	Ops          *Ops
	sync.RWMutex
}

func (cl *BaseClient) GetID() string {
	return cl.ID
}

func (cl *BaseClient) GetConnection() *ClientConnection {
	return &cl.Net
}

func (cl *BaseClient) GetProperties() *ClientProperties {
	return &cl.Properties
}

func (cl *BaseClient) GetState() *ClientState {
	return &cl.State
}

func (cl *BaseClient) Closed() bool {
	return cl.State.Open == nil || cl.State.Open.Err() != nil
}

func NewBaseClient(o *Ops) *BaseClient {
	ctx, cancel := context.WithCancel(context.Background())
	return &BaseClient{
		State: ClientState{
			Inflight:      NewInflights(),
			Subscriptions: NewSubscriptions(),
			TopicAliases:  NewTopicAliases(o.TopicAliasMaximum),
			Open:          ctx,
			CancelOpen:    cancel,
			Keepalive:     defaultKeepalive,
			Outbound:      make(chan *packets.Packet, o.MaximumClientWritesPending),
		},
		Properties: ClientProperties{
			ProtocolVersion: defaultClientProtocolVersion,
		},
		Ops: o,
	}
}

func (cl *BaseClient) WriteLoop() {
	for {
		select {
		case pk := <-cl.State.Outbound:
			if err := cl.WritePacket(*pk); err != nil {
				cl.Ops.Log.Debug("failed publishing packet", "error", err, "client", cl.ID, "packet", pk)
			}
			atomic.AddInt32(&cl.State.OutboundQty, -1)
		case <-cl.State.Open.Done():
			return
		}
	}
}

func (cl *BaseClient) ParseConnect(lid string, pk packets.Packet) {
	cl.Net.Listener = lid
	cl.Properties.ProtocolVersion = pk.ProtocolVersion
	cl.Properties.Username = pk.Connect.Username
	cl.Properties.Clean = pk.Connect.Clean
	cl.Properties.Props = pk.Properties.Copy(false)

	if cl.Properties.Props.ReceiveMaximum > cl.Ops.MaximumInflight {
		cl.Properties.Props.ReceiveMaximum = cl.Ops.MaximumInflight
	}

	if pk.Connect.Keepalive <= minimumKeepalive {
		cl.Ops.Log.Warn(
			ErrMinimumKeepalive.Error(),
			"client", cl.ID,
			"keepalive", pk.Connect.Keepalive,
			"recommended", minimumKeepalive,
		)
	}

	cl.State.Keepalive = pk.Connect.Keepalive
	cl.State.Inflight.ResetReceiveQuota(int32(cl.Ops.MaximumPacketSize)) // maximum is mapped to receive max config
	cl.State.Inflight.ResetSendQuota(int32(cl.Properties.Props.ReceiveMaximum))
	cl.State.TopicAliases.Outbound = NewOutboundTopicAliases(cl.Properties.Props.TopicAliasMaximum)

	if pk.Connect.ClientIdentifier != "" {
		cl.ID = pk.Connect.ClientIdentifier
	}

	if pk.Connect.WillFlag {
		cl.Properties.Will = Will{
			Qos:               pk.Connect.WillQos,
			Retain:            pk.Connect.WillRetain,
			Payload:           pk.Connect.WillPayload,
			TopicName:         pk.Connect.WillTopic,
			WillDelayInterval: pk.Connect.WillProperties.WillDelayInterval,
			User:              pk.Connect.WillProperties.User,
		}
		if pk.Properties.SessionExpiryIntervalFlag &&
			pk.Properties.SessionExpiryInterval < pk.Connect.WillProperties.WillDelayInterval {
			cl.Properties.Will.WillDelayInterval = pk.Properties.SessionExpiryInterval
		}
		cl.Properties.Will.Flag = 1
	}
}

func (cl *BaseClient) RefreshDeadline(keepalive uint16) {
	var expiry time.Time
	if keepalive > 0 {
		expiry = time.Now().Add(time.Duration(keepalive+(keepalive/2)) * time.Second)
	}
	if cl.Net.Transport != nil {
		_ = cl.Net.Transport.SetDeadline(expiry)
	}
}

func (cl *BaseClient) NextPacketID() (i uint32, err error) {
	cl.Lock()
	defer cl.Unlock()

	i = atomic.LoadUint32(&cl.State.PacketID)
	started := i
	overflowed := false
	for {
		if overflowed && i == started {
			return 0, packets.ErrQuotaExceeded
		}

		if i >= cl.Ops.MaximumPacketID {
			overflowed = true
			i = 0
			continue
		}

		i++

		if _, ok := cl.State.Inflight.Get(uint16(i)); !ok {
			atomic.StoreUint32(&cl.State.PacketID, i)
			return i, nil
		}
	}
}

func (cl *BaseClient) ResendInflightMessages(force bool) error {
	cl.RLock()
	messages := cl.State.Inflight.GetAll(false)
	cl.RUnlock()

	if len(messages) == 0 {
		return nil
	}

	for _, pk := range messages {
		if pk.FixedHeader.Type == packets.Publish {
			pk.FixedHeader.Dup = true
		}
		if err := cl.WritePacket(pk); err != nil {
			return err
		}

		if pk.FixedHeader.Type == packets.Puback || pk.FixedHeader.Type == packets.Pubcomp {
			if ok := cl.State.Inflight.Delete(pk.PacketID); ok {
				if cl.Ops.Callbacks != nil {
					cl.Ops.Callbacks.OnQosComplete(cl, pk)
				}
			}
		}
	}
	return nil
}

func (cl *BaseClient) ClearExpiredInflights(now, maximumExpiry int64) []uint16 {
	cl.Lock()
	defer cl.Unlock()

	deleted := []uint16{}
	for id, pk := range cl.State.Inflight.internal {
		expired := pk.ProtocolVersion == 5 && pk.Expiry > 0 && pk.Expiry < now
		enforced := maximumExpiry > 0 && now-pk.Created > maximumExpiry

		if expired || enforced {
			cl.State.Inflight.receiveQuotaState.increase()
			delete(cl.State.Inflight.internal, id)
			if cl.Ops.Callbacks != nil {
				cl.Ops.Callbacks.AddInflight(-1)
			}
			deleted = append(deleted, id)
		}
	}
	return deleted
}

func (cl *BaseClient) ClearInflights() {
	for _, tk := range cl.State.Inflight.GetAll(false) {
		if ok := cl.State.Inflight.Delete(tk.PacketID); ok {
			if cl.Ops.Callbacks != nil {
				cl.Ops.Callbacks.OnQosDropped(cl, tk)
				cl.Ops.Callbacks.AddInflight(-1)
			}
		}
	}
}

func (cl *BaseClient) Read(packetHandler func(Client, packets.Packet) error) error {
	var err error
	var fh packets.FixedHeader
	for {
		if cl.Closed() {
			return nil
		}
		err = cl.ReadFixedHeader(&fh)
		if err != nil {
			cl.Stop(err)
			return err
		}

		pk, err := cl.ReadPacket(&fh)
		if err != nil {
			cl.Stop(err)
			return err
		}

		cl.RefreshDeadline(cl.State.Keepalive)

		err = packetHandler(cl, pk)
		if err != nil {
			cl.Stop(err)
			return err
		}
	}
}

func (cl *BaseClient) Stop(err error) {
	if !atomic.CompareAndSwapUint32(&cl.State.isStopping, 0, 1) {
		return
	}

	cl.State.endOnce.Do(func() {
		if err != nil {
			cl.State.stopCause.Store(err)
		}

		if cl.State.CancelOpen != nil {
			cl.State.CancelOpen()
		}

		atomic.StoreInt64(&cl.State.Disconnected, time.Now().Unix())
	})

	if cl.Net.Transport != nil {
		_ = cl.Net.Transport.Close()
	}
}

func (cl *BaseClient) StopCause() error {
	if cl.State.stopCause.Load() == nil {
		return nil
	}
	return cl.State.stopCause.Load().(error)
}

func (cl *BaseClient) StopTime() int64 {
	return atomic.LoadInt64(&cl.State.Disconnected)
}

func (cl *BaseClient) IsTakenOver() bool {
	return cl.State.IsTakenOver.Load()
}

func (cl *BaseClient) SetTakenOver(val bool) {
	cl.State.IsTakenOver.Store(val)
}

func (cl *BaseClient) ReadFixedHeader(fh *packets.FixedHeader) error {
	if cl.Net.Transport == nil {
		return transport.ErrConnectionClosed
	}
	decodedFh, bytesRead, err := cl.Net.Transport.ReadFixedHeader(cl.Ops.MaximumPacketSize)
	if err != nil {
		return err
	}
	*fh = decodedFh
	if cl.Ops.Callbacks != nil {
		cl.Ops.Callbacks.AddBytesReceived(int64(bytesRead))
	}
	return nil
}

func (cl *BaseClient) ReadPacket(fh *packets.FixedHeader) (pk packets.Packet, err error) {
	if cl.Net.Transport == nil {
		return pk, transport.ErrConnectionClosed
	}
	decodedPk, bytesRead, err := cl.Net.Transport.ReadPacket(fh, cl.Properties.ProtocolVersion)
	if err != nil {
		return pk, err
	}
	pk = decodedPk
	if cl.Ops.Callbacks != nil {
		cl.Ops.Callbacks.AddBytesReceived(int64(bytesRead))
		cl.Ops.Callbacks.AddPacketsReceived(1)
		if pk.FixedHeader.Type == packets.Publish {
			cl.Ops.Callbacks.AddMessagesReceived(1)
		}
	}

	if cl.Ops.Callbacks != nil {
		pk, err = cl.Ops.Callbacks.OnPacketRead(cl, pk)
	}
	return pk, err
}

func (cl *BaseClient) WritePacket(pk packets.Packet) error {
	if cl.Closed() {
		return transport.ErrConnectionClosed
	}
	if cl.Net.Transport == nil {
		return nil
	}

	if pk.Expiry > 0 {
		expiry := pk.Expiry - time.Now().Unix()
		if expiry < 1 {
			expiry = 1
		}
		pk.Properties.MessageExpiryInterval = uint32(expiry)
	}

	pk.ProtocolVersion = cl.Properties.ProtocolVersion
	if pk.Mods.MaxSize == 0 {
		pk.Mods.MaxSize = cl.Properties.Props.MaximumPacketSize
	}

	if cl.Properties.Props.RequestProblemInfoFlag && cl.Properties.Props.RequestProblemInfo == 0x0 {
		pk.Mods.DisallowProblemInfo = true
	}

	if pk.FixedHeader.Type != packets.Connack || cl.Properties.Props.RequestResponseInfo == 0x1 {
		pk.Mods.AllowResponseInfo = true
	}

	if cl.Ops.Callbacks != nil {
		pk = cl.Ops.Callbacks.OnPacketEncode(cl, pk)
	}

	var err error
	buf := new(bytes.Buffer)
	switch pk.FixedHeader.Type {
	case packets.Connect:
		err = pk.ConnectEncode(buf)
	case packets.Connack:
		err = pk.ConnackEncode(buf)
	case packets.Publish:
		err = pk.PublishEncode(buf)
	case packets.Puback:
		err = pk.PubackEncode(buf)
	case packets.Pubrec:
		err = pk.PubrecEncode(buf)
	case packets.Pubrel:
		err = pk.PubrelEncode(buf)
	case packets.Pubcomp:
		err = pk.PubcompEncode(buf)
	case packets.Subscribe:
		err = pk.SubscribeEncode(buf)
	case packets.Suback:
		err = pk.SubackEncode(buf)
	case packets.Unsubscribe:
		err = pk.UnsubscribeEncode(buf)
	case packets.Unsuback:
		err = pk.UnsubackEncode(buf)
	case packets.Pingreq:
		err = pk.PingreqEncode(buf)
	case packets.Pingresp:
		err = pk.PingrespEncode(buf)
	case packets.Disconnect:
		err = pk.DisconnectEncode(buf)
	case packets.Auth:
		err = pk.AuthEncode(buf)
	default:
		err = fmt.Errorf("%w: %v", packets.ErrNoValidPacketAvailable, pk.FixedHeader.Type)
	}
	if err != nil {
		return err
	}

	if pk.Mods.MaxSize > 0 && uint32(buf.Len()) > pk.Mods.MaxSize {
		return packets.ErrPacketTooLarge
	}

	n, err := func() (int64, error) {
		cl.Lock()
		defer cl.Unlock()
		if cl.Net.Transport != nil {
			return cl.Net.Transport.Write(buf, len(cl.State.Outbound), cl.Ops.ClientNetWriteBufferSize)
		}
		return 0, nil
	}()
	if err != nil {
		return err
	}

	if cl.Ops.Callbacks != nil {
		cl.Ops.Callbacks.AddBytesSent(n)
		cl.Ops.Callbacks.AddPacketsSent(1)
		if pk.FixedHeader.Type == packets.Publish {
			cl.Ops.Callbacks.AddMessagesSent(1)
		}
		cl.Ops.Callbacks.OnPacketSent(cl, pk, buf.Bytes())
	}

	return err
}
