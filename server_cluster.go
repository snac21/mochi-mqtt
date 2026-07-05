// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package mqtt

import (
	"errors"
	"sync/atomic"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
)

var (
	ErrClientNotFound                 = errors.New("client not found")
	ErrClusterDispatchRequiresPublish = errors.New("cluster dispatch requires publish packet")
	ErrSessionNotFound                = errors.New("session not found")
)

type SessionSnapshot struct {
	ClientID              string
	Inflight              []packets.Packet
	Subscriptions         []packets.Subscription
	NextPacketID          uint32
	ProtocolVersion       byte
	Clean                 bool
	SessionExpiryInterval uint32
}

// DispatchClusterPublish delivers a publish packet to local subscribers without
// re-entering the normal inbound client processing path.
func (s *Server) DispatchClusterPublish(pk packets.Packet) error {
	if pk.FixedHeader.Type != packets.Publish {
		return ErrClusterDispatchRequiresPublish
	}

	s.publishToSubscribers(pk)
	return nil
}

// DeliverToClientID sends a publish packet directly to a connected local client.
// This bypasses subscription matching and is intended to be used by future cluster
// transports for point-to-point node forwarding.
func (s *Server) DeliverToClientID(clientID string, pk packets.Packet) error {
	if pk.FixedHeader.Type != packets.Publish {
		return ErrClusterDispatchRequiresPublish
	}

	cl, ok := s.Clients.Get(clientID)
	if !ok {
		return ErrClientNotFound
	}

	if pk.Created == 0 {
		pk.Created = time.Now().Unix()
	}

	if pk.Expiry == 0 {
		if expiry := minimum(s.Options.Capabilities.MaximumMessageExpiryInterval,
			int64(pk.Properties.MessageExpiryInterval)); expiry > 0 {
			pk.Expiry = pk.Created + expiry
		}
	}

	_, err := s.enqueuePublishToClient(cl, pk, pk)
	return err
}

// DeliverToClientWithSubscription sends a publish packet to a connected local
// client using subscription options. It is intended for cluster-owned delivery
// paths that need the same QoS, retain, identifier, ACL, and queueing semantics
// as normal subscriber delivery.
func (s *Server) DeliverToClientWithSubscription(clientID string, sub packets.Subscription, pk packets.Packet) error {
	if pk.FixedHeader.Type != packets.Publish {
		return ErrClusterDispatchRequiresPublish
	}

	cl, ok := s.Clients.Get(clientID)
	if !ok {
		return ErrClientNotFound
	}

	_, err := s.publishToClient(cl, sub, pk)
	return err
}

func (s *Server) RetainedMessages(filter string) []packets.Packet {
	return s.Topics.Messages(filter)
}

func (s *Server) TakeoverSession(clientID string) (*SessionSnapshot, error) {
	existing, ok := s.Clients.Get(clientID)
	if !ok {
		return nil, ErrSessionNotFound
	}

	snapshot := &SessionSnapshot{
		ClientID:              existing.ID,
		Inflight:              existing.State.Inflight.GetAll(false),
		NextPacketID:          existing.State.packetID,
		ProtocolVersion:       existing.Properties.ProtocolVersion,
		Clean:                 existing.Properties.Clean,
		SessionExpiryInterval: existing.Properties.Props.SessionExpiryInterval,
	}
	for _, sub := range existing.State.Subscriptions.GetAll() {
		snapshot.Subscriptions = append(snapshot.Subscriptions, sub)
	}

	_ = s.DisconnectClient(existing, packets.ErrSessionTakenOver)
	existing.State.isTakenOver.Store(true)
	s.UnsubscribeClient(existing)
	existing.ClearInflights()

	return snapshot, nil
}

func (s *Server) ImportSession(cl *Client, snapshot *SessionSnapshot) error {
	if cl == nil || snapshot == nil {
		return nil
	}

	if len(snapshot.Inflight) > 0 {
		inflight := NewInflights()
		for _, pk := range snapshot.Inflight {
			inflight.Set(pk)
		}
		cl.State.Inflight = inflight
		if cl.State.Inflight.MaximumReceiveQuota() == 0 && cl.ops.options.Capabilities.ReceiveMaximum != 0 {
			cl.State.Inflight.ResetReceiveQuota(int32(cl.ops.options.Capabilities.ReceiveMaximum))
			cl.State.Inflight.ResetSendQuota(int32(cl.Properties.Props.ReceiveMaximum))
		}
	}

	for _, sub := range snapshot.Subscriptions {
		existed := !s.Topics.Subscribe(cl.ID, sub)
		if !existed {
			atomic.AddInt64(&s.Info.Subscriptions, 1)
		}
		cl.State.Subscriptions.Add(sub.Filter, sub)
	}

	cl.State.packetID = snapshot.NextPacketID
	return nil
}
