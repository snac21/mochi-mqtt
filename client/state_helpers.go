// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package client

import (
	"sync"
	"sync/atomic"

	"github.com/mochi-mqtt/server/v2/packets"
)

// TopicAliases contains inbound and outbound topic alias maps.
type TopicAliases struct {
	Inbound  *InboundTopicAliases
	Outbound *OutboundTopicAliases
}

// NewTopicAliases returns an instance of TopicAliases.
func NewTopicAliases(topicAliasMaximum uint16) TopicAliases {
	return TopicAliases{
		Inbound:  NewInboundTopicAliases(topicAliasMaximum),
		Outbound: NewOutboundTopicAliases(topicAliasMaximum),
	}
}

// InboundTopicAliases contains a map of topic aliases received from the client.
type InboundTopicAliases struct {
	Internal map[uint16]string
	sync.RWMutex
	Maximum uint16
}

// NewInboundTopicAliases returns a pointer to InboundTopicAliases.
func NewInboundTopicAliases(topicAliasMaximum uint16) *InboundTopicAliases {
	return &InboundTopicAliases{
		Maximum:  topicAliasMaximum,
		Internal: map[uint16]string{},
	}
}

// Set sets a new alias for a specific topic.
func (a *InboundTopicAliases) Set(id uint16, topic string) string {
	a.Lock()
	defer a.Unlock()

	if a.Maximum == 0 {
		return topic
	}

	if existing, ok := a.Internal[id]; ok && topic == "" {
		return existing
	}

	a.Internal[id] = topic
	return topic
}

// OutboundTopicAliases contains a map of topic aliases sent from the broker to the client.
type OutboundTopicAliases struct {
	Internal map[string]uint16
	sync.RWMutex
	Cursor  uint32
	Maximum uint16
}

// NewOutboundTopicAliases returns a pointer to OutboundTopicAliases.
func NewOutboundTopicAliases(topicAliasMaximum uint16) *OutboundTopicAliases {
	return &OutboundTopicAliases{
		Maximum:  topicAliasMaximum,
		Internal: map[string]uint16{},
	}
}

// Set sets a new topic alias for a topic and returns the alias value, and a boolean
// indicating if the alias already existed.
func (a *OutboundTopicAliases) Set(topic string) (uint16, bool) {
	a.Lock()
	defer a.Unlock()

	if a.Maximum == 0 {
		return 0, false
	}

	if i, ok := a.Internal[topic]; ok {
		return i, true
	}

	i := atomic.LoadUint32(&a.Cursor)
	if i+1 > uint32(a.Maximum) {
		return 0, false
	}

	a.Internal[topic] = uint16(i) + 1
	atomic.StoreUint32(&a.Cursor, i+1)
	return uint16(i) + 1, false
}

// Subscriptions is a map of subscriptions keyed on filter.
type Subscriptions struct {
	internal map[string]packets.Subscription
	sync.RWMutex
}

// NewSubscriptions returns a new instance of Subscriptions.
func NewSubscriptions() *Subscriptions {
	return &Subscriptions{
		internal: map[string]packets.Subscription{},
	}
}

// Add adds a new subscription.
func (s *Subscriptions) Add(id string, val packets.Subscription) {
	s.Lock()
	defer s.Unlock()
	s.internal[id] = val
}

// GetAll returns all subscriptions.
func (s *Subscriptions) GetAll() map[string]packets.Subscription {
	s.RLock()
	defer s.RUnlock()
	m := map[string]packets.Subscription{}
	for k, v := range s.internal {
		m[k] = v
	}
	return m
}

// Get returns a subscription by ID.
func (s *Subscriptions) Get(id string) (val packets.Subscription, ok bool) {
	s.RLock()
	defer s.RUnlock()
	val, ok = s.internal[id]
	return val, ok
}

// Len returns the number of subscriptions.
func (s *Subscriptions) Len() int {
	s.RLock()
	defer s.RUnlock()
	return len(s.internal)
}

// Delete removes a subscription by filter.
func (s *Subscriptions) Delete(id string) {
	s.Lock()
	defer s.Unlock()
	delete(s.internal, id)
}
