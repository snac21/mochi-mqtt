// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2023 mochi-mqtt, mochi-co
// SPDX-FileContributor: mochi-co

package mqtt

import (
	"sort"
	"sync"

	"github.com/mochi-mqtt/server/v2/packets"
)

type quotaState struct {
	sync.Mutex
	value   int32
	maximum int32
}

func (q *quotaState) decrease() (int32, bool) {
	q.Lock()
	defer q.Unlock()
	if q.value <= 0 {
		return q.value, false
	}
	q.value--
	return q.value, true
}

func (q *quotaState) increase() (int32, bool) {
	q.Lock()
	defer q.Unlock()
	if q.value >= q.maximum {
		return q.value, false
	}
	q.value++
	return q.value, true
}

func (q *quotaState) reset(n int32) {
	q.set(n, n)
}

func (q *quotaState) set(value, maximum int32) {
	q.Lock()
	defer q.Unlock()
	q.value = value
	q.maximum = maximum
}

func (q *quotaState) current() int32 {
	q.Lock()
	defer q.Unlock()
	return q.value
}

func (q *quotaState) max() int32 {
	q.Lock()
	defer q.Unlock()
	return q.maximum
}

func (q *quotaState) snapshot() (int32, int32) {
	q.Lock()
	defer q.Unlock()
	return q.value, q.maximum
}

// Inflight is a map of InflightMessage keyed on packet id.
type Inflight struct {
	sync.RWMutex
	internal          map[uint16]packets.Packet // internal contains the inflight packets
	receiveQuotaState quotaState
	sendQuotaState    quotaState
}

// NewInflights returns a new instance of an Inflight packets map.
func NewInflights() *Inflight {
	return &Inflight{
		internal: map[uint16]packets.Packet{},
	}
}

// Set adds or updates an inflight packet by packet id.
func (i *Inflight) Set(m packets.Packet) bool {
	i.Lock()
	defer i.Unlock()

	_, ok := i.internal[m.PacketID]
	i.internal[m.PacketID] = m
	return !ok
}

// Get returns an inflight packet by packet id.
func (i *Inflight) Get(id uint16) (packets.Packet, bool) {
	i.RLock()
	defer i.RUnlock()

	if m, ok := i.internal[id]; ok {
		return m, true
	}

	return packets.Packet{}, false
}

// Len returns the size of the inflight messages map.
func (i *Inflight) Len() int {
	i.RLock()
	defer i.RUnlock()
	return len(i.internal)
}

// Clone returns a new instance of Inflight with the same message data.
// This is used when transferring inflights from a taken-over session.
func (i *Inflight) Clone() *Inflight {
	c := NewInflights()
	i.RLock()
	defer i.RUnlock()
	for k, v := range i.internal {
		c.internal[k] = v
	}
	recv, maxRecv := i.receiveQuotaState.snapshot()
	send, maxSend := i.sendQuotaState.snapshot()
	c.receiveQuotaState.set(recv, maxRecv)
	c.sendQuotaState.set(send, maxSend)
	return c
}

// GetAll returns all the inflight messages.
func (i *Inflight) GetAll(immediate bool) []packets.Packet {
	i.RLock()
	defer i.RUnlock()

	m := []packets.Packet{}
	for _, v := range i.internal {
		if !immediate || (immediate && v.Expiry < 0) {
			m = append(m, v)
		}
	}

	sort.Slice(m, func(i, j int) bool {
		return uint16(m[i].Created) < uint16(m[j].Created)
	})

	return m
}

// NextImmediate returns the next inflight packet which is indicated to be sent immediately.
// This typically occurs when the quota has been exhausted, and we need to wait until new quota
// is free to continue sending.
func (i *Inflight) NextImmediate() (packets.Packet, bool) {
	m := i.GetAll(true)
	if len(m) > 0 {
		return m[0], true
	}

	return packets.Packet{}, false
}

// Delete removes an in-flight message from the map. Returns true if the message existed.
func (i *Inflight) Delete(id uint16) bool {
	i.Lock()
	defer i.Unlock()

	_, ok := i.internal[id]
	delete(i.internal, id)

	return ok
}

// TakeRecieveQuota reduces the receive quota by 1.
func (i *Inflight) DecreaseReceiveQuota() {
	i.receiveQuotaState.decrease()
}

// TakeRecieveQuota increases the receive quota by 1.
func (i *Inflight) IncreaseReceiveQuota() {
	i.receiveQuotaState.increase()
}

// ResetReceiveQuota resets the receive quota to the maximum allowed value.
func (i *Inflight) ResetReceiveQuota(n int32) {
	i.receiveQuotaState.reset(n)
}

// ReceiveQuota returns the remaining receive quota.
func (i *Inflight) ReceiveQuota() int32 {
	return i.receiveQuotaState.current()
}

// MaximumReceiveQuota returns the maximum receive quota.
func (i *Inflight) MaximumReceiveQuota() int32 {
	return i.receiveQuotaState.max()
}

// DecreaseSendQuota reduces the send quota by 1.
func (i *Inflight) DecreaseSendQuota() {
	i.sendQuotaState.decrease()
}

// IncreaseSendQuota increases the send quota by 1.
func (i *Inflight) IncreaseSendQuota() {
	i.sendQuotaState.increase()
}

// ResetSendQuota resets the send quota to the maximum allowed value.
func (i *Inflight) ResetSendQuota(n int32) {
	i.sendQuotaState.reset(n)
}

// SendQuota returns the remaining send quota.
func (i *Inflight) SendQuota() int32 {
	return i.sendQuotaState.current()
}

// MaximumSendQuota returns the maximum send quota.
func (i *Inflight) MaximumSendQuota() int32 {
	return i.sendQuotaState.max()
}
