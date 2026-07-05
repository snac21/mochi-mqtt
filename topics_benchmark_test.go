// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt, mochi-co

package mqtt

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
)

// BenchmarkSingleLockTrie tests single lock trie performance under concurrent reads/writes
func BenchmarkSingleLockTrie(b *testing.B) {
	idx := NewTopicsIndexShard()
	benchmarkTrie(b, idx)
}

// BenchmarkShardedLockTrie tests 128-slot sharded lock trie performance under concurrent reads/writes
func BenchmarkShardedLockTrie(b *testing.B) {
	idx := NewTopicsIndex()
	benchmarkTrie(b, idx)
}

type trieInterface interface {
	Subscribe(client string, subscription packets.Subscription) bool
	Subscribers(topic string) *Subscribers
}

func benchmarkTrie(b *testing.B, idx trieInterface) {
	const numClients = 1000
	const numTopics = 100
	for i := 0; i < numClients; i++ {
		client := fmt.Sprintf("client_%d", i)
		// Use topic_X as the first level topic to ensure proper sharding hash dispersion
		topic := fmt.Sprintf("topic_%d", i%numTopics)
		idx.Subscribe(client, packets.Subscription{
			Filter: topic,
			Qos:    1,
		})
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			op := r.Intn(10)
			if op == 0 {
				client := fmt.Sprintf("client_dynamic_%d", r.Intn(numClients))
				topic := fmt.Sprintf("topic_%d", r.Intn(numTopics))
				idx.Subscribe(client, packets.Subscription{
					Filter: topic,
					Qos:    1,
				})
			} else {
				topic := fmt.Sprintf("topic_%d", r.Intn(numTopics))
				_ = idx.Subscribers(topic)
			}
		}
	})
}
