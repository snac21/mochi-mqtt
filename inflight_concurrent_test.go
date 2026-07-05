// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 mochi-mqtt

package mqtt

import (
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mochi-mqtt/server/v2/packets"
	"github.com/stretchr/testify/require"
)

// TestInflightQuotaConcurrentRaceCondition 测试配额在高并发下不会越界
// 这是对 commit 06d5b96 修复的 TOCTOU 竞态条件的回归测试
func TestInflightQuotaConcurrentRaceCondition(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	// 测试多次以提高发现竞态的概率
	for attempt := 0; attempt < 50; attempt++ {
		i := NewInflights()
		initialQuota := int32(100)
		i.ResetReceiveQuota(initialQuota)
		i.ResetSendQuota(initialQuota)

		var wg sync.WaitGroup
		goroutines := 200
		operationsPerGoroutine := 50

		// 并发减少 receive quota
		for j := 0; j < goroutines; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < operationsPerGoroutine; k++ {
					i.DecreaseReceiveQuota()
				}
			}()
		}

		// 并发减少 send quota
		for j := 0; j < goroutines; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < operationsPerGoroutine; k++ {
					i.DecreaseSendQuota()
				}
			}()
		}

		wg.Wait()

		// 验证配额不会变成负数（修复前会越界）
		receiveQuota := i.ReceiveQuota()
		sendQuota := i.SendQuota()

		require.GreaterOrEqual(t, receiveQuota, int32(0),
			"receive quota 不应该变成负数，attempt %d", attempt)
		require.GreaterOrEqual(t, sendQuota, int32(0),
			"send quota 不应该变成负数，attempt %d", attempt)

		// 验证配额正确停在 0
		require.Equal(t, int32(0), receiveQuota,
			"receive quota 应该正好是 0，attempt %d", attempt)
		require.Equal(t, int32(0), sendQuota,
			"send quota 应该正好是 0，attempt %d", attempt)
	}
}

// TestInflightQuotaMixedOperations 测试混合增减操作的并发安全性
func TestInflightQuotaMixedOperations(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	for attempt := 0; attempt < 30; attempt++ {
		i := NewInflights()
		i.ResetReceiveQuota(50)
		i.ResetSendQuota(50)

		var wg sync.WaitGroup
		done := make(chan struct{})

		// 并发减少
		for j := 0; j < 50; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
						i.DecreaseReceiveQuota()
						i.DecreaseSendQuota()
					}
				}
			}()
		}

		// 并发增加
		for j := 0; j < 50; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-done:
						return
					default:
						i.IncreaseReceiveQuota()
						i.IncreaseSendQuota()
					}
				}
			}()
		}

		// 运行一段时间
		time.Sleep(100 * time.Millisecond)
		close(done)
		wg.Wait()

		// 验证配额在合法范围内
		receiveQuota := i.ReceiveQuota()
		sendQuota := i.SendQuota()
		maxReceive := i.MaximumReceiveQuota()
		maxSend := i.MaximumSendQuota()

		require.GreaterOrEqual(t, receiveQuota, int32(0), "receive quota >= 0")
		require.LessOrEqual(t, receiveQuota, maxReceive, "receive quota <= max")
		require.GreaterOrEqual(t, sendQuota, int32(0), "send quota >= 0")
		require.LessOrEqual(t, sendQuota, maxSend, "send quota <= max")
	}
}

// TestInflightQuotaCloneConcurrency 测试 Clone 操作的并发安全性
func TestInflightQuotaCloneConcurrency(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	i := NewInflights()
	i.ResetReceiveQuota(100)
	i.ResetSendQuota(100)
	i.Set(packets.Packet{PacketID: 1})
	i.Set(packets.Packet{PacketID: 2})

	var wg sync.WaitGroup
	done := make(chan struct{})

	// 并发修改配额
	for j := 0; j < 20; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					i.DecreaseReceiveQuota()
					i.DecreaseSendQuota()
					i.IncreaseReceiveQuota()
					i.IncreaseSendQuota()
				}
			}
		}()
	}

	// 并发 Clone
	clones := make([]*Inflight, 100)
	for j := 0; j < 100; j++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clones[idx] = i.Clone()
		}(j)
	}

	time.Sleep(50 * time.Millisecond)
	close(done)
	wg.Wait()

	// 验证所有 clone 都有有效的配额值
	for idx, clone := range clones {
		require.NotNil(t, clone, "clone %d should not be nil", idx)
		require.GreaterOrEqual(t, clone.ReceiveQuota(), int32(0), "clone %d receive quota", idx)
		require.GreaterOrEqual(t, clone.SendQuota(), int32(0), "clone %d send quota", idx)
		require.LessOrEqual(t, clone.ReceiveQuota(), clone.MaximumReceiveQuota(), "clone %d", idx)
		require.LessOrEqual(t, clone.SendQuota(), clone.MaximumSendQuota(), "clone %d", idx)
	}
}

// TestInflightQuotaBoundaryConditions 测试边界条件
func TestInflightQuotaBoundaryConditions(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	tests := []struct {
		name         string
		initialQuota int32
		operations   int
	}{
		{"quota=1, ops=1000", 1, 1000},
		{"quota=2, ops=1000", 2, 1000},
		{"quota=10, ops=1000", 10, 1000},
		{"quota=100, ops=10000", 100, 10000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for attempt := 0; attempt < 20; attempt++ {
				i := NewInflights()
				i.ResetReceiveQuota(tt.initialQuota)

				var wg sync.WaitGroup
				start := make(chan struct{})

				for j := 0; j < tt.operations; j++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						<-start
						i.DecreaseReceiveQuota()
					}()
				}

				close(start)
				wg.Wait()

				quota := i.ReceiveQuota()
				require.Equal(t, int32(0), quota,
					"attempt %d: quota should be exactly 0", attempt)
			}
		})
	}
}

// TestInflightQuotaStressTest 压力测试：模拟真实 MQTT 场景
func TestInflightQuotaStressTest(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过压力测试")
	}

	runtime.GOMAXPROCS(runtime.NumCPU())

	i := NewInflights()
	i.ResetReceiveQuota(1000)
	i.ResetSendQuota(1000)

	var wg sync.WaitGroup
	done := make(chan struct{})

	var publishCount, ackCount int64

	// 模拟发布消息（减少 send quota）
	for j := 0; j < 100; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					i.DecreaseSendQuota()
					atomic.AddInt64(&publishCount, 1)
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// 模拟接收 ACK（增加 send quota）
	for j := 0; j < 100; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					i.IncreaseSendQuota()
					atomic.AddInt64(&ackCount, 1)
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// 模拟接收消息（减少 receive quota）
	for j := 0; j < 100; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					i.DecreaseReceiveQuota()
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// 模拟发送 ACK（增加 receive quota）
	for j := 0; j < 100; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-done:
					return
				default:
					i.IncreaseReceiveQuota()
					time.Sleep(time.Microsecond)
				}
			}
		}()
	}

	// 运行 1 秒
	time.Sleep(1 * time.Second)
	close(done)
	wg.Wait()

	// 验证配额在合法范围内
	receiveQuota := i.ReceiveQuota()
	sendQuota := i.SendQuota()

	require.GreaterOrEqual(t, receiveQuota, int32(0), "receive quota should be >= 0")
	require.LessOrEqual(t, receiveQuota, i.MaximumReceiveQuota(), "receive quota should be <= max")
	require.GreaterOrEqual(t, sendQuota, int32(0), "send quota should be >= 0")
	require.LessOrEqual(t, sendQuota, i.MaximumSendQuota(), "send quota should be <= max")

	t.Logf("压力测试完成: publish=%d, ack=%d, final_send_quota=%d, final_receive_quota=%d",
		publishCount, ackCount, sendQuota, receiveQuota)
}

// TestInflightQuotaNoNegativeOverflow 确保配额永远不会溢出到负数
func TestInflightQuotaNoNegativeOverflow(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	for attempt := 0; attempt < 100; attempt++ {
		i := NewInflights()
		i.ResetReceiveQuota(1)
		i.ResetSendQuota(1)

		var wg sync.WaitGroup
		start := make(chan struct{})

		// 大量 goroutine 同时尝试减少配额
		for j := 0; j < 1000; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				i.DecreaseReceiveQuota()
				i.DecreaseSendQuota()
			}()
		}

		close(start)
		wg.Wait()

		// 关键断言：配额必须正好是 0，不能是负数
		receiveQuota := i.ReceiveQuota()
		sendQuota := i.SendQuota()

		require.Equal(t, int32(0), receiveQuota,
			"attempt %d: receive quota 必须是 0，不能越界", attempt)
		require.Equal(t, int32(0), sendQuota,
			"attempt %d: send quota 必须是 0，不能越界", attempt)
	}
}

// TestInflightQuotaNoPositiveOverflow 确保配额不会超过最大值
func TestInflightQuotaNoPositiveOverflow(t *testing.T) {
	runtime.GOMAXPROCS(runtime.NumCPU())

	for attempt := 0; attempt < 100; attempt++ {
		i := NewInflights()
		maxQuota := int32(10)
		i.ResetReceiveQuota(maxQuota)
		i.ResetSendQuota(maxQuota)

		var wg sync.WaitGroup
		start := make(chan struct{})

		// 大量 goroutine 同时尝试增加配额
		for j := 0; j < 1000; j++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				i.IncreaseReceiveQuota()
				i.IncreaseSendQuota()
			}()
		}

		close(start)
		wg.Wait()

		// 关键断言：配额不能超过最大值
		receiveQuota := i.ReceiveQuota()
		sendQuota := i.SendQuota()

		require.Equal(t, maxQuota, receiveQuota,
			"attempt %d: receive quota 不能超过最大值", attempt)
		require.Equal(t, maxQuota, sendQuota,
			"attempt %d: send quota 不能超过最大值", attempt)
	}
}

// TestInflightNextImmediateNoDeadlock 测试 NextImmediate 不会因为嵌套锁而死锁
// 这是对 commit 8278a78 类似问题的预防性测试
func TestInflightNextImmediateNoDeadlock(t *testing.T) {
	i := NewInflights()
	i.Set(packets.Packet{PacketID: 1, Expiry: time.Now().Unix() + 100})
	i.Set(packets.Packet{PacketID: 2, Expiry: -1})

	done := make(chan bool)
	timeout := time.After(5 * time.Second)

	var wg sync.WaitGroup

	// 并发调用 NextImmediate
	for j := 0; j < 50; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				_, _ = i.NextImmediate()
			}
		}()
	}

	// 并发修改 inflight
	for j := 0; j < 50; j++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for k := 0; k < 100; k++ {
				i.Set(packets.Packet{PacketID: uint16(id*100 + k)})
				i.Delete(uint16(id*100 + k))
			}
		}(j)
	}

	go func() {
		wg.Wait()
		done <- true
	}()

	select {
	case <-done:
		// 测试通过
	case <-timeout:
		t.Fatal("NextImmediate 测试超时，可能存在死锁")
	}
}
