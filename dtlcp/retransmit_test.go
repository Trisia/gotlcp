// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"testing"
	"time"
)

// TestRetransmitTimerInit 测试初始超时值为 1 秒。
func TestRetransmitTimerInit(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)
	if tmr.current != time.Second {
		t.Fatalf("初始超时值应为 1s，实际 %v", tmr.current)
	}
	if tmr.initial != time.Second {
		t.Fatalf("initial 应为 1s，实际 %v", tmr.initial)
	}
}

// TestRetransmitTimerBackoff 测试指数退避：1s -> 2s -> 4s。
func TestRetransmitTimerBackoff(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 第1次退避：1s -> 2s
	tmr.backoff()
	if tmr.current != 2*time.Second {
		t.Fatalf("第1次退避后应为 2s，实际 %v", tmr.current)
	}

	// 第2次退避：2s -> 4s
	tmr.backoff()
	if tmr.current != 4*time.Second {
		t.Fatalf("第2次退避后应为 4s，实际 %v", tmr.current)
	}
}

// TestRetransmitTimerMax 测试背靠背退避不超过 64s。
func TestRetransmitTimerMax(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 退避 10 次：1,2,4,8,16,32,64,64,64,64
	for i := 0; i < 10; i++ {
		tmr.backoff()
	}

	if tmr.current > 64*time.Second {
		t.Fatalf("退避多次后不应超过 64s，实际 %v", tmr.current)
	}
	if tmr.current != 64*time.Second {
		t.Fatalf("退避 10 次后应为 64s，实际 %v", tmr.current)
	}
}

// TestRetransmitTimerReset 测试 reset 后回到初始值。
func TestRetransmitTimerReset(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 先退避
	tmr.backoff()
	tmr.backoff()
	if tmr.current != 4*time.Second {
		t.Fatalf("退避后应为 4s，实际 %v", tmr.current)
	}

	// 重置
	tmr.reset()
	if tmr.current != time.Second {
		t.Fatalf("重置后应为 1s，实际 %v", tmr.current)
	}
}

// TestRetransmitTimerFired 测试定时器触发后 fired() 返回 true。
func TestRetransmitTimerFired(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 启动定时器
	tmr.start()
	if tmr.handle == nil {
		t.Fatal("start 后 handle 不应为 nil")
	}

	// 在没有触发前 fired() 应为 false
	if tmr.fired() {
		t.Fatal("未触发的定时器 fired() 应返回 false")
	}

	// 手动触发
	fireMockTimer(tmr.handle)

	if !tmr.fired() {
		t.Fatal("触发后的定时器 fired() 应返回 true")
	}
}

// TestRetransmitTimerNotFired 测试未触发的定时器 fired() 返回 false。
func TestRetransmitTimerNotFired(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	tmr.start()
	if tmr.fired() {
		t.Fatal("未触发的定时器 fired() 应返回 false")
	}
}

// TestRetransmitTimerStop 测试停止定时器后 handle 被清空。
func TestRetransmitTimerStop(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	tmr.start()
	if tmr.handle == nil {
		t.Fatal("start 后 handle 不应为 nil")
	}

	tmr.stop()
	if tmr.handle != nil {
		t.Fatal("stop 后 handle 应为 nil")
	}
}

// TestRetransmitTimerStartStopStart 测试定时器重启后正常工作。
func TestRetransmitTimerStartStopStart(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 启动-停止-启动
	tmr.start()
	tmr.stop()
	tmr.start()

	if tmr.handle == nil {
		t.Fatal("重启后 handle 不应为 nil")
	}

	// 触发并验证
	fireMockTimer(tmr.handle)
	if !tmr.fired() {
		t.Fatal("触发后 fired() 应返回 true")
	}
}

// TestRetransmitTimerBackoffAfterReset 测试 reset 后 backoff 从初始值开始。
func TestRetransmitTimerBackoffAfterReset(t *testing.T) {
	tmr := newRetransmitTimer(time.Second, 64*time.Second, newMockTimer)

	// 先退避到 4s
	tmr.backoff()
	tmr.backoff()
	if tmr.current != 4*time.Second {
		t.Fatalf("退避后应为 4s，实际 %v", tmr.current)
	}

	// 重置
	tmr.reset()
	// 再次退避，应从 1s -> 2s
	tmr.backoff()
	if tmr.current != 2*time.Second {
		t.Fatalf("重置后退避应为 2s，实际 %v", tmr.current)
	}
}
