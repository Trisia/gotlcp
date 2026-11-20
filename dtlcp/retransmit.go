// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"sync"
	"time"
)

// RetransmitTimer DTLCP 重传定时器，支持指数退避策略。
// 初始超时 = Config.InitialRetransmitTimeout（默认 1s）。
// 每次超时后超时值翻倍，上限 = Config.MaxRetransmitTimeout（默认 64s）。
// 通过 Config.NewTimer 注入，便于测试 mock。
type RetransmitTimer struct {
	initial  time.Duration
	current  time.Duration
	max      time.Duration
	newTimer func(time.Duration) *TimerHandle

	// handleMu 保护 handle，定时器可能由握手 goroutine 更新、
	// 被测试或并发调用方读取。
	handleMu sync.Mutex
	handle   *TimerHandle
}

// newRetransmitTimer 创建重传定时器
func newRetransmitTimer(initial, max time.Duration, newTimer func(time.Duration) *TimerHandle) *RetransmitTimer {
	return &RetransmitTimer{
		initial:  initial,
		current:  initial,
		max:      max,
		newTimer: newTimer,
	}
}

// start 启动定时器（使用当前超时值）
func (t *RetransmitTimer) start() {
	handle := t.newTimer(t.current)
	t.handleMu.Lock()
	t.handle = handle
	t.handleMu.Unlock()
}

// backoff 指数退避：当前值翻倍，不超过 max，然后重启
func (t *RetransmitTimer) backoff() {
	t.current *= 2
	if t.current > t.max {
		t.current = t.max
	}
	t.start()
}

// reset 恢复到初始超时值并重启
func (t *RetransmitTimer) reset() {
	t.current = t.initial
	t.start()
}

// stop 停止定时器
func (t *RetransmitTimer) stop() {
	t.handleMu.Lock()
	handle := t.handle
	t.handle = nil
	t.handleMu.Unlock()
	if handle != nil {
		handle.Stop()
	}
}

// fired 检查定时器是否已触发（非阻塞）
func (t *RetransmitTimer) fired() bool {
	t.handleMu.Lock()
	handle := t.handle
	t.handleMu.Unlock()
	if handle == nil {
		return false
	}
	select {
	case <-handle.C:
		return true
	default:
		return false
	}
}

// currentHandle 返回当前定时器句柄，无定时器时返回 nil。
func (t *RetransmitTimer) currentHandle() *TimerHandle {
	t.handleMu.Lock()
	defer t.handleMu.Unlock()
	return t.handle
}
