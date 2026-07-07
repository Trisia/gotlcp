// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import "time"

// RetransmitTimer DTLCP 重传定时器
// 支持指数退避：每次超时加倍，直到 max
type RetransmitTimer struct {
	initial  time.Duration
	current  time.Duration
	max      time.Duration
	newTimer func(time.Duration) *TimerHandle
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
	t.handle = t.newTimer(t.current)
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
	if t.handle != nil {
		t.handle.Stop()
		t.handle = nil
	}
}

// fired 检查定时器是否已触发（非阻塞）
func (t *RetransmitTimer) fired() bool {
	if t.handle == nil {
		return false
	}
	select {
	case <-t.handle.C:
		return true
	default:
		return false
	}
}
