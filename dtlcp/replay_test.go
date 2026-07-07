// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import "testing"

// TestReplayWindowSequential 测试连续序列号依次通过。
func TestReplayWindowSequential(t *testing.T) {
	w := newReplayWindow(64)
	for i := uint48(0); i < 10; i++ {
		if !w.check(i) {
			t.Fatalf("序列号 %d 应被接受", i)
		}
	}
}

// TestReplayWindowRejectOld 测试远小于窗口左边缘的老序列号被拒绝。
func TestReplayWindowRejectOld(t *testing.T) {
	w := newReplayWindow(64)
	// 先将窗口移动到 right=100
	for i := uint48(0); i <= 100; i++ {
		w.check(i)
	}
	// seq=30 在窗口左边缘 (100-64+1=37) 之外，应被拒绝
	if w.check(30) {
		t.Fatal("远小于窗口左边缘的序列号应被拒绝")
	}
}

// TestReplayWindowRejectDuplicate 测试重复序列号被拒绝。
func TestReplayWindowRejectDuplicate(t *testing.T) {
	w := newReplayWindow(64)
	// 接受 seq=50
	if !w.check(50) {
		t.Fatal("首次 seq=50 应被接受")
	}
	// 再次接受 seq=50 应被拒绝
	if w.check(50) {
		t.Fatal("重复 seq=50 应被拒绝")
	}
}

// TestReplayWindowAcceptAfterShift 测试窗口右移后接受新序列号。
func TestReplayWindowAcceptAfterShift(t *testing.T) {
	w := newReplayWindow(64)
	// 移到 right=100
	for i := uint48(0); i <= 100; i++ {
		w.check(i)
	}
	// seq=200 远大于 right=100，窗口应右移
	if !w.check(200) {
		t.Fatal("seq=200 应被接受（窗口右移）")
	}
	if w.right != 200 {
		t.Fatalf("right 应为 200，实际 %d", w.right)
	}
}

// TestReplayWindowJumpLargerThanSize 测试跳跃超过窗口大小的序列号被接受并重置位图。
func TestReplayWindowJumpLargerThanSize(t *testing.T) {
	w := newReplayWindow(64)
	// 移到 right=100
	for i := uint48(0); i <= 100; i++ {
		w.check(i)
	}
	// seq=200 跳跃 100 > 64，应重置位图
	if !w.check(200) {
		t.Fatal("跳跃超过窗口大小的 seq=200 应被接受")
	}
	if w.right != 200 {
		t.Fatalf("right 应为 200，实际 %d", w.right)
	}
	// 重置后位图应只标记了 200
	if w.bitmap != 1 {
		t.Fatal("位图应仅标记新序列号 200")
	}
}

// TestReplayWindowBoundary 测试窗口左边缘的序列号（边界情况）。
func TestReplayWindowBoundary(t *testing.T) {
	w := newReplayWindow(64)

	// 先接收 seq=0-36，建立 right=36
	for i := uint48(0); i <= 36; i++ {
		if !w.check(i) {
			t.Fatalf("seq=%d 应被接受", i)
		}
	}
	// 此时 right=36
	// 跳转到 seq=100，diff=64，达到 size 边界，
	// 由于 diff >= size(64)，位图被重置
	if !w.check(100) {
		t.Fatal("seq=100 应被接受")
	}
	// right=100, size=64, 左边缘=100-64+1=37
	// seq=36 的位置：diff=100-36=64，diff >= 64，拒绝
	if w.check(36) {
		t.Fatal("seq=36 在窗口左边缘之外，应被拒绝")
	}
	// seq=37 的位置：diff=100-37=63，diff < 64，且位图中无此位，应接受
	if !w.check(37) {
		t.Fatal("seq=37 在窗口左边缘（未收到过），应被接受")
	}
	// seq=100 重复，应拒绝
	if w.check(100) {
		t.Fatal("重复 seq=100 应被拒绝")
	}
}

// TestReplayWindowMinSize 测试最小窗口大小为 32。
func TestReplayWindowMinSize(t *testing.T) {
	w := newReplayWindow(10) // 小于最小 32
	if w.size != 32 {
		t.Fatalf("窗口大小应为最小 32，实际 %d", w.size)
	}
}

// TestReplayWindowAcceptInWindow 测试窗口内非重复序列号被接受。
func TestReplayWindowAcceptInWindow(t *testing.T) {
	w := newReplayWindow(64)
	// 接受 seq=100
	w.check(100)
	// 接受 seq=95 (100-5=95 > 100-64+1=37)，应在窗口内
	if !w.check(95) {
		t.Fatal("seq=95 在窗口内且非重复，应被接受")
	}
	// 再接受 seq=95（重复），应拒绝
	if w.check(95) {
		t.Fatal("重复 seq=95 应被拒绝")
	}
}
