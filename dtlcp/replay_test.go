// Copyright (c) 2025 gotlcp contributors
// gotlcp is licensed under Mulan PSL v2.

package dtlcp

import (
	"testing"
)

// =============================================================================
// replayWindow 单元测试 (RFC 6347 §4.1.2.6)
// =============================================================================

func TestReplayWindowInit(t *testing.T) {
	config := &Config{}
	srv := Server(nil, nil, config)
	if srv.replayWindow == nil {
		t.Fatal("Server() 后 replayWindow 不应为 nil")
	}
	if srv.replayWindow.size != defaultReplayWindowSize {
		t.Fatalf("默认窗口大小应为 %d，实际 %d", defaultReplayWindowSize, srv.replayWindow.size)
	}
	cli := Client(nil, nil, config)
	if cli.replayWindow == nil {
		t.Fatal("Client() 后 replayWindow 不应为 nil")
	}
}

func TestReplayWindowCustomSize(t *testing.T) {
	srv := Server(nil, nil, &Config{ReplayWindow: 128})
	if srv.replayWindow.size != 128 {
		t.Fatalf("自定义窗口大小应为 128，实际 %d", srv.replayWindow.size)
	}
}

func TestReplayWindowMinSize(t *testing.T) {
	srv := Server(nil, nil, &Config{ReplayWindow: 16})
	if srv.replayWindow.size < 32 {
		t.Fatalf("窗口大小最小应为 32，实际 %d", srv.replayWindow.size)
	}
}

func TestReplayWindowCheckNewSeq(t *testing.T) {
	w := newReplayWindow(64)
	if !w.check(100) {
		t.Fatal("check(100) 新序列号应接受")
	}
	if w.right != 100 {
		t.Fatalf("right 应更新为 100，实际 %d", w.right)
	}
}

func TestReplayWindowCheckDuplicate(t *testing.T) {
	w := newReplayWindow(64)
	if !w.check(50) {
		t.Fatal("首次 check(50) 应接受")
	}
	if w.check(50) {
		t.Fatal("重复 check(50) 应拒绝")
	}
}

func TestReplayWindowCheckOldSeq(t *testing.T) {
	w := newReplayWindow(64)
	w.check(100)
	if w.check(10) {
		t.Fatal("check(10) 在窗口左侧应拒绝")
	}
}

func TestReplayWindowSliding(t *testing.T) {
	w := newReplayWindow(64)
	for i := uint48(0); i < 70; i++ {
		if !w.check(i) {
			t.Fatalf("check(%d) 应接受", i)
		}
	}
	if w.check(0) {
		t.Fatal("check(0) 应已移出窗口被拒绝")
	}
}

func TestReplayWindowLargeJump(t *testing.T) {
	w := newReplayWindow(64)
	w.check(10)
	if !w.check(100) {
		t.Fatal("check(100) 大幅跳跃应接受")
	}
	if w.right != 100 {
		t.Fatalf("right 应更新为 100，实际 %d", w.right)
	}
	if !w.check(50) {
		t.Fatal("跳跃后窗口内未检查过的 seq 应接受")
	}
}

func TestReplayWindowZeroSeq(t *testing.T) {
	w := newReplayWindow(64)
	if !w.check(0) {
		t.Fatal("check(0) 应接受")
	}
	if w.check(0) {
		t.Fatal("重复 check(0) 应拒绝")
	}
}
