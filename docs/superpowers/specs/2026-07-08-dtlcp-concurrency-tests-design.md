# DTLCP 并发测试设计

## 概述

为 `dtlcp/` 模块添加并发测试，验证内部（单 `Conn` 多 goroutine）和外部（多 `Conn` 并发使用）的稳定性。发现并发问题后修复。

## 背景

当前 `dtlcp/` 测试覆盖：

- `fragment.go`、`replay.go`、`retransmit.go`、`cookie.go` 有完整单元测试
- 握手集成测试存在但用 `t.Skipf()` 容错
- **零并发测试** — 无 `t.Parallel()`、无 `-race`、无压力测试

经并发分析发现一个实际竞态：`Close()` 与 `Read()/Write()` 之间的 `activeCall`/`workKey` 竞态。

## 核心问题：Close() 与 Read/Write 竞态

### 问题描述

`Close()` 使用 `activeCall` (int32) 协调与 `Write()` 的并发：

- `Write()`: CAS 递增 activeCall（位 1+ = 活跃写计数），defer 递减
- `Read()`: **未参与 activeCall 协议**，直接获取 `in.Lock` 后读数据
- `Close()`: CAS 设置位 0（关闭标记），若 `activeCall==0` 则发送 closeNotify、清零 workKey、关闭 pconn；否则直接关闭 pconn 跳过清理

竞态窗口：

```
Write():  atomic.Load(&activeCall) → 发现未关闭
Close():  atomic.CAS(&activeCall, 0, 1) → 成功，标记已关闭
Close():  setZero(c.workKey) → 清零工作密钥
Write():  atomic.CAS(&activeCall, x, x+2) → 成功，写入计数+1
Write():  用 c.workKey 加密... → 读取已清零的内存！DATA RACE
```

`Read()` 更严重 — 完全不受 `activeCall` 保护，`Close()` 关闭 `pconn` 时 `Read()` 可能正在解密。

### 修复方案

`Read()` 和 `ReadFrom()` 加入 `activeCall` 协议：

```go
// Close() 等待所有活跃调用完成后才清理
func (c *Conn) Close() error {
    // 设置关闭标记
    for {
        x := atomic.LoadInt32(&c.activeCall)
        if x&1 != 0 {
            return net.ErrClosed
        }
        if atomic.CompareAndSwapInt32(&c.activeCall, x, x|1) {
            break
        }
    }
    // 等待所有活跃 Read/Write/ReadFrom 完成
    for atomic.LoadInt32(&c.activeCall) > 1 {
        // 自旋等待（实际场景中活跃调用会在毫秒内完成）
    }
    // 发送 closeNotify（仅握手完成后）
    // 清零 workKey
    // 关闭 pconn
}
```

```go
// Read() 加入 activeCall 保护
func (c *Conn) Read(b []byte) (int, error) {
    // 检查并递增 activeCall
    for {
        x := atomic.LoadInt32(&c.activeCall)
        if x&1 != 0 {
            return 0, net.ErrClosed
        }
        if atomic.CompareAndSwapInt32(&c.activeCall, x, x+2) {
            break
        }
    }
    defer atomic.AddInt32(&c.activeCall, -2)
    // 原有逻辑...
}
```

## 测试设计

### 运行方式

```bash
# 单次运行
go test -race -v -run "Concurrent|Many|Multi" ./dtlcp/

# 多次运行以暴露概率性竞态
go test -race -count=50 -run "TestConcurrentWriteAndClose|TestConcurrentReadAndClose" ./dtlcp/
```

### 阶段一：内部并发测试

**文件：** `dtlcp/conn_concurrent_test.go`

基于现有 `mockPacketConn` 和 `testHandshakePair()` 辅助函数，完成握手后对同一 `Conn` 施加并发操作。

#### TestConcurrentReadWrite

- N 个 writer goroutine 并发写，M 个 reader goroutine 并发读
- 验证数据完整性（每条消息带序号，读端验证）
- 无死锁，`in.Lock`/`out.Lock` 正确序列化

#### TestConcurrentWriteAndClose

- goroutine A: 循环 Write
- goroutine B: 随机 0-10ms sleep 后 Close()
- `-race -count=50` 多次运行
- 预期：无 panic，无 data race

#### TestConcurrentReadAndClose

- goroutine A: 循环 Read
- goroutine B: 随机 0-10ms sleep 后 Close()
- `-race -count=50` 多次运行
- 预期：无 panic，无 data race

#### TestConcurrentReadFromWriteToAndClose

- 对 `ReadFrom`/`WriteTo`（PacketConn 接口）做同样测试

#### TestConcurrentMixedOps

- 同时启动 Read/Write/ReadFrom/WriteTo/Close goroutine
- `-race -count=20` 多次运行

### 阶段二：外部并发测试

**文件：** `dtlcp/concurrent_stress_test.go`

#### TestManyConnections

- 创建 N 对 mockPacketConn（N=50）
- N 个 goroutine 并发完成握手 + 传输 10 条消息
- 验证全部成功
- 检测 goroutine 泄漏（`runtime.NumGoroutine()` 前后对比）
- `-race` 无竞态

#### TestSingleServerMultiClient

- 1 个服务端 Conn + M 个客户端 Conn（M=20）
- 并发握手 + 数据传输
- 验证服务端正确处理多个对端
- `-race` 无竞态

#### TestDialListenConcurrency

- 同时启动多个 `Listen` 和 `Dial`（基于真实 UDP）
- 验证 `NewListener` goroutine 安全

## 预期测试输出

测试通过需满足：

1. 无 panic
2. `-race` 无竞态报告
3. 数据完整性验证通过
4. 无 goroutine 泄漏
5. `-count=50` 多次运行稳定通过

## 非目标

- 不测试 `pendingFragments` map 的并发访问（当前所有访问路径持有 `in.Lock`，无实际风险）
- 不修改 `RetransmitTimer`、`replayWindow`、`fragmentBuffer` 内部结构（它们在 Conn 锁保护下安全使用）
- 不为锁顺序问题添加运行时检测（当前 API 使用模式不会触发死锁）
