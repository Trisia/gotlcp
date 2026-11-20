# DTLCP 重握手使用指南

重握手（Renegotiation）是 DTLCP 连接在首次握手完成之后，由服务端发起的第二次及以后的握手。本文说明适用场景、服务端发起方式、客户端回调决策、拒绝后的行为、错误处理与并发约束。

协议依据：GM/T 0128—2023《数据报传输层密码协议规范》6.4.5.1、6.4.5.3、6.4.5.4.4。

---

## 1. 概述

### 1.1 什么是重握手

DTLCP 连接的完整生命周期由若干轮握手串接：

```
首次握手（FINISHED） → [HelloRequest → 重握手 → FINISHED] → [HelloRequest → 重握手 → FINISHED] → ...
```

- **发起方固定为服务端**：服务端发送 `hello_request` 消息，客户端收到后重新发送 `ClientHello`，双方重新完成一轮完整握手。
- **会话标识不变**：重握手沿用同一个 `*dtlcp.Conn` 对象和同一条 UDP 四元组，`RemoteAddr()` / `LocalAddr()` 不变。
- **密钥与 epoch 更新**：重握手会重新协商密钥；记录层 epoch 按 GM/T 0128—2023 6.3.3.2 递增，**不会回退**。

### 1.2 适用场景

| 场景 | 说明 |
|------|------|
| 证书轮换 | 服务端更换证书后，让已建立的连接切换到新证书，无需断开重连 |
| 密钥更新 | 长时间存活的连接定期刷新工作密钥，缩短单组密钥的暴露时间 |
| 安全策略刷新 | 重新校验客户端身份、重新协商密码套件或 ALPN |
| 定期安全刷新 | 按时间或消息量阈值，周期性执行一次完整握手 |

### 1.3 与首次握手的区别

| 维度 | 首次握手 | 重握手 |
|------|----------|--------|
| 发起方 | 客户端（发送 `ClientHello`） | 服务端（发送 `hello_request`） |
| `hello_request` 的 `message_seq` | 不存在 | `0` |
| 首条 `ServerHello` 的 `message_seq` | `1` | `1`（`message_seq` 从头计数） |
| 客户端是否可拒绝 | 不适用 | 可拒绝，且拒绝后旧会话继续可用 |
| 失败后果 | 连接不可用 | 接受后失败即关闭连接 |
| epoch | 从 `0` 开始递增 | 在上一轮基础上继续递增，不回退 |

### 1.4 默认行为

- **客户端未配置 `Config.OnRenegotiation` 时，收到 `hello_request` 一律拒绝**：客户端返回 `no_renegotiation` 告警，连接保持可用。这保证已有的客户端代码不会在未确认的情况下被拖入重握手。
- 服务端可随时调用 `Renegotiate()`；是否真正完成重握手，取决于客户端回调的决策。

---

## 2. 服务端发起重握手

### 2.1 API

```go
// Renegotiate 由服务端主动发起一次重握手（GM/T 0128—2023 6.4.5.4.4）。
//
// 服务端发送 HelloRequest 后，客户端应重新发送 ClientHello 开始新一轮握手。
// 调用前连接必须已完成首次握手。
//
// 返回值：
//   - error：连接尚未完成握手、本端为客户端、或握手失败时返回非 nil。
func (c *Conn) Renegotiate() error
```

| 项 | 说明 |
|----|------|
| 适用端 | 仅服务端。在客户端 `Conn` 上调用返回 `ErrRenegotiationUnsupported` |
| 前置条件 | 首次握手已完成（`ConnectionState().HandshakeComplete == true`） |
| 阻塞性 | **同步阻塞**，直到本轮重握手完成、被拒绝或失败才返回 |
| 返回值 | `nil` 表示重握手已完成；非 `nil` 见 §5 |

`Renegotiate()` 内部按以下顺序执行：

1. 检查首次握手是否已完成，未完成则返回错误；
2. 发送 `hello_request`（`message_seq = 0`）；
3. 重置本轮握手状态（`message_seq`、乱序缓存、flight 缓冲等归零，epoch 保持递增）；
4. 以 WAITING 状态进入服务端握手流程，直至完成、被拒绝或失败。

> `hello_request` 必须在状态重置**之前**发送，否则 `message_seq` 已经归零，服务端无法区分这是新一轮握手还是上一轮的残留消息。

### 2.2 调用时机

| 场景 | 建议做法 |
|------|---------|
| 证书轮换 | 将新证书加载到 `Config` 后，对每条可用连接调用一次 `Renegotiate()` |
| 定期刷新 | 由应用层定时器触发，串行调用，避免同一连接并发重握手 |
| 应用数据处理中 | 可以调用，但会阻塞该连接上的 `Read` / `Write`（见 §6） |

不建议在连接刚完成首次握手时立刻调用：客户端回调若依赖首次会话的上下文（如 `HandshakeCount == 1` 的判断），连续重握手会让判断失真。

### 2.3 完整示例

```go
package main

import (
	"log"
	"time"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

// handleConn 处理一条服务端连接，并按间隔发起重握手。
func handleConn(conn *dtlcp.Conn) {
	defer conn.Close()

	// 每 5 分钟重握手一次，刷新工作密钥
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	go func() {
		buf := make([]byte, 1500)
		for {
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			conn.WriteTo(buf[:n], addr)
		}
	}()

	for range ticker.C {
		if err := conn.Renegotiate(); err != nil {
			// 重握手失败后连接已不可用
			log.Printf("重握手失败，关闭连接 %s: %v", conn.RemoteAddr(), err)
			return
		}
		state := conn.ConnectionState()
		log.Printf("重握手完成：套件=0x%04x 对端证书数=%d",
			state.CipherSuite, len(state.PeerCertificates))
	}
}
```

> 说明：`Renegotiate()` 是同步调用，示例把它放在该连接专用的 goroutine 中，避免阻塞 `Accept` 循环。

### 2.4 服务端如何得知结果

| 结果 | 服务端观察到的现象 |
|------|-------------------|
| 客户端接受并完成 | `Renegotiate()` 返回 `nil`，`ConnectionState()` 为新一轮协商结果 |
| 客户端拒绝 | `Renegotiate()` 返回 `nil`，连接保持可用，但协商结果仍是旧会话；若配置了 `OnAlert`，会收到 `no_renegotiation`（`code = 100`）告警回调 |
| 握手失败 | `Renegotiate()` 返回非 `nil` 错误，连接不可用 |

用 `OnAlert` 区分"接受"与"拒绝"：

```go
config := &dtlcp.Config{
	Certificates: []dtlcp.Certificate{sigCert, encCert},
	OnAlert: func(code uint8, conn *dtlcp.Conn) {
		if code == 100 { // no_renegotiation
			log.Printf("对端拒绝重握手：%s", dtlcp.AlertCN(code))
		}
	},
}
```

---

## 3. 客户端响应：`OnRenegotiation` 回调

### 3.1 回调定义

```go
// OnRenegotiation 【可选】 客户端收到服务端 HelloRequest 时调用，
// 用于决定是否接受本次重握手。
//
// 返回 true 继续重握手；返回 false 则回退到原有会话，
// 并向服务端发送 no_renegotiation 告警，连接保持可用。
//
// 该方法为空时视为拒绝重握手。
OnRenegotiation func(*RenegotiationOffer) bool
```

该字段属于 `Config`，仅在客户端生效。

### 3.2 `RenegotiationOffer` 字段

| 字段 | 类型 | 含义 |
|------|------|------|
| `Conn` | `*Conn` | 收到重握手请求的连接对象，可读取 `RemoteAddr()` 与 `ConnectionState()` |
| `HandshakeCount` | `int` | 本连接已完成的握手轮数。首次握手完成后为 `1`，此后每完成一次重握手加 `1`；不含本次被提议的握手 |
| `PreviousState` | `ConnectionState` | 重握手生效前的连接状态快照（旧会话的套件、对端证书等） |

`PreviousState` 的常用字段：

| 字段 | 含义 |
|------|------|
| `HandshakeComplete` | 旧会话是否已完成握手（正常情况下为 `true`） |
| `CipherSuite` | 旧会话协商的密码套件 |
| `NegotiatedProtocol` | 旧会话协商的 ALPN 协议 |
| `PeerCertificates` | 旧会话中的服务端证书链 |
| `DidResume` | 旧会话是否通过会话重用完成 |
| `PeerIBCIdentity` / `PeerIBCSysParams` | 旧会话的 IBC 标识与公共参数（仅 IBC/IBSDH 套件） |

### 3.3 返回值与语义

| 返回值 | 语义 | 后续行为 |
|--------|------|---------|
| `true` | 接受重握手 | 客户端重置本轮握手状态，发送 `ClientHello`，重新执行完整握手。**此后重握手失败即关闭连接** |
| `false` | 拒绝重握手 | 客户端发送 `no_renegotiation` 告警（warning 级），**旧会话密钥与状态保持不变，连接继续可用** |
| 回调为 `nil` | 默认拒绝 | 与返回 `false` 相同 |

### 3.4 完整示例

```go
package main

import (
	"log"

	"gitee.com/Trisia/gotlcp/dtlcp"
)

func newClientConfig(pool *smx509.CertPool) *dtlcp.Config {
	return &dtlcp.Config{
		RootCAs: pool,
		OnRenegotiation: func(offer *dtlcp.RenegotiationOffer) bool {
			// 限定重握手次数，避免无上限的重复协商
			if offer.HandshakeCount >= 8 {
				log.Printf("连接 %s 已完成 %d 次握手，拒绝本次重握手",
					offer.Conn.RemoteAddr(), offer.HandshakeCount)
				return false
			}

			// 服务端证书未变化时无需重握手
			if certUnchanged(offer.PreviousState, offer.Conn) {
				log.Printf("服务端证书未变化，拒绝本次重握手")
				return false
			}

			log.Printf("接受重握手：第 %d 次，旧会话套件=0x%04x",
				offer.HandshakeCount, offer.PreviousState.CipherSuite)
			return true
		},
	}
}

// certUnchanged 判断服务端证书是否与旧会话一致。
func certUnchanged(prev dtlcp.ConnectionState, conn *dtlcp.Conn) bool {
	_ = prev
	// 这里可按业务需要读取当前配置中的证书指纹与 prev.PeerCertificates 比对
	return false
}
```

最简单的一直接受写法：

```go
config := &dtlcp.Config{
	RootCAs: pool,
	OnRenegotiation: func(offer *dtlcp.RenegotiationOffer) bool {
		return true
	},
}
```

### 3.5 回调内的注意事项

- 回调在客户端**处理入站记录**的路径上同步执行，不要阻塞（不要做网络请求、等待锁、写日志到慢设备）。
- 回调执行期间持有该连接入方向的互斥量，回调内**不要**对该 `Conn` 调用 `Read` / `Write` / `Renegotiate()`，否则会死锁。
- 接受重握手后，客户端旧会话的密钥被立即清理；不要再缓存或使用从 `PreviousState` 推导的密钥材料。

---

## 4. 拒绝重握手

### 4.1 `no_renegotiation` 告警的行为

| 项 | 说明 |
|----|------|
| 告警码 | `100`，名称 `no_renegotiation`，中文名"拒绝重新协商"（`dtlcp.AlertCN(100)`） |
| 级别 | **warning**（`alertLevelWarning`），不是致命告警 |
| 本端状态 | 客户端保持旧会话密钥与连接状态不变，`ConnectionState()` 仍返回旧会话结果 |
| 对端状态 | 服务端收到后不会将连接标记为失败，但本轮 `Renegotiate()` 不会产生新的协商结果 |
| 可继续进行 | 是。应用数据收发不受影响；客户端在首次握手完成前收到 `hello_request` 同样会发送该告警 |

### 4.2 旧会话为什么保持可用

拒绝路径下客户端只做两件事：发送 `no_renegotiation` 告警、返回。它**不**重置握手状态、不重新协商密钥、不递增 epoch，因此：

- 记录层读写密钥不变，旧 epoch 与 sequence_number 继续使用；
- 应用层 `Read` / `Write` 不会因这次拒绝而收到错误；
- 服务端可稍后再次调用 `Renegotiate()` 重试。

### 4.3 拒绝示例

按业务规则拒绝（例如只允许工作日 9:00—18:00 重握手）：

```go
config := &dtlcp.Config{
	RootCAs: pool,
	OnRenegotiation: func(offer *dtlcp.RenegotiationOffer) bool {
		// PreviousState 是旧会话快照，读取它不会触发握手
		if offer.PreviousState.DidResume {
			// 会话重用建立的连接不参与周期性刷新
			return false
		}
		return inServiceHours()
	},
}

// inServiceHours 判断当前是否处于允许重握手的时间段。
func inServiceHours() bool {
	now := time.Now()
	if now.Weekday() == time.Sunday || now.Weekday() == time.Saturday {
		return false
	}
	return now.Hour() >= 9 && now.Hour() < 18
}
```

### 4.4 拒绝后的重试

服务端侧 `Renegotiate()` 在客户端拒绝后返回 `nil`（重握手被正确处理，只是未生效）。如需重试，由服务端应用层决定重试间隔，并**限制最大重试次数**，否则持续向客户端发送 `hello_request` 会形成无效流量。

```go
const maxRenegotiationRetry = 3

// renegotiateWithRetry 在客户端拒绝（未生效）时按间隔重试。
func renegotiateWithRetry(conn *dtlcp.Conn, oldSuite uint16) error {
	for i := 0; i < maxRenegotiationRetry; i++ {
		if err := conn.Renegotiate(); err != nil {
			return err
		}
		if conn.ConnectionState().CipherSuite != oldSuite {
			return nil // 新会话已生效
		}
		time.Sleep(30 * time.Second)
	}
	return errors.New("dtlcp: 对端持续拒绝重握手")
}
```

---

## 5. 错误处理

### 5.1 错误一览

| 错误 | 触发条件 | 处理建议 |
|------|---------|---------|
| `ErrRenegotiationUnsupported` | 在客户端 `Conn` 上调用 `Renegotiate()` | 确认调用方向：重握手只能由服务端发起 |
| `errors.New("dtlcp: renegotiate called before initial handshake completed")` | 首次握手尚未完成就调用 `Renegotiate()` | 先等待握手完成（`ConnectionState().HandshakeComplete` 为 `true`）后再调用 |
| 其他握手错误 | 重握手过程中校验失败、超时、对端中断 | **连接已不可用，必须关闭并重建** |

### 5.2 失败即关闭

一旦客户端回调返回 `true`，本轮重握手就进入不可回退的路径：失败时**不尝试恢复旧会话**（旧会话密钥已被清理），`Conn` 进入错误状态，后续 `Read` / `Write` 均返回错误。这是 GM/T 0128—2023 对已完成握手失败的要求，也是本实现的明确取舍。

因此调用方必须把重握手失败视为连接级故障：

```go
if err := conn.Renegotiate(); err != nil {
	conn.Close()
	// 由应用层重新 Dial 建立新连接
	return err
}
```

### 5.3 使用 `errors.Is` 判断

```go
if err := conn.Renegotiate(); err != nil {
	if errors.Is(err, dtlcp.ErrRenegotiationUnsupported) {
		log.Printf("该连接不支持重握手，跳过本轮刷新")
		return nil
	}
	log.Printf("重握手失败，连接不可用: %v", err)
	return err
}
```

### 5.4 排查步骤

| 现象 | 可能原因 |
|------|---------|
| 服务端 `Renegotiate()` 返回 `nil` 但套件/证书未变化 | 客户端 `OnRenegotiation` 未配置或返回 `false`，检查客户端的回调逻辑与 `OnAlert` 输出 |
| 客户端完全没有反应 | 客户端 Old 版本不支持 `hello_request`，或客户端库版本低于本特性所在版本 |
| 重握手后连接立即失效 | 重握手过程中证书校验失败（例如服务端已换证书但客户端根证书池未更新） |
| 客户端出现 `unexpected message` | 对端实现的 `message_seq` 不按标准递增；本实现严格校验序号 |

---

## 6. 并发与阻塞说明

### 6.1 重握手期间的 `Read` / `Write`

| 操作 | 重握手期间的行为 |
|------|-----------------|
| 服务端 `Renegotiate()` | 同步阻塞直至本轮结束 |
| 同连接的 `Read` / `ReadFrom` | 阻塞，重握手完成后继续；重握手失败时返回错误 |
| 同连接的 `Write` / `WriteTo` | 阻塞，重握手完成后继续使用新密钥发送；失败时返回错误 |
| 客户端回调 `OnRenegotiation` | 在入站处理路径同步执行，返回后客户端才继续握手 |

### 6.2 并发调用 `Renegotiate()`

`Renegotiate()` 内部串行化同一连接的握手过程。并发调用不会造成状态错乱，但**不建议**依赖它排队：应用层应保证每条连接同时只有一个重握手在途。

```go
// 推荐：每条连接一个专用 goroutine 负责重握手
go func() {
	for range ticker.C {
		if err := conn.Renegotiate(); err != nil {
			return
		}
	}
}()
```

### 6.3 注意事项

1. **不要在 `Read` / `Write` 的调用栈内调用 `Renegotiate()`**，尤其是从数据处理回调中直接调用，会与同连接的读写互斥量形成冲突。
2. **不要在上层持有应用级锁时跨重握手**，重握手是可能持续数秒（受 `MaxRetransmitTimeout` 影响）的阻塞操作。
3. **重握手期间不要主动发送应用数据**，等待 `Renegotiate()` 返回后再继续，可避免消息在旧密钥下发送后又需要重传。
4. **`Config` 中的证书回调会被重新调用**：重握手时服务端会再次进入 `GetCertificate` / `GetKECertificate`，客户端会再次进入 `GetClientCertificate`。如果证书在文件中轮换，只需替换回调读取的文件，再调用 `Renegotiate()`。
5. **会话缓存与会话重用**：重握手执行的是完整握手，不受 `SessionCache` 影响；重握手完成后旧会话缓存条目不应再被使用。

---

## 7. 与协议标准的关系

| 标准条款 | 内容 | 本实现的对应 |
|---------|------|-------------|
| GM/T 0128—2023 6.4.5.1 | 重握手时 `HelloRequest` 的 `message_seq` 为 `0`，`ServerHello` 的 `message_seq` 为 `1` | `Renegotiate()` 在重置握手状态**之前**发送 `hello_request`，使其取到 `message_seq = 0`；随后 `resetHandshakeState()` 令 `message_seq` 归零，`ServerHello` 取到 `1` |
| GM/T 0128—2023 6.4.5.3 | 服务端需要重新握手时从 FINISHED 转 PREPARING 并传送 `HelloRequest`；客户端收到 `HelloRequest` 后从 FINISHED 转 PREPARING 并传送 `ClientHello` | 服务端 `Renegotiate()` 完成该状态迁移；客户端在握手完成后收到 `hello_request` 才允许进入重握手，握手未完成时发送 `no_renegotiation` 并忽略 |
| GM/T 0128—2023 6.4.5.4.4 | `hello_request` 消息定义（消息体为空） | `helloRequestMsg` 编码为 12 字节握手头 + 0 字节消息体 |
| GM/T 0128—2023 6.3.3.2 | 每次密码规格变更 epoch 递增，短期内不得重用 | `resetHandshakeState()` **不清零** `readEpoch` / `writeEpoch`，重握手走一次 CCS 后 epoch 自然递增 |
| GM/T 0128—2023 6.4.5.1 | 握手两端维护 `next_receive_seq`，重传消息沿用相同 `message_seq` | 重握手与首次握手共用同一套序号校验与整轮重传逻辑，重传消息的序号语义与首次握手一致 |

### 7.1 已知取舍

| 项 | 说明 |
|----|------|
| 无"是否允许重握手"开关 | 采用严格模式，不提供禁用重握手的配置项；拒绝与否由客户端 `OnRenegotiation` 决定 |
| 默认拒绝 | `OnRenegotiation` 为 `nil` 时拒绝，避免已有客户端被意外拖入重握手 |
| 接受后失败不做回退 | 不尝试恢复旧会话密钥，直接关闭连接 |
| 序号严格校验 | 接收端校验 `message_seq`，与不符合标准的对端互通时可能被判定为乱序/重复 |

---

## 8. 速查

```go
// 服务端：发起重握手（同步，直到完成/被拒绝/失败）
err := conn.Renegotiate()

// 客户端：决定是否接受（未配置即拒绝）
config := &dtlcp.Config{
	OnRenegotiation: func(offer *dtlcp.RenegotiationOffer) bool {
		return offer.HandshakeCount < 8
	},
}

// 服务端：观察客户端是否拒绝（告警码 100）
config := &dtlcp.Config{
	OnAlert: func(code uint8, conn *dtlcp.Conn) {
		if code == 100 {
			log.Print(dtlcp.AlertCN(code)) // 拒绝重新协商
		}
	},
}
```

| 相关配置 | 文档 |
|---------|------|
| `Config.OnRenegotiation` | [DTLCP 配置详解 §1.1](./DTLCP-Config.md) |
| 重传超时 | [DTLCP 配置详解 §2.4](./DTLCP-Config.md) |
| epoch 与序号 | [DTLCP 设计文档 §5.2](./DTLCP-Design.md) |
| `message_seq` 维护规则 | [DTLCP 设计文档 §6.2](./DTLCP-Design.md) |