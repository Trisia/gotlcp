# DTLCP 与 TLCP 共享代码重构设计

## 目标

消除 `dtlcp/` 与 `tlcp/` 之间的代码重复。将8个功能完全相同的文件抽取到共享包 `tlcp/common/`，两个包均通过 import 引用。

## 背景

两个包共有13个同名文件，其中8个文件（`alert.go`、`auth.go`、`cache.go`、`cipher_suites.go`、`key_agreement.go`、`key_schedule.go`、`prf.go`、`session.go`）的代码逻辑完全相同，仅包名不同。目前以复制粘贴方式维护，存在两处同步修改的维护成本。

DTLCP特有的文件（`cookie.go`、`fragment.go`、`retransmit.go`、`replay.go`）和协议特有的文件（`common.go`、`conn.go`、`handshake_*.go`、`handshake_messages.go`）需要各自保留。

## 方案

### 新建共享包 `tlcp/common/`

包路径：`gitee.com/Trisia/gotlcp/tlcp/common`

移入8个文件，每个文件的调整如下：

| 文件 | 调整内容 |
|------|---------|
| `alert.go` | 无 |
| `prf.go` | 无 |
| `cipher_suites.go` | 无（已包含 `TLCP_*` 常量、`CipherSuite`、`cipherSuite`、`SignatureAlgorithm`） |
| `key_agreement.go` | 错误消息移除 `"tlcp:"`/`"dtlcp:"` 前缀 |
| `key_schedule.go` | 无 |
| `session.go` | 无 |
| `auth.go` | `signHandshake()` 第一个参数从 `*Conn` 改为 `io.Reader`（只用了 `c.config.rand()`） |
| `cache.go` | 无 |

另需从 `common.go` 提取以下相同常量/类型到共享包：
- `VersionTLCP`（值 `0x0101`，两边相同）
- `CurveID` 类型及 `CurveSM2` 常量

### tlcp 包变更

- 删除以上8个文件
- `common.go` 中删除 `VersionTLCP`、`CurveID`、`CurveSM2` 定义，改为 `type CurveID = common.CurveID` 等重新导出语句以保持 API 向后兼容
- `conn.go` 中 `activeCertHandles` 字段类型改为 `[]*common.ActiveCert`
- `handshake_client.go` 中调用 `signHandshake` 时传入 `c.config.rand()` 替代 `c`，引用共享类型时加上 `common.` 前缀

### dtlcp 包变更

- 删除以上8个文件
- `common.go` 中同样改为引用共享包中的常量/类型
- `conn.go` 中 `activeCertHandles` 字段类型改为 `[]*common.ActiveCert`
- `handshake_client.go` 中同样适配 `signHandshake` 调用和类型引用
- DTLCP 特有文件（`cookie.go`、`dtlcp.go`、`fragment.go`、`retransmit.go`、`replay.go`）保持不变

### 兼容性

- `tlcp.CurveID` 通过类型别名 `type CurveID = common.CurveID` 重新导出，外部调用者不受影响
- `tlcp.CipherSuite` 等公开类型同理处理
- 错误消息前缀移除后，错误文本变为通用描述，不再包含包名前缀

### 不变的部分

- `common.go` 中双方不同的部分（`Config`、`Conn`、`ConnectionState`、`recordHeaderLen` 等）各自保留
- `conn.go`、`handshake_client.go`、`handshake_server.go`、`handshake_messages.go` 各自保留
- DTLCP 特有文件全部保留

## 文件影响范围

### 新增

- `tlcp/common/alert.go`
- `tlcp/common/prf.go`
- `tlcp/common/cipher_suites.go`
- `tlcp/common/key_agreement.go`
- `tlcp/common/key_schedule.go`
- `tlcp/common/session.go`
- `tlcp/common/auth.go`
- `tlcp/common/cache.go`

### 删除

- `dtlcp/alert.go`、`dtlcp/prf.go`、`dtlcp/cipher_suites.go`、`dtlcp/key_agreement.go`、`dtlcp/key_schedule.go`、`dtlcp/session.go`、`dtlcp/auth.go`、`dtlcp/cache.go`
- `tlcp/alert.go`、`tlcp/prf.go`、`tlcp/cipher_suites.go`、`tlcp/key_agreement.go`、`tlcp/key_schedule.go`、`tlcp/session.go`、`tlcp/auth.go`、`tlcp/cache.go`

### 修改

- `tlcp/common.go` — 删除共享常量/类型，添加重新导出
- `tlcp/conn.go` — `activeCertHandles` 类型改为共享包类型
- `tlcp/handshake_client.go` — `signHandshake` 调用适配
- `tlcp/handshake_server.go` — 类型引用适配
- `dtlcp/common.go` — 删除共享常量/类型，添加重新导出
- `dtlcp/conn.go` — `activeCertHandles` 类型改为共享包类型
- `dtlcp/handshake_client.go` — `signHandshake` 调用适配
- `dtlcp/handshake_server.go` — 类型引用适配
- `dtlcp/handshake_messages.go` — 类型引用适配

## 验证

```bash
# 编译检查
go build ./tlcp/...
go build ./dtlcp/...

# 完整测试
go test -v ./tlcp/...
go test -v ./dtlcp/...
```
