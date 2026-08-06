---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 5,
  "psk": "password",
  "identity": false,
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "obfs_mode": "",
  "tls": {}
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // 监听字段

  "version": 6,
  "psk": "password",
  "users": [
    {
      "name": "sekai",
      "userkey": "user-password"
    }
  ],
  "mode": ""
}
```

### 监听字段

参阅 [监听字段](/zh/configuration/shared/listen/)。

### 字段

#### version

==必填==

Snell 协议版本，`5` `6` 之一。

版本 `5` 支持 HTTP 混淆（`obfs_mode`）；版本 `6` 以流量整形（`mode`）取而代之，并要求
`psk` 长度为 12 到 255 字节。

!!! note

    由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，
    因此不提供独立的 v4 服务器和 v5 客户端。

#### psk

==必填==

预共享密钥。

#### users

Snell 用户。

设置后，服务器运行于多用户模式：每一项包含 `name`（可选，用于日志）和 `userkey`
（用户密钥）。顶层的 `psk` 仍作为服务器密钥。

#### identity

==仅版本 5==

启用 Snell Identity 解析。

启用后，服务端根据线路 magic 自动选择版本：`DLSNID01` 使用 Identity v1；`DLSNID02`
使用 Identity v2，并校验与 TLS exporter 绑定的认证标签。因此 Identity v2 要求使用
ECH-TLS 且握手实际接受 ECH。

#### obfs_mode

==仅版本 5==

HTTP 混淆模式，`none` `http` 之一。

默认为 `none`。

#### tls

==仅版本 5==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/)。Snell ECH-TLS 要求启用 TLS 和 ECH，且不能
与 `obfs_mode` 组合使用。`alpn` 默认为空；显式配置后协商值必须匹配配置列表。
Identity v2 不绑定特定 ALPN。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。
