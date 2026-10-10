---
icon: material/new-box
---

!!! question "自 sing-box 1.14.0 起"

### 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "identity": 0,
  "reuse": false,
  "preconnect": 0,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  "tls": {},

  ... // 拨号字段
}
```

### 版本 6 结构

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 6,
  "psk": "password",
  "userkey": "",
  "reuse": false,
  "network": "tcp",
  "mode": "",

  ... // 拨号字段
}
```

### 字段

#### server

==必填==

服务器地址。

#### server_port

==必填==

服务器端口。

#### version

==必填==

Snell 协议版本，`4` `6` 之一。

版本 `4` 支持 HTTP 混淆（`obfs_mode` / `obfs_host`）；版本 `6` 以流量整形（`mode`）
取而代之，并要求 `psk` 长度为 12 到 255 字节。

!!! note

    由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，
    因此不提供独立的 v4 服务器和 v5 客户端。

#### psk

==必填==

预共享密钥。

#### userkey

用户密钥，用于向多用户服务器进行认证。

#### identity

==仅版本 4==

Snell Identity 版本。省略时关闭，`1` 发送 `DLSNID01` Identity，
`2` 发送使用 TLS exporter 和 Snell salt 认证的 `DLSNID02` Identity。

Identity v1 是 `BLAKE3-512(psk)` 的前 16 字节。Identity v2 要求使用 ECH-TLS 且握手实际接受
ECH；它不绑定特定 ALPN。默认 TCP 传输允许与 `tls.insecure: true` 一起使用，
HTTP/3 则要求开启证书验证。

#### reuse

启用连接复用（Snell v2 `CONNECT` 命令）。

#### preconnect

后台预先建立的可复用连接数，范围为 `0` 到 `4`，默认为 `0`（关闭）。

大于 `0` 时要求 Snell v4、ECH-TLS 和 `reuse: true`。预连接失败只记录警告，不阻止出站启动。

#### network

启用的网络协议。

`tcp` 或 `udp`。

默认所有。

#### obfs_mode

==仅版本 4==

HTTP 混淆模式，`none` `http` 之一。

默认为 `none`。

#### obfs_host

==仅版本 4==

`obfs_mode` 为 `http` 时发送的 HTTP `Host` 头。

默认为 `bing.com`。

#### tls

==仅版本 4==

TLS 配置，参阅 [TLS](/zh/configuration/shared/tls/)。

使用 Snell ECH-TLS 时，必须启用 TLS，并将 `ech.enabled` 设为 `true`。未设置 `transport` 时，
TLS 连接直接承载 raw Snell v4。不能与 simple-obfs 组合使用，且服务端必须实际接受 ECH。

`alpn` 默认为空；显式配置后，协商结果必须属于配置列表。可以显式使用 `snell-ech/1`，
也可以使用自定义值。

示例：

```json
{
  "type": "snell",
  "tag": "snell-ech",
  "server": "server.example.com",
  "server_port": 443,
  "version": 4,
  "psk": "password",
  "identity": 2,
  "reuse": true,
  "preconnect": 2,
  "tls": {
    "enabled": true,
    "server_name": "public.example.com",
    "alpn": ["snell-ech/1"],
    "ech": {
      "enabled": true,
      "config": [
        "-----BEGIN ECH CONFIGS-----",
        "...",
        "-----END ECH CONFIGS-----"
      ]
    },
    "utls": {
      "enabled": true,
      "fingerprint": "chrome"
    }
  }
}
```

#### transport

==仅版本 4==

可选的 Snell 专用传输配置。省略时保持原有 TCP 行为，`type` 仅支持 `http3`。

此模式通过 QUIC 上的 HTTP/3 Extended CONNECT 隧道承载 Snell v4，
不是官方 Snell v5 的 QUIC 模式，也不是 V2Ray QUIC 传输。
服务端须支持对应的隧道协议：`:protocol = websocket`，路径为 `/ws-tunnel-`
加 PSK SHA-256 前 12 字节的小写十六进制。隧道内直接传输 Snell 数据，不添加 WebSocket 帧。

要求显式设置 `identity: 2`，开启 TLS、ECH 和证书验证（`tls.insecure` 必须为 `false`）。
不支持叠加 simple-obfs、Reality、非 Go TLS 引擎或显式配置 `1.3` 以外的 TLS 版本。
二进制必须使用 `with_quic` 构建，即使开启 Happy Eyeballs 也不例外。

```json
{
  "type": "snell",
  "server": "server.example.com",
  "server_port": 443,
  "version": 4,
  "psk": "password",
  "identity": 2,
  "transport": {
    "type": "http3",
    "happy_eyeballs": false,
    "quic_congestion_control": "reno"
  },
  "tls": {
    "enabled": true,
    "server_name": "inner.example.com",
    "ech": {
      "enabled": true
    }
  }
}
```

ECH 沿用现有 TLS 配置，支持内联配置、配置文件和 DNS 获取。
HTTP/3 使用 Go TLS 1.3 和 `h3` ALPN；`tls.utls`、TLS 分片、spoof 和 kTLS 仅用于 TCP 传输。
HTTP/3 不覆盖 TCP 的 ALPN：TCP 使用显式 `tls.alpn`，省略时默认 `snell-ech/1`。

TCP 和 UDP 代理流量均通过隧道传输。多个独立隧道共享 QUIC 会话，
现有 `reuse` 和 `preconnect` 配置仍然适用。

##### transport.happy_eyeballs

默认 `false`。HTTP/3 隧道建立预算为 10 秒，失败直接返回错误。

设为 `true` 时，立即启动 HTTP/3，建隧道预算为 2 秒；延迟 250 ms 后启动同一服务器地址和端口的
ECH-TLS TCP。若 HTTP/3 提前失败，则立即启动 TCP。已有 QUIC 会话时，延迟为其平滑 RTT 的两倍，
限制在 100 ms–1 秒。首个完成验证的传输获胜，TCP 失败不会取消仍在进行的 HTTP/3 尝试。
竞速发生在发送 Snell 认证和业务数据之前，不会重放请求。

TCP 获胜后，HTTP/3 在原有预算内继续尝试。迟到成功会关闭多余隧道，但保留 QUIC 会话并清除冷却；
HTTP/3 失败则使之后 30 秒内的新连接直接使用 TCP。并发 HTTP/3 尝试成功也会清除冷却。

等待获胜连接期间，调用方取消或更短的 deadline 会终止竞速，且不会将 HTTP/3 标记为故障。
共享 QUIC 建连不受单个等待者取消影响，预算为 2 秒（未开启 Happy Eyeballs 时为 10 秒）。
接口更新和关闭会取消后台任务并丢弃旧结果。

两种传输均要求证书验证和 ECH 成功，不使用明文 Snell 或 Identity v1。
旧字段 `transport.fallback` 已移除并会报错，请改用 `transport.happy_eyeballs`。

##### transport.quic_congestion_control

支持 `reno`、`cubic`、`bbr`，默认使用 QUIC 库原生 Reno。
仅控制客户端 QUIC 发送方向，不改变服务端发送算法，也不影响 TCP 传输。

##### transport.bbr_profile

支持 `standard`、`conservative`、`aggressive`，使用 BBR 时默认 `standard`。
仅允许与显式 `quic_congestion_control: "bbr"` 一起使用；
其他算法下填写此字段会报错，不会自动切换为 BBR。

##### 传输层 QUIC 字段

可直接在 `transport` 内设置标准 [QUIC 字段](/zh/configuration/shared/quic/)：
`idle_timeout`、`keep_alive_period`、`stream_receive_window`、
`connection_receive_window`、`max_concurrent_streams`、`initial_packet_size` 和
`disable_path_mtu_discovery`。

省略的字段使用 QUIC 库默认值，不再设置 Snell 专用接收窗口、保活参数或按平台覆盖路径 MTU 发现。
显式指定接收窗口时，该值同时作为初始值与最大值。这些字段仅影响 HTTP/3，
不影响 TCP 传输或 Happy Eyeballs 建连时限。

#### mode

==仅版本 6==

流量整形模式，`default` `unshaped` `unsafe-raw` 之一。

默认为 `default`。

### 拨号字段

参阅 [拨号字段](/zh/configuration/shared/dial/)。
