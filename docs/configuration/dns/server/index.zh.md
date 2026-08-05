---
icon: material/alert-decagram
---

!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [mdns](./mdns/)

!!! quote "sing-box 1.12.0 中的更改"

    :material-plus: [type](#type)

# DNS Server

### 结构

```json
{
  "dns": {
    "servers": [
      {
        "type": "",
        "tag": "",
        "oixcloud": false
      }
    ]
  }
}
```

#### type

DNS 服务器的类型。

| 类型              | 格式                        |
|-----------------|---------------------------|
| empty (default) | :material-note-remove: [Legacy](./legacy/) |
| `local`         | [Local](./local/)         |
| `hosts`         | [Hosts](./hosts/)         |
| `tcp`           | [TCP](./tcp/)             |
| `udp`           | [UDP](./udp/)             |
| `tls`           | [TLS](./tls/)             |
| `quic`          | [QUIC](./quic/)           |
| `https`         | [HTTPS](./https/)         |
| `h3`            | [HTTP/3](./http3/)        |
| `dhcp`          | [DHCP](./dhcp/)           |
| `mdns`          | [mDNS](./mdns/)           |
| `fakeip`        | [Fake IP](./fakeip/)      |
| `tailscale`     | [Tailscale](./tailscale/) |
| `openconnect`   | [OpenConnect](./openconnect/) |
| `openvpn`       | [OpenVPN](./openvpn/)         |
| `resolved`      | [Resolved](./resolved/)   |

#### tag

DNS 服务器的标签。

#### oixcloud

为远程 DNS 服务器启用 oixCloud DNS 查询认证。支持 `udp`、`tcp`、`tls`、`https`、`quic` 和 `h3`。

启用后，sing-box 使用编译时嵌入的 Ed25519 私钥和固定的 300 秒时间窗为每个查询域名签名。签名编码为两个小写 Base32 标签并添加到查询名之前；响应返回 DNS 客户端前会恢复其中匹配的名称。

此选项认证查询，但不加密 DNS 报文。如需传输保密性，请使用 `tls`、`https`、`quic` 或 `h3`。

构建产物必须包含有效的 oixCloud 私钥。密钥缺失或无效时 DNS 服务器初始化失败；签名后无法形成合法 DNS 名称的查询也会直接失败，不会以未签名形式发送。

密钥注入方式参阅[从源代码构建](/zh/installation/build-from-source/#oixcloud)。
