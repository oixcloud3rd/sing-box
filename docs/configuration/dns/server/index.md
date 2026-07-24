---
icon: material/alert-decagram
---

!!! quote "Changes in sing-box 1.14.0"

    :material-plus: [mdns](./mdns/)

!!! quote "Changes in sing-box 1.12.0"

    :material-plus: [type](#type)

# DNS Server

### Structure

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

The type of the DNS server.

| Type            | Format                    |
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

The tag of the DNS server.

#### oixcloud

Enable oixCloud DNS query authentication for remote DNS server types: `udp`, `tcp`, `tls`, `https`, `quic`, and `h3`.

When enabled, sing-box signs every queried domain with the Ed25519 private key embedded at build time and a fixed 300-second time window. The signature is encoded as two lowercase Base32 labels prepended to the query name. Matching names in the response are restored before the response is returned to the DNS client.

This option authenticates queries but does not encrypt DNS packets. Use `tls`, `https`, `quic`, or `h3` when transport confidentiality is also required.

The build must contain a valid oixCloud private key. Server initialization fails if the key is missing or invalid, and queries that cannot form a valid signed DNS name fail without being sent unsigned.

See [Build from source](/installation/build-from-source/#oixcloud-private-key) for key injection instructions.
