---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-out",

  "server": "127.0.0.1",
  "server_port": 1080,
  "version": 4,
  "psk": "password",
  "userkey": "",
  "identity": false,
  "reuse": false,
  "network": "tcp",
  "obfs_mode": "",
  "obfs_host": "",

  "tls": {},
  "transport": {},

  ... // Dial Fields
}
```

### Version 6 Structure

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

  ... // Dial Fields
}
```

### Fields

#### server

==Required==

The server address.

#### server_port

==Required==

The server port.

#### version

==Required==

The Snell protocol version, one of `4` `6`.

Version `4` supports HTTP obfuscation (`obfs_mode` / `obfs_host`); version `6`
replaces it with traffic shaping (`mode`) and requires a `psk` of 12 to 255
bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### userkey

The user key, used to authenticate against a multi-user server.

#### identity

==Version 4 only==

Enable the non-standard Snell identity header used by FlClash-compatible servers.

The identity is the first 16 bytes of `BLAKE3-512(psk)`. When enabled, `DLSNID01` and the identity
are inserted after the initial Snell salt. This option is disabled by default and must be enabled
explicitly when required by a server using the private Snell ECH-TLS extension.

#### reuse

Enable connection reuse (the Snell v2 `CONNECT` command).

#### network

Enabled network

One of `tcp` `udp`.

Both is enabled by default.

#### obfs_mode

==Version 4 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### obfs_host

==Version 4 only==

The HTTP `Host` header sent when `obfs_mode` is `http`.

`bing.com` is used by default.

#### tls

==Version 4 only==

TLS configuration, see [TLS](/configuration/shared/tls/).

For Snell ECH-TLS, TLS must be enabled and `ech.enabled` must be `true`.

#### transport

==Version 4 only==

V2Ray transport configuration, see [V2Ray Transport](/configuration/shared/v2ray-transport/).

For Snell ECH-TLS, only WebSocket transport with a non-empty `path` is supported. It cannot be
combined with `obfs_mode`.

The resulting protocol stack is Snell v4 over WebSocket over TLS with ECH. No additional bytes are
added to the Snell wire format.

Example:

```json
{
  "type": "snell",
  "tag": "snell-ech",
  "server": "server.example.com",
  "server_port": 443,
  "version": 4,
  "psk": "password",
  "identity": true,
  "reuse": true,
  "tls": {
    "enabled": true,
    "server_name": "public.example.com",
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
  },
  "transport": {
    "type": "ws",
    "path": "/snell",
    "headers": {
      "Host": "tunnel.example.com"
    }
  }
}
```

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.

### Dial Fields

See [Dial Fields](/configuration/shared/dial/) for details.
