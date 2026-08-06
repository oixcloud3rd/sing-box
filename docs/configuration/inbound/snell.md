---
icon: material/new-box
---

!!! question "Since sing-box 1.14.0"

### Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

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

### Version 6 Structure

```json
{
  "type": "snell",
  "tag": "snell-in",

  ... // Listen Fields

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

### Listen Fields

See [Listen Fields](/configuration/shared/listen/) for details.

### Fields

#### version

==Required==

The Snell protocol version, one of `5` `6`.

Version `5` supports HTTP obfuscation (`obfs_mode`); version `6` replaces it
with traffic shaping (`mode`) and requires a `psk` of 12 to 255 bytes.

!!! note

    Since we intentionally do not support the QUIC proxy mode of Snell v5, the v5 wire protocol
    is effectively identical to v4, so no separate v4 server or v5 client is provided.

#### psk

==Required==

The pre-shared key.

#### users

Snell users.

When set, the server runs in multi-user mode: each entry has a `name` (optional, used in
logs) and a `userkey` (the user's key). The top-level `psk` remains the server key.

#### identity

==Version 5 only==

Enable Snell identity parsing.

When enabled, the server selects the identity version from the wire magic: `DLSNID01` uses
Identity v1, while `DLSNID02` uses Identity v2 and verifies its TLS-exporter-bound authentication
tag. Identity v2 therefore requires ECH-TLS and an accepted ECH handshake.

#### obfs_mode

==Version 5 only==

HTTP obfuscation mode, one of `none` `http`.

`none` is used by default.

#### tls

==Version 5 only==

TLS configuration, see [TLS](/configuration/shared/tls/). Snell ECH-TLS requires TLS and ECH to be
enabled and cannot be combined with `obfs_mode`. `alpn` is empty by default; if configured, the
negotiated value must match the configured list. Identity v2 is not tied to a particular ALPN.

#### mode

==Version 6 only==

Traffic shaping mode, one of `default` `unshaped` `unsafe-raw`.

`default` is used by default.
