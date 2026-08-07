# Experimental

!!! quote "Changes in sing-box 1.8.0"

    :material-plus: [cache_file](#cache_file)  
    :material-alert-decagram: [clash_api](#clash_api)

### Structure

```json
{
  "experimental": {
    "cache_file": {},
    "clash_api": {},
    "v2ray_api": {},
    "unified_delay": {
      "enabled": false
    }
  }
}
```

### Fields

| Key             | Format                            |
|-----------------|-----------------------------------|
| `cache_file`    | [Cache File](./cache-file/)        |
| `clash_api`     | [Clash API](./clash-api/)          |
| `v2ray_api`     | [V2Ray API](./v2ray-api/)          |
| `unified_delay` | [Unified Delay](#unified_delay)    |

#### unified_delay

When `unified_delay.enabled` is enabled, URL tests send a warm-up request and measure only a second request on the same connection. This excludes connection establishment and TLS handshake time from the reported delay.

Disabled by default.
