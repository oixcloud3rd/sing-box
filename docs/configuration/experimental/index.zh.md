# 实验性

!!! quote "sing-box 1.8.0 中的更改"

    :material-plus: [cache_file](#cache_file)  
    :material-alert-decagram: [clash_api](#clash_api)

### 结构

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

### 字段

| 键              | 格式                            |
|-----------------|--------------------------------|
| `cache_file`    | [缓存文件](./cache-file/)        |
| `clash_api`     | [Clash API](./clash-api/)      |
| `v2ray_api`     | [V2Ray API](./v2ray-api/)      |
| `unified_delay` | [统一延迟](#unified_delay)       |

#### unified_delay

启用 `unified_delay.enabled` 后，URL 测试会先发送一次预热请求，然后仅测量同一连接上的第二次请求。这会从报告的延迟中排除连接建立和 TLS 握手时间。

默认禁用。
