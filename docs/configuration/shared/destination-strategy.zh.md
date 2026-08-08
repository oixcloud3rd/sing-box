# 目标策略字段

该字段可用于最终非组出站和客户端或拨号型端点。`selector` 和 `urltest` 不接受该字段；它们对每条连接使用最终选中叶子出站的策略。OpenVPN Server 等非拨号型端点不支持该字段。

目标策略字段与[拨号字段](/zh/configuration/shared/dial/)相互独立、处于同一级，可同时配置。

### 结构

```json
{
  "destination_strategy": "prefer_destination_addresses"
}
```

或：

```json
{
  "destination_strategy": {
    "strategy": "prefer_destination",
    "override_with_domain": {
      "evaluator": "dns-check",
      "ip_only": true
    }
  }
}
```

### 字段

#### strategy

可选值：

* `prefer_destination_addresses`（默认）：存在已解析目标地址时使用它们，否则使用原目标。
* `prefer_destination`：始终使用原目标，忽略已解析目标地址。

字符串形式仅设置 `strategy`。对象形式必须设置 `strategy`，且仅能为 `prefer_destination` 启用 `override_with_domain`。

#### override_with_domain

设置后，仅当显式指定的[域名评估器](/zh/configuration/shared/domain-evaluator/)接受域名时，才使用 HTTP、TLS 或 QUIC 嗅探得到的合法域名替换拨号目标。覆盖时保留原目标端口。

省略或设为 `null` 时，不读取或评估嗅探域名。

路由中的显式 `override_address` 优先级更高，并会跳过域名覆盖。仅设置 `override_port` 时仍允许域名覆盖，并保留修改后的端口。

#### override_with_domain.evaluator

必填。顶层[域名评估器](/zh/configuration/shared/domain-evaluator/)的标签。评估器没有隐式默认值。

#### override_with_domain.ip_only

启用后，仅当原目标为 IP 地址时允许覆盖。

对于 Selector 和 URLTest 组，每条连接都会原子绑定最终叶子及其策略。之后的组切换仅影响新连接（除非组的现有设置中断旧连接）。
