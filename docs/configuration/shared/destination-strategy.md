# Destination Strategy Fields

Available on final non-group outbounds and client or dialing endpoints. `selector` and `urltest` do not accept this field; they use the strategy of the leaf selected for each connection. Non-dialing endpoints such as OpenVPN Server do not support this field.

Destination Strategy Fields and [Dial Fields](/configuration/shared/dial/) are independent sibling fields and can be configured together.

### Structure

```json
{
  "destination_strategy": "prefer_destination_addresses"
}
```

or:

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

### Fields

#### strategy

One of:

* `prefer_destination_addresses` (default): use resolved destination addresses when present, otherwise use the original destination.
* `prefer_destination`: always use the original destination and ignore resolved destination addresses.

The string form sets only `strategy`. The object form requires `strategy` and may enable `override_with_domain` only with `prefer_destination`.

#### override_with_domain

When present, replace the dial destination with a valid domain sniffed from HTTP, TLS, or QUIC only after the explicitly selected [Domain Evaluator](/configuration/shared/domain-evaluator/) accepts it. The original destination port is preserved.

When omitted or `null`, sniffed domains are not read or evaluated.

An explicit route `override_address` has higher priority and skips domain override. A route that only changes `override_port` still permits domain override and preserves the changed port.

#### override_with_domain.evaluator

Required. The tag of a top-level [Domain Evaluator](/configuration/shared/domain-evaluator/). There is no implicit default evaluator.

#### override_with_domain.ip_only

If enabled, override only when the original destination is an IP address.

For selector and URLTest groups, the selected final leaf and its strategy are bound atomically for each connection. A later group switch affects only new connections (unless existing connections are interrupted by the group's existing setting).
