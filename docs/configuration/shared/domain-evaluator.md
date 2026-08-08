# Domain Evaluator

### Structure

```json
{
  "domain_evaluators": [
    {
      "tag": "dns-check",
      "server": "dns-server-tag"
    }
  ]
}
```

### Fields

#### tag

The unique tag of the domain evaluator.

#### server

The tag of a DNS server used to evaluate domain names.

If omitted, the DNS server is selected by DNS rules.

An evaluator first performs a quiet cache-only lookup. A cache miss does not delay the current connection: the original destination is used and a normal DNS lookup is started in the background. A later connection can use the evaluated domain after the lookup succeeds.

Each evaluator has independent bounded positive and negative caches. Negative results are cached for 10 seconds, and concurrent background lookups for the same domain are deduplicated.
