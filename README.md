# vault-audit-metrics

Processes incoming Vault audit logs into Prometheus metrics.

## Usage

```
Usage of vault-audit-metrics:
  -audit-addr string
        Address to listen for audit log connections on (default ":9090")
  -audit-network string
        Network to listen for audit log connections on (default "tcp")
  -cache-cleanup duration
        Interval at which expired entries in the request timestamp cache are evicted (default 1m0s)
  -cache-ttl duration
        Length of time to cache request timestamps for calculating latency (default 5m0s)
  -http-addr string
        Address to bind the HTTP server (including /metrics) to (default ":8080")
  -version
        Print version information and exit
```

## Endpoints

### `GET /metrics`

A standard Prometheus metrics endpoint. In addition to Go runtime metrics, the following custom metrics are exposed:

- `vaultaudit_cache_timestamp_cache_entries_total`: Number of request timestamp entries in the cache.
- `vaultaudit_events_requests_total`: Number of Vault requests recorded in the audit log. Partitioned by operation, path, and error.
- `vaultaudit_events_response_duration_seconds`: Latency of a Vault response. Partitioned by operation, path, and error.
- `vaultaudit_events_responses_total`: Number of Vault responses recorded in the audit log. Partitioned by operation, path, and error.

### `GET /healthz`

Health endpoint for health checks. Returns `200`, with the following response:

```json
{
  "timestamp_cache_size": 1337
}
```
