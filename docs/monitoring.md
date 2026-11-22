# Monitoring a MetalBear host

MetalBear serves Prometheus text-format metrics at `GET /metrics`, behind the
same HTTP Basic admin credential as the `com.atproto.admin.*` endpoints. The
optional stack in `deploy/monitoring/` adds Prometheus, Grafana and a
node-exporter around that endpoint for a self-hoster who does not already run
them.

## Start the stack

1. Put the admin password on the host in a file readable only by the operator,
   for example `/etc/metalbear/metrics-password`, with mode `0600`. The file
   must contain the password alone; the username is `admin`. It is mounted
   read-only into Prometheus and is never copied into the repository or an
   image.
2. Start the stack:

   ```sh
   docker compose -f deploy/monitoring/compose.yaml up --detach
   ```

   Set `METALBEAR_METRICS_PASSWORD_FILE` if the password file lives elsewhere.
3. Open `http://127.0.0.1:3001` through an SSH tunnel. Grafana is on port 3001
   because MetalBear owns 2583; Prometheus is on 9090 and node-exporter on
   9100, all bound to 127.0.0.1.

The Prometheus configuration scrapes `127.0.0.1:2583` by default. Change the
target in `deploy/monitoring/prometheus.yml` if the PDS listens elsewhere.

## What the dashboard shows

| Panel | Metric |
|---|---|
| Version, uptime | `metalbear_build_info`, `metalbear_uptime_seconds` |
| Accounts by status | `metalbear_accounts` |
| Request and error rate by route | `metalbear_route_requests_total`, `metalbear_route_errors_total` |
| Firehose sequence | `metalbear_firehose_seq` |
| Open account contexts | `metalbear_account_cache_resident`, `metalbear_account_cache_idle` |
| Host CPU | `node_cpu_seconds_total` |

`metalbear_firehose_seq` is the one worth alerting on: a PDS whose sequence has
stopped advancing while accounts are still writing is indistinguishable, from
outside, from a PDS that is down.

The dashboard is provisioned read-only from
`deploy/monitoring/dashboards/metalbear-overview.json`. To change a panel,
edit that file and recreate the Grafana container; UI edits are discarded on
restart.

## If you already run Prometheus

Nothing here is required. Add a scrape job for `/metrics` with `basic_auth` and
your own admin password, then point any dashboard at the metric names above.
The stack is optional and stays outside the main container.

The reference PDS ships a similar stack under `monitoring/` (MIT/Apache-2.0);
this one was written for the metrics MetalBear actually exposes rather than
copied wholesale.
