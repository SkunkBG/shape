# Shape monitoring

<p align="center">
  <a href="README.md">Русский</a> · <b>English</b>
</p>

Nodes expose metrics in Prometheus format. The dashboard is built for a fleet of
dozens of nodes: everything is split by `node`, so a single panel shows every
server at once.

All of it is configured from the menu: **Service → 📈 Monitoring**. The ready
`scrape_configs` snippet for the chosen path is shown there too.

## Path one: a file for node_exporter

Suitable when node_exporter is already installed on the node. No open ports and
no tokens: once a minute Shape writes `shape.prom` into the textfile directory
and the exporter picks it up itself.

In the menu — **Write a file for node_exporter**. The wizard finds the directory,
sets up the timer and checks that the file appeared. By hand, the same thing:

```bash
shaperctl.py metrics --out /var/lib/node_exporter/textfile_collector/shape.prom
```

Nothing needs adding to Prometheus — Shape's metrics arrive together with
node_exporter's, in the same job.

To check:

```bash
shaperctl.py metrics | head
curl -s localhost:9100/metrics | grep shape_
```

## Path two: the node pushes on its own

The only path that works from countries where VPNs are blocked, and from behind
NAT: once a minute the node pushes its metrics to the monitoring server over
ordinary outbound HTTPS. **Not a single inbound port is opened on the node.**

```bash
shaperctl metrics set --url https://metrics.example.com/api/v1/import/prometheus \
                      --token WRITE_TOKEN
systemctl enable --now shape-push.timer
```

Check it right away:

```bash
shaperctl metrics push
shaperctl metrics show
```

The address is given **in full, path included**: Shape does not know, and should
not know, which storage sits on the other side. The request body is the same text
that goes into the node_exporter file; every series already carries a `node`
label, so the receiver needs to add nothing, and it does not matter how many
nodes write into one place.

The token travels in an `Authorization: Bearer` header. It lives in
`/etc/shaper/config.json`, not in the systemd unit: a secret in a unit is visible
to anyone who can read `/etc/systemd`.

**Plain `http` to the outside world is refused** — the token would travel in
clear text. To `127.0.0.1` and private networks it is allowed.

If the server is unreachable otherwise, there is `--proxy socks5://…` — the same
mechanism Telegram uses.

The timer fires once a minute with a 15-second spread: 28 nodes updated at once
would otherwise all arrive in the very same second.

## Path three: through the API

Suitable when the API is already installed and the monitoring host can reach it.

```bash
sudo bash install.sh --with-api
TOKEN=$(sudo /opt/shaper/api/server.py --print-tokens | awk '/read/{print $2}')
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/metrics | head
```

For Prometheus to reach the node, the API must listen on more than `127.0.0.1`.
The right way is a private network rather than a public address: menu →
**Service → 🔗 Node API**, set the WireGuard interface address and the allowed
networks.

```
Listen address  : 10.100.0.7
Allowed addresses: 10.100.0.2/32
```

The read token is passed in a header — Prometheus does this out of the box:

```yaml
scrape_configs:
  - job_name: shape
    metrics_path: /metrics
    scrape_interval: 30s
    authorization:
      type: Bearer
      credentials: "READ_TOKEN"
    static_configs:
      - targets:
          - 10.100.0.7:8765
          - 10.100.0.8:8765
          - 10.100.0.9:8765
```

Each node has its own token. If one shared token is more convenient, set it by
hand in `/etc/shaper/api.json` during rollout; tokens can be rotated later
without downtime — the previous pair is accepted for another day.

Metrics can also be opened without a token, but only once the API is already
hidden inside a private network. Then `"metrics_public": true` goes into
`api.json`, and the `authorization` section is not needed in `scrape_configs`.

## In Grafana

**Dashboards → New → Import → Upload JSON file** and pick
`shape-dashboard.json`. On import Grafana asks for a data source — point it at
your Prometheus.

What is inside:

| Row | What it shows |
|---|---|
| Fleet | how many nodes answer, where the engine is not loaded, where the watchdog is silent, total channel, how many addresses are limited |
| Channel | download and upload per node stacked, the total of the last closed day, the derivative of the counters |
| Addresses and limits | limits over time, active addresses, personal speeds, events in 24h |
| Node health | a table: Shape version, uptime, limit, interface, whether the engine is loaded |

Annotations appear on the graphs when the engine restarts — by them you can see
whether a traffic dip is connected to an update or to something else.

## Metrics

| Metric | Type | Meaning |
|---|---|---|
| `shape_up` | gauge | metrics were collected |
| `shape_metrics_complete` | gauge | 0 — the BPF maps could not be read, the numbers are incomplete |
| `shape_info{node,version,api_version,interface}` | gauge | constant facts about the node |
| `shape_engine_loaded` | gauge | the eBPF maps are pinned |
| `shape_watchdog_active` | gauge | the watchdog is running |
| `shape_uptime_seconds` | gauge | how long the engine has been up |
| `shape_speed_limit_mbps` | gauge | the shared per-address limit |
| `shape_guard_enabled` | gauge | whether the guard is on |
| `shape_traffic_bytes_total{direction}` | counter | bytes since the engine started |
| `shape_channel_mbps{direction}` | gauge | current channel load |
| `shape_ips_known` / `_active` / `_limited` / `_personal` / `_whitelisted` | gauge | addresses in various states |
| `shape_owners_known` | gauge | for how many addresses the owner is known |
| `shape_events_24h{type}` | gauge | events in 24h by type |
| `shape_last_day_bytes{direction}` | gauge | traffic of the last closed day |

When metrics come through the API, `shape_api_up` and `shape_api_uptime_seconds`
are added — they are absent from the file path because without the API they do
not exist.

`shape_traffic_bytes_total` resets when the engine restarts — that is ordinary
counter behaviour, and `rate()` in Prometheus handles such resets itself.

## What it costs the node

One metrics collection is a dump of two BPF maps and a parse of the day's event
log. In the API the results are cached: the dump for 2 seconds, the event parse
for 30, so even polling once a second does not turn into load. The timer in the
file path runs once a minute, and on a weak node that is tens of milliseconds of
CPU time per minute.

The channel speed is computed as the difference from the previous measurement.
The measurement lives in `/var/lib/shape/metrics.state` — three numbers. That is
why it works both for a one-off CLI run and for any combination of sources: it
does not matter who measured last time, the timer or the API.
