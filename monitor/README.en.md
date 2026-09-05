# Shape monitoring server

<p align="center">
  <a href="README.md">Русский</a> · <b>English</b>
</p>

One VPS, four containers, a fleet of dozens of nodes on one screen.

```
node in Russia ─┐
node in Europe ─┼─→  https://push.<domain>  ─→  VictoriaMetrics
node behind NAT ┘         (token)                     │
                                                      ↓
    you ─→  https://grafana.<domain>  ─→  Authelia  ─→  Grafana
                                          (gate)     (own login)
```

## The rule that matters

**The dashboard only reads.** No rule on any node looks at the central source or
may depend on it. The monitoring server dies, the domain expires, the VPS burns
down — nothing changes on the nodes, the limits keep working.

This is not a promise but a property of the design: Shape has no line of code
that reads a decision from outside. The important part is not to break it later.

## Why the nodes push

Not "the server comes for the metrics" but the other way round. Three reasons,
any one of which would be enough:

- **WireGuard is blocked** — in Russia, by the fingerprint of its handshake. A
  private network between the nodes and the server simply will not come up.
- **NAT.** Some nodes cannot be reached from outside at all.
- **An inbound port on 28 nodes** is 28 places to get it wrong.

Outbound HTTPS to an ordinary domain with a real certificate is
indistinguishable from a person opening a website. The nodes open nothing.

## What you need before installing

- A VPS: **2 cores, 4 GB.** The data alone would fit in 1/2 — 28 nodes produce
  about seven hundred series, which is nothing for VictoriaMetrics. It is
  Grafana: it idles at 200–250 MB and wakes up when a dashboard covering every
  node is opened. On 2 GB it fits, but only just, and on one core it will feel
  slow.
- Docker and `docker compose` v2.
- A domain and **three names already pointing at this server**:

  ```
  grafana.<domain>   the graphs
  auth.<domain>      the login page
  push.<domain>      metrics intake from the nodes
  ```

  The records must exist **before** the first start: Caddy issues certificates
  right away, and Let's Encrypt limits the number of failed attempts.

## Installing

```bash
git clone https://github.com/SkunkBG/shape.git
cd shape/monitor
sudo bash install.sh
```

It asks for **three things** — the domain, an e-mail address and a password for
the gate — and then does the rest itself: computes the password hash, writes the
files, generates secrets into `.env` with mode 600, validates the Authelia
configuration and brings the stack up.

You do not have to invent a password: an empty answer means the installer
generates one and shows it once.

At the end it prints both passwords and the ready-made command for the nodes.
Nothing else to do: open `https://grafana.<domain>`.

## Access: two layers, and that is not paranoia

Grafana has a recognisable login page. Its version can be read off it, and known
holes follow from the version. The gate in front returns the same thing to every
unauthenticated visitor, and **from outside it is impossible to tell what stands
behind it**.

| Layer | What it is | What for |
| --- | --- | --- |
| Authelia | the gate password | strangers cannot even see that this is Grafana |
| Grafana | its own login | someone already inside the perimeter is still outside |

**There is no second factor, and that is deliberate.** There was one, and it was
removed after the first live deployment: there is no mail server, so confirmation
codes had to be dug out of a file inside the container, and registering a device
took six steps across two consoles. Protection that cannot be used does not
protect — people simply stop using it.

Bringing it back is easy once a mail server exists: in
`authelia/configuration.yml` replace `one_factor` with `two_factor` and configure
`notifier.smtp`.

A forgotten gate password does not lock you out forever: SSH access to the
machine is always there, and the user is edited in `authelia/users.yml`.

## Metrics intake: why it is not behind the gate

A node cannot go through an interactive login. So it has a route of its own with
a check of its own — and that route is **deliberately narrow**:

```
@push {
    path /api/v1/import*
    method POST
    header Authorization "Bearer {$SHAPE_PUSH_TOKEN}"
}
```

All three conditions must match. The path is restricted because VictoriaMetrics
keeps series deletion next door (`/api/v1/admin/tsdb/delete_series`): opening the
whole storage here would hand whoever holds the token the ability to erase the
history. And the token sits on 28 nodes and will leak sooner or later.

**What a stolen token buys:** writing junk metrics. Not reading, not deleting,
not touching the nodes.

One token for all nodes. A separate token per node is stricter, but that is 28
tokens to manage; at 28 nodes the trade favours simplicity, at a hundred I would
think differently.

## Setting up a node

```bash
shaperctl metrics set --url https://push.<domain>/api/v1/import/prometheus \
                      --token TOKEN_FROM_.env
shaperctl metrics push        # check right now
systemctl enable --now shape-push.timer
```

Details are in [../grafana/README.en.md](../grafana/README.en.md).

## What is inside

| Container | Version | Ports exposed |
| --- | --- | --- |
| caddy | 2.8-alpine | **80, 443** |
| victoriametrics | v1.102.0 | none |
| grafana | 11.2.0 | none |
| authelia | 4.38 | none |

Exactly one container faces outward. The rest are reachable only inside the
docker network: if Grafana ever became reachable directly, the gate would stop
meaning anything, and that could only be noticed by its consequences.

The versions are pinned deliberately. Authelia's configuration changed
incompatibly between 4.37 and 4.38, and `latest` will simply fail to come up one
morning.

## What it costs

Storage: 28 nodes × ~25 series × one sample a minute. VictoriaMetrics compresses
that down to **tens of megabytes a month**. Retention is a year, set in
`docker-compose.yml`.

Traffic: about 4 KB a minute per node, so roughly **170 MB a month** from all
twenty-eight.

## Maintenance

```bash
cd shape/monitor
docker compose logs -f caddy          # who came and with what
docker compose logs -f authelia       # login attempts
docker compose pull && docker compose up -d   # updating the images
```

A backup is two volumes and two files:

```bash
docker run --rm -v shape-monitor_vm-data:/d -v "$PWD":/b alpine \
    tar czf /b/vm-data.tgz -C /d .
cp .env authelia/users.yml /somewhere/safe/
```

`.env` and `authelia/users.yml` never reach the repository — see the `.gitignore`
next to them. Keep the copy separately: they hold the token, the passwords and
the hash of your own password.
