<p align="center">
  <img src="../assets/watchman-banner.jpg" alt="Watchman — a silence watchdog for the node fleet" width="360">
</p>

# Watchman

<p align="center">
  <a href="README.md">Русский</a> · <b>English</b>
</p>

A silence watchdog for a fleet of nodes. It notices when a node stops taking
clients and says so in Telegram.

```
                 ┌─────────────────────────┐
   Watchman ─────│  Remnawave panel        │  once a minute, read only
   (a separate   │  GET /api/nodes         │
    machine)     └─────────────────────────┘
       │
       └──→  Telegram: "clients gone", "node offline", a daily summary
```

## The main rule

**Watchman is not installed on a node and changes nothing on any node.** It
only reads the panel. If watchman dies, its domain lapses or its VPS burns
down, nothing changes on the nodes.

This is not a wish but the reason it exists at all: **a watchdog living on a
node goes quiet exactly when it is needed.** A node that is down will not send
a message saying it is down. Absence of a signal cannot be sent as a signal.

## Why it watches client counts rather than missing metrics

The obvious design is to watch that a node keeps pushing metrics and raise an
alarm when it stops. That catches a dead node and **misses the case watchman
was written for**.

A node can be perfectly healthy — processes running, panel connected,
certificates valid — and still be unreachable for clients: the CDN in front of
it broke, a DNS record vanished, a route went down. Metrics keep flowing all
the while, and a metrics watchdog stays silent.

The number of people on the node collapses in both cases. That is what
watchman looks at.

And it says where to look straight away: if the panel still **sees** the node
while nobody is on it, the node is alive and the fault lies on the path to the
clients.

## Before installing

- A separate machine: **not a node and not the panel host.** An observer must
  fail independently of what it observes; watchman on the panel host would die
  together with its own data source.
- The cheapest VPS will do: one request a minute and a few megabytes of memory.
- `python3` and `systemd`. Nothing else — the standard library only.
- A Remnawave panel token allowed to read nodes.
- A Telegram bot and a chat to write to.

Watchman **opens no inbound ports at all**.

## Installation

```bash
git clone https://github.com/SkunkBG/shape.git
cd shape/watchman
sudo bash install.sh
sudo watchman
```

The installer creates the system user `watchman`, puts files in
`/opt/watchman`, enables the timer and creates the `watchman` command — the
menu. Running it again is safe: settings and accumulated history are kept.

## Configuration

Everything through the menu — `sudo watchman`:

| Section | What is there |
|---|---|
| Status | per-node table: normal level, current, watched or not |
| Panel | address and token, connection check |
| Telegram | bot, chat, topic, send check |
| Thresholds | sensitivity, windows, summary hour |
| Message samples | see what alerts look like without waiting for a failure |
| Service | timer, a single manual pass |
| Log | recent entries |

The panel address is given **without `/api`** — the path is appended
automatically. The menu fixes it even if you type it in.

Tokens live in `/opt/watchman/config.json` with mode `600` and are never shown
on screen or in the log.

## How it decides

**A node's normal level is the median client count over the last fifteen
minutes**, with the most recent three minutes left out. A median rather than a
mean, so one bad minute cannot drag the level down. Recent samples are excluded
because a collapse in progress would otherwise lower the very bar it is judged
against.

**Fleet correction.** At night the online count drops everywhere at once.
Watchman measures how far the whole fleet has sagged and compares each node
against that. Without it the watchdog would wake you every night; with it, it
stays quiet when everyone drops and alerts when one node goes to zero while the
others hold.

**Small nodes are not checked for collapse.** If a node normally has fewer than
ten people, zero proves nothing. Loss of connection is watched on every node
without exception.

**Confirmation.** An alert is sent only if the condition held for three passes
in a row. Repeats about the same node come no more than hourly. When clients
return, an all-clear follows.

## What arrives in Telegram

- **Clients gone** — the panel sees the node, but nobody is on it. With
  figures, a twenty-minute sparkline and a hint to look at the path to clients.
- **Node offline** — the panel lost it, with the panel's own error text.
- **Panel not responding** — watchman has gone blind and says so.
- **Xray restarted** — not an alarm, just a fact.
- **Daily summary** — "watchman alive", fleet figures and an expandable node
  list.

The daily summary is not decoration: **without it, watchman's own death looks
like silence, which reads as "all is well"**. If summaries stop arriving, check
watchman, not the nodes.

## Checking and maintenance

```bash
sudo watchman                                        # menu
runuser -u watchman -- python3 /opt/watchman/watchman.py --status    # table
runuser -u watchman -- python3 /opt/watchman/watchman.py --dry-run   # pass without sending
runuser -u watchman -- python3 /opt/watchman/selftest.py             # logic check
journalctl -u watchman.service -n 50                 # log
```

`selftest.py` runs the rules against invented scenarios and touches no network:
a calm fleet, a night-time drop everywhere, one node collapsing, a collapse at
night, a small node, loss of connection, a manually disabled node, an
all-clear. If you change the thresholds, run it and confirm nothing broke.

## Known limits

- **A slow decline is recognised worse than a sharp collapse**: within a
  quarter of an hour the normal level adapts. That is intended — a gradual
  decline is more likely human behaviour than a fault.
- **A node that never has anyone on it will not be checked** — there is no
  collapse from zero. Such nodes show up as small in the Status section.
- Watchman knows nothing about what happens **inside** a node: penalties,
  offenders and daily traffic digests come from the shaper's own Telegram.

## Removal

```bash
systemctl disable --now watchman.timer
rm -f /etc/systemd/system/watchman.{service,timer} /usr/local/bin/watchman
systemctl daemon-reload
rm -rf /opt/watchman
userdel watchman
```
