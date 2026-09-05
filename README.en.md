<p align="center">
  <img src="assets/banner.png" alt="Shape — per-IP speed limiter" width="820">
</p>

<p align="center">
  <a href="#installation"><img src="https://img.shields.io/badge/version-3.82-8ECA43?style=flat-square" alt="version"></a>
  <img src="https://img.shields.io/badge/kernel-Linux%205.4+-8ECA43?style=flat-square" alt="kernel">
  <img src="https://img.shields.io/badge/language-ru%20%7C%20en-8ECA43?style=flat-square" alt="languages">
  <img src="https://img.shields.io/badge/license-GPL--2.0-8ECA43?style=flat-square" alt="license">
</p>

<p align="center">
  <a href="README.md">Русский</a> · <b>English</b>
</p>

# Shape v3.82

Per-IP speed limiter for VPN nodes. eBPF + EDT.

> ### Thanks
>
> **[Gy9vin](https://github.com/Gy9vin)** — for two changes to the eBPF filter
> that found and closed an entire class of nodes where Shape simply did not
> work: **IPIP tunnel unwrapping** and **PROXY protocol parsing** for clients
> behind a CDN. Both came from his [fork](https://github.com/Gy9vin/shape),
> tests included. Thank you for reading someone else's code that carefully —
> it is a rare and very useful thing to do.

The interface speaks Russian and English — the language is asked on first run
and can be changed later: Service → 🌐 Язык / Language.

One setting: **a port and a speed in Mbit/s**. Every IP address gets its own
independent limit in both directions.

**The limit applies to an IP address, not to an account.** This matters: a whole
family behind one home router shares a single address and therefore a single
limit. The other way round, one person on a phone and a laptop on different
networks gets two independent limits. Your panel knows about accounts, the
shaper does not — it works at the network layer and only sees addresses.

Version history lives in [CHANGELOG.en.md](CHANGELOG.en.md) ([Русский](CHANGELOG.md)).

There is an optional [Node API](#node-api) for external systems — installed
separately, and Shape runs perfectly well without it.

Zero external dependencies: the system Python plus `clang`, `bpftool` and
`iproute2`. Runs on a single-core VPS with 512 MB of RAM.

**Three optional companions live alongside.** Each is installed separately and
none of them affects how the shaper works:

- **[watchman/](watchman/)** — a silence watchdog. It notices when a node stops
  taking clients and says so in Telegram. It is installed **not on a node**: a
  watchdog living on a node goes quiet exactly when it is needed.
- **[monitor/](monitor/)** — a metrics receiver: VictoriaMetrics, Grafana,
  Caddy and a second-factor gate, one command on a clean VPS.
- **[grafana/](grafana/)** — a ready dashboard for the whole fleet and a
  description of every metric.

---

## Installation

```bash
apt update && apt install -y git && rm -rf /tmp/shape && \
git clone https://github.com/SkunkBG/shape.git /tmp/shape && \
bash /tmp/shape/install.sh && shaper
```

With the optional API:

```bash
bash /tmp/shape/install.sh --with-api
```

### Requirements

| | |
|---|---|
| Linux kernel | 5.4+ |
| CPU | one core is enough |
| RAM | 512 MB is enough |
| Packages | `clang`, `bpftool`, `iproute2`, `python3` |

The installer pulls dependencies itself on apt/dnf/yum. On Debian 11/12 and
Ubuntu 22.04/24.04 everything is in the standard repositories.

### What it costs

Packet processing happens in the kernel and takes a few nanoseconds per packet —
invisible on the CPU graph even at gigabit speeds.

The noticeable part is the watchdog. Every 10 seconds it dumps two BPF maps and
parses JSON. The cost is driven by map size, not by the number of clients: LRU
maps fill up to capacity and stay full.

| Map entries | JSON | Parse per cycle |
|---|---|---|
| 8192 (default) | 1.3 MB | ~30 ms |
| 65536 | 10.6 MB | ~300 ms |

Eight thousand entries is a twentyfold margin: a node with 150 clients sees
300–500 addresses a day even accounting for mobile IPs rotating.

All in all the watchdog eats under one percent of a single-core CPU, plus about
25 MB for Python and 2 MB for the BPF maps.

**Want it even lighter?** Raise the polling interval in the auto-limiter
settings to 20–30 seconds. Detection quality barely changes, because thresholds
are counted in samples rather than in seconds.

## Updating

`shaper` → **Service** → **Update from GitHub**. The menu shows the installed
and the available version, the latest changes, and asks for confirmation.

Settings, whitelist and the limit are preserved. Before an update the current
version is copied to `/opt/shaper.bak`; if the new one fails to build, the
installer rolls back to it automatically.

The same from the command line:

```bash
rm -rf /tmp/shape && git clone https://github.com/SkunkBG/shape.git /tmp/shape
bash /tmp/shape/install.sh
```

Removal: `bash install.sh --uninstall`.
Removing only the API: `bash install.sh --uninstall-api`.

---

## Using it

```
shaper
```

<p align="center">
  <img src="assets/screenshot.png" alt="Main screen" width="760">
</p>

```
  ⚡ Shape · per-IP speed limiter
  ────────────────────────────────────────────────────────────
  🟢  Shaper    running    interface ens3
  🔁  Autostart on         survives a server reboot
  🚀  Speed     50 Mbit/s  for every IP address
  🔌  Port      443
  🚦  Auto-limit on        both ways ↓5 ↑1.5 Mbit/s 10 min → 1 Mbit/s for 60 min
      or 11.2 GB an hour · 150 GB a day · upload over 50%
  ✉️   Telegram   on         node label: Node-1
  🛰  Remnawave  connected  disables the subscription after 60 min
  🔑  API        running
  ────────────────────────────────────────────────────────────
```

The main screen shows **everything that is on and off**, so there is no need to
walk into the sections and check them one by one.

The bottom three lines are about links to the outside world. "On" there means a
working configuration rather than a checkbox: Telegram without a token or a chat
is shown as off, and so is a panel without a UUID. Half a configuration is worse
than none — one is sure it works when it does not.

### Setting a limit

Menu → **🎚 Speed limit**. Pick a ready value or type your own, then confirm the
port. The menu lists the ports processes are actually listening on, so you don't
have to guess.

### Monitor

Menu → **📡 Monitor**. Live per-IP speeds, a one-minute average and how long the
address has been holding the load:

```
  Monitor                                      refresh 2 s · Ctrl+C to exit
  ────────────────────────────────────────────────────────────────────────────
   Channel now     ↓   54.1   ↑  10.4 Mbit/s   ▂▃▄▅▅▆▇█████  last minute
   Limit per address  10 Mbit/s   for every IP    loading 58 of 377
  ────────────────────────────────────────────────────────────────────────────
   IP                       now  upload packet     data     avg    total holding  share of limit
 ▪ 203.0.113.34           10.1     0.1    140       2%     3.1  12.4 GB  12 min  ████████████
 ▪ 203.0.113.17               9.8     0.2    150       1%     9.6   8.1 GB  44 min  ███████████▉
   203.0.113.21              6.4     0.2    130       3%     1.1   1.2 GB       —  ███████▊····
 ✓ 203.0.113.40             5.1     0.4    160       4%     4.8   3.0 GB   5 min  ██████▏·····
   203.0.113.22              1.4     2.7   1310      91%     1.7  22.8 GB       —  █▊··········
 ⊘ 203.0.113.16             1.0     0.0    120        —     4.3  412 MB        —  █▎··········
  ────────────────────────────────────────────────────────────────────────────
   showing 20 of 68   ▪ holding over 30 s   ✓ whitelisted   ⊘ limited
   packet — average upload size in bytes; from 600 it is data, not acknowledgements
   data — share of the daily upload sent in large packets; from 55% it is no longer acknowledgements
   total — transferred since the engine loaded, down and up together
```

The **packet** column is the average upload packet size. That is the figure
which tells seeding apart from an ordinary download, and it does not depend on
the channel speed: acknowledgements take 100–170 bytes, data takes over a
thousand. In the sample above everyone sits around a hundred and fifty, and
only 203.0.113.22 shows 1310.

**Row colour is the share of the limit:** grey up to 20%, green to half, yellow
to 80%, red above. The upload column has its own scale: mobile carriers give a
narrow uplink, so noticeable upload is the first sign of seeding. In the sample
above 203.0.113.22 downloads only 1.4 Mbit/s but uploads 2.7 — that is what a
torrent looks like.

The **data** column answers the same question over a day rather than a moment.
The packet size jumps from window to window: someone sends an attachment in a
messenger and it reads over a thousand for ten seconds. The share knows no
jumps.

The two columns diverge exactly for the addresses worth a look: a high packet
with a low share means a burst; a low packet with a high share means it is quiet
now but the day was spent seeding. Grey up to 55%, yellow from 55 (the
watchdog's threshold), red from 80. A dash means there was no upload at all
today — which is not the same as zero percent.

The **total** column is how much the address has transferred since the engine
loaded, down and up together. Speed shows the present moment, and "0.1 Mbit"
looks the same for someone who moved twenty gigabytes today as for someone who
just connected. It turns yellow from 5 GB and red from 20. In the sample above
203.0.113.22 downloads only 1.4 Mbit/s but has already moved 22.8 GB.

The **avg** column is the average speed over roughly a minute, **holding** is
how long the address has stayed above half the limit. Together they separate a
steady multi-hour load from a short burst.

**The mark on the left:** ▪ holding load for over 30 seconds, ✓ the address is
whitelisted, ⊘ the address is already limited. The sparkline in the header is
the channel over the last minute.

Whitelisted addresses are shown alongside the rest: the limit does not apply to
them, but the load they create is just as real and worth knowing about. They
used to be invisible everywhere.

### Why "now" sometimes exceeds the limit

The monitor shows 128% and even 202% of the limit. That is not the limiter
failing but a consequence of where bytes are counted.

The counter increments when a packet **enters** the shaper, not when it reaches
the client. Downloads are paced by `fq`: a packet is given a departure time and
waits its turn. A burst arrives, the counter has already counted it, and the
client receives it spread over the following seconds.

The neighbouring column proves it: the address showing 202% had **avg** of
2.5 Mbit against a 10 Mbit limit. The one-minute average always stays under the
limit — that is what actually arrives. "Now" is an instantaneous sample, and
spikes in it are normal.

That is usually enough to spot a downloader without any auto-limiting at all.

---

## Auto-limiting heavy users

A global limit does not stop torrents: a person simply holds their 10 Mbit/s
around the clock. The watchdog catches exactly that.

Every 10 seconds it samples each IP and decides on a combination of signals
rather than a single threshold. Everything is configurable: 🚦 Auto-limit.

### The mandatory condition

**Traffic in both directions at once** — at least half of the limit down, at
least 15% of it up, for ten minutes in a row. Without this no penalty is issued
at all, no matter how heavy the traffic is.

The condition rests on a simple observation: a torrent is about the only
everyday activity that pulls data down *and* up for hours. Streaming is silent
upward, cloud backup is silent downward, a plain download is silent upward —
none of them pass the check, so none of them are ever punished.

The thresholds differ on purpose. A torrent takes **all** the available
download, while a video call holds a modest 2–3 Mbit/s. The upload threshold is
low because mobile carriers give only 3–20 Mbit/s up, and with a 10 Mbit limit
seeding uses just a third of the channel.

### Points

| Signal | Points |
|---|---|
| Large packets going up (>600 B) | +2 |
| Pinned at the download ceiling | +1 |
| More than 4 hours of activity per day | +2 |
| More than 2 GB uploaded per day | +1 |

A penalty is issued at three points.

The key signal is the **average upload packet size**, and it is the only one
independent of channel speed. A client that only consumes sends bare ACKs of
40–80 bytes upward. A client that seeds sends data of 1200–1400. That twentyfold
difference is the same at 3 Mbit and at 20.

### Verified by simulation

| Scenario | Result |
|---|---|
| YouTube 1080p on a phone | clean |
| YouTube 4K on a TV | clean |
| Three-hour video conference | clean |
| Cloud backup | clean |
| Downloading a 5 GB ISO | clean |
| Online gaming | clean |
| Torrent at 3, 5, 10, 20 Mbit uplink | limited after 10 min |
| Torrent with pauses | limited after 23 min |

### Why you cannot simply lower the upload floor

The obvious rule suggests itself: "downloading and uploading more than one
and a half megabits at the same time means seeding". It does not work, and
here is why.

Downloading generates an upstream flow all by itself — acknowledgements. Their
volume **grows together with the download speed**:

```
37.9 Mbit/s down  ≈ 3400 packets/s
                  ≈ 1700 acknowledgements/s upstream
    wrapped by Reality at 130–170 bytes each
                  ≈ 1.5–2.0 Mbit/s of "upload"
```

So an ordinary download on a 50 Mbit node already produces about two megabits
upstream, and twice that on a 100 Mbit one. An absolute threshold would catch
it along with the seeding.

**Packet size tells them apart**, and it is the only figure that does not
depend on the channel speed:

| | average upload packet |
|---|---|
| acknowledgements | 100–170 bytes |
| seeding data | 1200–1400 bytes |

That is why the torrent preset lowers the upload floor to 3% **together with**
the large-packet requirement: `--require-packet on`. With it the two-way
counter does not grow while upstream packets stay short — no matter how many
megabits of acknowledgements pile up.

The switch is available on its own from the command line:

```bash
shaperctl guard --both-ul 3 --require-packet on
```

Without it, lowering the upload floor below 10% is a bad idea.

### Hours of upload

The only signal that measures not "how much" but **"how long"** — and that is
exactly where a torrent differs from work.

```bash
shaperctl guard --upload-hours 6
```

- Three gigabytes at 50 Mbit take **eight minutes**.
- An archive for a client, twenty.
- Seeding runs for twelve hours, sixteen, around the clock.

A sample counts when three conditions hold. Each one filters its own class.

| Condition | What it filters |
| --- | --- |
| upload above 0.05 Mbit/s | noise |
| upload at least 20% of the download | acknowledgements of an ordinary download |
| upstream packet from 1000 B (`--ratio-needs-packet on`) | conversations and video calls |

Acknowledgements are filtered by share, not by rate, and that matters. Their
volume is set by download speed, not by the person: at 10 Mbit down they come to
0.33 Mbit up, at a gigabit to more than three. Any rate floor high enough for a
fast link eats the quiet seeder along with them. Their share of the download is
structurally 3-5% at any speed, and a 20% threshold leaves a fourfold margin.

No download in the sample at all — the second condition passes at once: that is
what pure seeding looks like.

The third condition is optional. On QUIC nodes (Hysteria2) packets are small for
everyone and `ratio_needs_packet` is turned off there — the hours signal then
loses its protection against conversations, but stays independent of the
protocol: the share works the same on QUIC as on TCP.

**There is no penalty for this and there will not be one.** A phone's first
backup is indistinguishable from seeding by every signal we have: someone who has
just switched on the upload of ten years of photos pushes a hundred gigabytes for
a whole day, and the proportion, the data share and the hours all line up.
The only thing that tells them apart is that a backup ends and seeding does not —
and we do not count that.

So the signal arrives as a notice, and the decision stays with you.

### Upload on nodes where traffic is paid for

There the bill covers **both** directions, while the limit covered only the
download — and the budget leaked the other way.

```bash
shaperctl guard --upload-gbh 3 --upload-day 25
```

A mirror of the download thresholds, with the same numbers. And the question that
troubled us throughout this section — torrent or backup — **does not matter here
at all**: a gigabyte costs the same, whatever it is.

Intent matters only where the traffic is free.

### Daily upload: two levels

The simplest signal, and the only one that depends on neither proportion, nor
packet size, nor protocol.

```bash
shaperctl guard --upload-warn 10 --upload-day 30
```

**10 GB uploaded in a day — a Telegram notice. The speed is not cut.** One
message per address per day.

```
🔔 Heavy upload · Node-1

👤 Daria · @maria_p
🆔 Telegram: 100000002
🔑 Panel login: user_100000002 · #102

📍 Address: 203.0.113.7
10.5 GB uploaded in 24h — the notice threshold is 10 GB
📈 For the day: ↓ 3.9 GB · ↑ 10.5 GB (269%)
📦 Upload over 6.0 h: 96% as data · packet 1255 B · max 1408

No limit applied, this is a warning. At 30 GB the speed will be reduced.
```

**30 GB — a limit.** With the usual penalty, like the other signals.

**Why this beats the other signals.** The upload ratio catches disproportion —
and therefore touches conversations, where both sides send equally. The data
share catches large packets — and therefore depends on whether the kernel merges
them and which protocol the node runs. Thirty gigabytes up is just thirty
gigabytes up, and it can be explained to a customer in one sentence.

The notice level exists precisely so you can see who is approaching the line
before they cross it, and decide for yourself.

The home preset sets 10 and 30. **The mobile preset sets neither** — there the
channel is the ceiling anyway, and such numbers are meaningless at ten megabits.

### The quiet seeder and the upload ratio

Torrents look different in three ways, and no single rule catches them all:

| How it looks | What catches it |
| --- | --- |
| Downloading and seeding at once | the two-way condition, instantly |
| Downloading hard, seeding off | volume per hour or per day |
| Seeding half a megabit for days | **the upload-to-download ratio** |

The third one falls through everything else. Instant thresholds are too high
for it, and the absolute upload volume is too small: 900 MB a day against a
two-gigabyte threshold. Yet it uploaded 2.4 times what it downloaded — and
nothing but seeding behaves that way.

```bash
shaperctl guard --upload-ratio 50 --upload-ratio-mb 3000 --upload-ratio-hours 2
```

Uploaded more than half of what was downloaded in a day, with at least 3 GB of
upload, and sent data for at least two hours — penalty. The path is independent:
the two-way condition is not checked, otherwise a quiet seeder would never reach
it.

**The hours condition arrived in 3.65 and it is required.** The ratio catches
disproportion but says nothing about how long it took to build up. A live case on
a mobile node: 418.8 MB down, 326.0 up, ratio 78%, data share exactly 55% against
a threshold of 55 — and all of it within two hours. A video sent to a chat looks
exactly like that, and by proportion it is indistinguishable from seeding.
Duration is what tells them apart.

The hours come from the same counter as the `--upload-hours` signal, where only
**data** upload is counted: acknowledgements and conversations do not get in.
To switch the condition off: `--upload-ratio-hours 0`.

**The threshold differs between home and mobile nodes: 50% against 35%.**

Thirty-five was chosen from a distribution over 6143 addresses: honest clients
ended at 25%, seeders started at 45%, and in between it was empty. Thirty-five is
the middle of that emptiness.

The first confirmed false positive landed inside it: a marketer uploading work
files reached 38% and got penalised.

Once statistics from two nodes accumulated, the picture sharpened. The 300 MB
lower bound on upload volume cuts off more than half the list, and only a few
addresses actually reach the ratio check:

```
392%  seeding
229%  seeding
 75%  seeding
  ·   ← empty
 38%  the marketer, a false positive
```

Fifty is the middle of that gap. On mobile nodes the threshold is left as it
was: there is neither statistics nor work uploads there.

**But the person has to be there.** The signal is counted from daily
counters, while the kernel map is an LRU of 8192 entries: an address that
downloaded in the morning and left at noon sits there until midnight along with
its figures. Without an "is uploading right now" condition the penalty went to
an address nobody was behind — the panel does not know such an address, there is
no point to it, and if the address has been reassigned an innocent person
suffers. The liveness floor is low, 0.05 Mbit/s: a real seeder uploads
continuously, one that left uploads nothing.

**No second penalty for the same thing.** A daily counter never goes down, so a
penalty that expired after an hour used to be handed out again ten seconds later
— and so on until midnight. Lifting a limit by hand did not help, for the same
reason.

Now the counter the person was caught on is recorded at penalty time. A second
penalty for the same signal happens only if the counter **grows by another
quarter**. Someone who keeps seeding returns in an hour or two; someone who
stopped does not return at all. `shaperctl release` works the same way: until
midnight, or until a quarter more volume. The rule covers the three daily
signals — the ratio, daily upload and daily download; hourly windows are cleared
separately.

**Why the ratio and not gigabytes.** For an ordinary client, upload is TCP
acknowledgements, and their share is set by packet size rather than by human
behaviour: 5–15% of the download, at ten megabits or at a gigabit. It never
rises above half, whatever the download. On a live node with six thousand
addresses the gap looked like this:

```
916 MB / 379 MB  = 242%   ← seeding
756 MB / 857 MB  =  88%   ← seeding
489 MB / 1015 MB =  48%   ← seeding
500 MB / 1.1 GB  =  45%   ← seeding
280 MB / 1.1 GB  =  25%
213 MB / 1.0 GB  =  21%
…everyone else      2-17%
```

The threshold sits at **35%** — in the middle of the gap between 25% and 45%.

### Where to see the distribution

```bash
shaperctl status --ratio    # distribution of the upload ratio
shaperctl status --bulk     # distribution of the data share in uploads
```

The second shows the same for the second signal: how much of each address's
upload went in large packets. Counted from the daily counters, for the current
day.

```
  Distribution of the data share in uploads
  addresses: 339 · upload from 100 MB · for the current day
      0-10  ████████████████████████ 122
     10-20  ████████ 43
     20-30  ███████ 38
     30-40  ███████ 35
     40-50  · 0
     50-60  · 0
     60-70  · 0
     70-80  ██████ 30
     80-90  · 0
       90+  ██████████████ 71
```

The emptiness between 40 and 70 is where the threshold goes. The same way the
ratio threshold was chosen: not from theory, but from where the live data has a
gap. Menu: **Statistics → 📦 Data share in uploads**.

```
Upload-to-download ratio
addresses with at least 100 MB uploaded: 17
    0-10  ████████████████████████ 8
   10-20  ███████████████ 5
   20-30  ███ 1
   30-40  · 0
   40-50  ██████ 2
   50-75  · 0
  75-100  ███ 1
```

The empty bucket in the middle is the gap. It shows where to put the threshold:
every node has its own client profile, and there is no need to guess a number.
In the menu: **Statistics → 🔍 Upload ratio**.

The volume floor is mandatory: an address with 10 MB down and 8 MB up has a
ratio of 80%, and that means nothing.

The signal is **off** by default — enabled by a preset or by hand.

### Volume thresholds

Two-way load catches a torrent that seeds. A client with seeding disabled only
sends block requests and never passes the mandatory condition — and that is
honest: **a torrent with seeding off is indistinguishable from an ordinary heavy
download at the network layer.** No signal can give it away, because there is
nothing to give away.

Volume gives it away. Two independent thresholds, both bypassing the mandatory
condition.

**Per hour** is the fastest signal. At a 10 Mbit/s limit an hour at full speed
yields exactly 4.5 GB, so a threshold around three means "held the channel for
two thirds of an hour". A download hits it in 40 minutes.

**Per day** is insurance against someone spreading the load thin.

Both are set in the menu, `0` disables them. By default the hourly one is off
and the daily one is 50 GB.

### Why the hour matters more than the day

A daily threshold punishes duration, an hourly one punishes intensity. Ten hours
of YouTube at 1080p is 18 GB: any daily limit below twenty punishes a person who
never once exceeded a reasonable speed.

The hourly threshold does not have this problem. The 1080p bitrate is 1.8 GB per
hour — half of a three-gigabyte threshold — so you can watch all day.

That is why the hourly rule should be the main one and the daily one should be
kept high, purely as a backstop.

### Presets: two, by node type

Both do the same job — torrents and shared subscriptions. Only the channel
differs, and what sits behind it.

| | 📱 Phones | 🖥 Home internet |
| --- | --- | --- |
| Per-address limit | usually 10 Mbit | usually 50–100 Mbit |
| Volume per hour | **3 GB** fixed | **half the channel** |
| Daily upload | — | **10 GB notice, 30 GB limit** |
| Hourly upload | **3 GB** | — |
| Daily upload | **25 GB** | 30 GB |
| Hours of upload per day | **notice from 6** | **notice from 6** |
| Hourly volume is a reason on its own | yes | **only with upload packets** |
| Volume per day | 25 GB | 150 GB |
| Sharing: addresses | over 20 | over 20 |
| Torrents | two-way traffic with large upload packets | same |
| Quiet seeders | **35%** a day | **50%** a day |
| Penalty for a torrent | 1 Mbit/s for 60 min | same |
| Penalty for volume alone | 1 Mbit/s for 60 min | **a third of the channel** |
| Sharing | 1 h cut-off, then the subscription is disabled | same |

**Why phones get a number and homes get a share.** Three gigabytes an hour is a
figure computed for a phone: 1080p fits twice over, and a download hits the
threshold in forty minutes. On a 100 Mbit node those same three gigabytes are
one film — the threshold would catch everyone. So at home it is derived from the
channel: half the bandwidth for an hour leaves video alone and still catches a
bulk transfer.

The daily figure at home is sixteen such hours — eight hours at full speed.
Any less will not do: one Steam game weighs some 120 GB, and on fifty megabits
eight hourly thresholds simply were not enough for it.

**The sharing threshold is the same on both nodes — twenty addresses.**

It differed while home nodes were assumed to be opened from wifi only. That is
wrong: mobile clients connect to any node, and a carrier changes the address on
reconnect and on handover. A family of five phones easily produces fifteen to
twenty addresses in ten minutes.

So the threshold is about the client, and the client is unknown to us. We take
the larger value. Real resellers meanwhile show 146 and 230 addresses, a tenfold
margin.

**How far back the node remembers can be measured.** There is no record lifetime
either in the panel documentation or in its environment variables: the connection
list is a live snapshot from Xray. So `panel show` prints the age of the oldest
address from the last poll, and warns when it is shorter than the window: the
window is then capped by the node, not by the setting.

A preset configures **both the auto-limiter and sharing** at once. Leaving the
other half of the policy to a different screen meant forgetting it — which is
exactly what happened.
### A Steam purchase is not a torrent

An hourly threshold set as a share of the channel fires **after exactly thirty
minutes at full speed** — on any channel, because that is what a half means:

| per-address limit | a full hour at that speed | threshold | fires after |
|---|---|---|---|
| 10 Mbit/s | 4.5 GB | 2.2 GB | 30 min |
| 50 Mbit/s | 22.5 GB | 11.2 GB | 30 min |
| 100 Mbit/s | 45 GB | 22.5 GB | 30 min |

A modern Steam game weighs about 120 GB, and the heaviest reach 235. So a person
who honestly bought one got penalised after half an hour — and then fell into a
cycle: thirty minutes fast, an hour crawling, thirty minutes again. The game
took eight hours instead of three, and the node owner got five notifications
about an honest customer.

**A store download cannot be told from a torrent by volume.** By upload packet
size it can, and Shape already measures that:

| | Steam | Torrent |
|---|---|---|
| Upload as a share of download | 1–3% | 20–200% |
| Upload packet size | 100–170 B, acknowledgements | 1200–1400 B, data |
| Duration | it ends | for days |

So in the home preset the hourly volume **stopped being a standalone reason**:
it also needs large upload packets. A torrent produces them, a store download
does not.

The cost is known and accepted: a torrent with uploading turned off entirely
will not be caught within the hour, because at the network layer it *is* an
ordinary download. The daily threshold catches it, where 300 GB in a day is no
longer "bought a game".

**Second: the penalty for volume got softer.** Volume is the one signal that
fires on honest behaviour too, so cutting to messenger-grade 1 Mbit/s for it is
not acceptable. The home preset sets a third of the channel:

| limit | penalty for volume alone |
|---|---|
| 50 Mbit/s | 15 Mbit/s |
| 100 Mbit/s | 30 Mbit/s |

The download does not die from that — it just finishes slower — but the channel
no longer suffers. If torrent signals fired alongside the volume, the usual
1 Mbit/s penalty applies.

Both settings are visible on the auto-limit screen and editable by hand: entries
`[13]` and `[14]`, or `--volume-needs-upload on|off` and `--volume-mbps` on the
command line.

On mobile nodes both are deliberately off. There the 3 GB/h threshold is "what a
person needs", not "what fits in the channel", and game downloads are beside the
point: on ten megabits a game takes a day regardless.
### Reading the verdict

The limited list shows exactly which signals caught the person:

```
  IP                         at    remaining   why
  ────────────────────────────────────────────────────────────
  203.0.113.23             20:48       11.1 h   downloaded gigabytes within an hour
  203.0.113.42            20:33       46 min   sends real data, not just ACKs,
                                               holds the download ceiling
```

Newest first, with the time the penalty was issued in the "at" column.

This helps you tune the thresholds and answer clients with specifics. Limited
addresses live in their own menu entry with a counter; you can release one or
all of them. Penalties survive a service restart and a server reboot.

---

## What it can and cannot do

**It cannot** tell a torrent from anything else. Inside VLESS/Reality on port
443 all traffic is a single encrypted TLS stream: there is no BitTorrent
handshake and no tracker ports to see. No L3/L4 tool can see that, by design.

**It can** do exactly what is needed: hold an honest speed ceiling per user so
that one downloader does not take the channel from everybody else. Whether they
are pulling a Windows image or watching YouTube makes no difference — the
ceiling is the same.

---

## How it works

```
Packet on the interface
   │
   ├─ limit set?          no  ──► pass
   ├─ IP whitelisted?     yes ──► pass
   ├─ port in the list?   no  ──► pass
   │
   ├─ Download (egress) : EDT — the packet is given a departure time and
   │                      fq holds it back. Dropped only past the horizon.
   └─ Upload  (ingress) : Token Bucket — excess packets are dropped,
                          TCP shrinks its window by itself.
```

EDT (Earliest Departure Time) instead of classic queues means the speed is
shaped smoothly: packets are not thrown away, they are spread evenly over time.
For video and calls that is noticeably nicer than dropping.

It is not entirely lossless. If the queue pushes departure more than two seconds
ahead, the packet is dropped after all: holding it longer is pointless, since by
then the sender has already given it up for lost. Two seconds is also the
ceiling on the delay EDT can add. An address carries a single departure stamp
for all of its flows, so a heavy download pushes back the same client's own call
packets too.

The port is matched strictly by direction: on download only `sport` is compared,
on upload only `dport`. Otherwise a rule for "443" would also catch the node's
own outbound traffic to other people's sites, where `dport=443`.

Port `0` means "all ports", and it carries more consequences than it looks.
It covers more than SSH and the node's own service traffic. The egress key is
the destination address — and for the node's own outbound connections that is
the remote site. So a popular site gets **one client's limit applied to the
entire node**, and the monitor fills with foreign addresses instead of client
ones. Don't set this rule without a reason.

State maps are LRU: once they hit 8192 addresses the kernel evicts the least
recently used ones on its own. No background cleanup needed.

The shaper sees packet sizes as the kernel hands them over, and the kernel
coalesces inbound packets (GRO) and passes outbound ones as a single chunk
before segmentation (GSO). Bytes and rates are unaffected, but the "average
packet size" is a post-coalescing figure, not what travels on the wire. The
auto-limit packet-size thresholds are calibrated on exactly those values, so
`ethtool -K <iface> gro off` invalidates them.

---

## When the client addresses are not visible

Both changes in this section come from **[Gy9vin](https://github.com/Gy9vin)**.
He found two cases where Shape was not merely working badly — it was not
working at all, and the symptoms gave almost nothing away.

### IPIP tunnels

Some hosters hand the node its public address through a tunnel. On the external
interface every packet is wrapped in an extra IP header with protocol 4. The
shaper sees "not TCP, not UDP" and lets **all** of that node's traffic past
without accounting or limiting. From outside it looks like "Shape is installed,
it limits nothing, and the monitor is empty".

### Clients behind a CDN

A CDN terminates the client's connection at its own edge and opens a separate
one to the node. At the packet level the sender is the relay, so **every client
behind it shares a single limit**. The real address arrives in the PROXY
protocol header — the first bytes of the stream, the same ones Xray reads with
`acceptProxyProtocol`.

### Why a list, not a switch

In both cases the real address comes from data written by the sender. Unwrapping
that for just anyone is not an option: whoever opens a connection to a shaped
port could prepend a header and pick which address gets charged — evading their
own limit and pushing someone else's address into a block.

Hence a list of who may be trusted. **While it is empty, neither unwrapping runs
at all** — the key comes from the IP header, as always.

```bash
shaperctl trusted add 198.51.100.7  --tunnel   # far end of the IPIP tunnel
shaperctl trusted add 198.51.100.20 --relay    # CDN relay
shaperctl trusted list
```

The tunnel address is visible in `ip -d link show`; the relay address is known
to whoever configured the CDN. The list lives in `/etc/shaper/trusted.txt` and
is reloaded on every engine start.

One address can carry both kinds if it really is both a tunnel and a relay — but
that is rare, and worth confirming first.

---

## Units

Speed is in **Mbit/s** everywhere, the way providers write it. Inside eBPF it is
stored as bytes per second, which the EDT arithmetic needs. The conversion is
`bytes/s = Mbit/s × 125000`, decimal megabits.

For reference: a call is 4 Mbit/s, YouTube 1080p is 10, 4K is 25.

The limit applies to each IP address separately. Fifty people at 15 Mbit/s is up
to 750 Mbit/s on the channel if they all download at once.

---

## CLI

The installer puts two commands in `/usr/local/bin`: `shaper` is the menu,
`shaperctl` is everything else. For compatibility with older notes an alias
`shaperctl.py` sits next to it and does the same thing.

```bash
shaperctl show                          # current settings
shaperctl apply --ports 443 --speed 15  # set the limit
shaperctl apply --speed 0               # remove the limit
shaperctl apply --ports 443,8443        # change ports only

shaperctl monitor                       # live load monitor
shaperctl monitor --interval 5          # refresh less often

shaperctl status                        # accumulated traffic per IP
shaperctl status --live                 # + current speed over 3 s
shaperctl status --full                 # all IPs
shaperctl status --json                 # for your own scripts

shaperctl whitelist add 203.0.113.10
shaperctl whitelist list

shaperctl trusted add 198.51.100.7 --tunnel   # IPIP tunnel endpoint
shaperctl trusted add 198.51.100.20 --relay   # CDN relay
shaperctl trusted list

shaperctl guard --enable --score 3 --both-min 10
shaperctl guard --both-dl 50 --both-ul 15 --packet 600
shaperctl guard --hours 4 --upload-gb 2 --penalty-mbps 1 --penalty-min 60
shaperctl guard --disable
shaperctl limited                       # who is limited right now
shaperctl release 203.0.113.42          # release one
shaperctl release --all                 # release everybody

shaperctl export --out /root/node.json  # back up node state
shaperctl export --out /root/node.json --with-secrets   # token included
shaperctl import /root/node.json --dry-run              # what would change
shaperctl import /root/node.json                        # restore
shaperctl import /root/node.json --only whitelist,owners

shaperctl telegram backup                # send a backup right now
shaperctl telegram set --backup on --backup-day 1
shaperctl telegram set --backup-thread 777

shaperctl panel show                     # the Remnawave panel link
shaperctl panel test                     # check the link, change nothing
shaperctl panel scan --dry-run           # look for sharing, do nothing
shaperctl panel set --url … --token … --node-uuid …
shaperctl panel set --action-set notify,limit --mbps 1 --minutes 60
shaperctl panel set --threshold 20 --window 10 --exempt 97,346
shaperctl panel report                   # send the node report now
shaperctl panel set --report on --report-at 09:00 --report-thread 777
shaperctl panel set --resolve off        # do not resolve names
shaperctl panel who 203.0.113.20            # whose address is this, per the panel
```

The `status --json` format:

```json
{
  "ip": "203.0.113.42",
  "downloaded_bytes": 5368709120,
  "uploaded_bytes": 419430400,
  "download_mbps": 14.8,
  "upload_mbps": 1.2,
  "idle_sec": 0.4
}
```

---

## Checking it

```bash
shaper                              # → Service → Check the environment
tc filter show dev ens3 egress      # the bpf filter should be visible
shaperctl status --live          # real per-IP speeds
```

Empty statistics while clients are online means the limit sits on the wrong
port. Look at what processes are actually listening: `ss -tulnp`.

---

## Telegram notifications

Off by default. Configured in the menu, entry **[5] Telegram**.

They send **events, not reports**. An address gets limited — one message with
the reason. Once a day — a digest for the day that just ended. That comes out to
5–20 messages a day instead of a stream people stop reading after a week.

```
🚦 Limited · RU Moscow

👤 Ivan · @ivan_k
🆔 Telegram: 100000003
🔑 Panel login: user_100000003 · #101

📍 Address: 203.0.113.42        ← a link to ipinfo.io
🐌 Speed reduced to 1 Mbit/s for 4 h
Reason: downloaded gigabytes within an hour
📈 For the day: ↓ 40.0 GB · ↑ 409.6 MB (1%)
📦 Upload over 6.2 h: 0% as data · packet 150 B · max 210
```

**The figures line answers "but what for, exactly".** The reason names the rule,
but does not say whether this was a torrent or someone uploading a backup to the
cloud. Three numbers do:

| | What it was |
| --- | --- |
| ↓ 40 GB · ↑ 0.4 GB (1%) · packet 150 B | a download: only acknowledgements go up |
| ↓ 1.5 GB · ↑ 1.0 GB (67%) · packet 109 B | small packets both ways: calls, games |
| ↓ 2.1 GB · ↑ 3.4 GB (162%) · packet 1310 B | seeding: data goes up |
| ↓ 0.1 GB · ↑ 5.0 GB · packet 1400 B | a cloud upload: almost nothing comes down |

There are two packet sizes, and the one to read is the **maximum**.

The daily average is arithmetic, and a stream carries an order of magnitude more
small packets than large ones: 440 MB in 1400-byte chunks plus 550 MB in 60-byte
acknowledgements average out to 109. That number cannot tell you whether the
person uploaded data — which is exactly what is needed.

The maximum is the largest average packet over any ten-second window in the day.
If it ever reached 1300, data chunks were going up. If it never did, they were
not, whatever the upload was.

| The line | What it was |
| --- | --- |
| ↑ 997 MB (67%) · upload packet 109 B | no data went up at any point |
| ↑ 997 MB (67%) · upload packet 109 B (max 1340) | it did, it just drowned in the average |

The maximum is only updated on samples with more than 20 KB uploaded: a handful
of stray packets must not set it, yet a quiet seeder on half a megabit must
still land in it.

**But what decides is the share, not the maximum.** The maximum is a "it got
there once" mark, and a single ten-second window sets it: send a video in a
messenger and for the rest of the day your calls pass the filter as seeding. So
how many bytes of the upload went in packets of 1000 and above is counted too:

```
📈 For the day: ↓ 146.7 MB · ↑ 976.1 MB (665%)
📦 Upload over 11.9 h: 96% as data · packet 1279 B · max 1400
```

The distribution across two nodes, 26 addresses:

```
    0-39   ███████████████ 15    calls sit at 1-6%
   40-65   ·  none
   66-100  ███████████ 11        seeding
```

The threshold sits in the middle of the gap — **55%**. To see the distribution:
`status --bulk`.

It moved three times, each time because the previous value had been set from too
small a sample: 30, from three Telegram cards — and a video call passed it with
32. Then 70, from the same three points but from the other side; it sat not in
the middle of the gap but flush against the lower edge of the upper cluster, and
the first below-average seeder (66% at a 392% ratio) did not make it in.

The general lesson: **a threshold set from a handful of observations is almost
certainly in the wrong place.** The 35% ratio threshold landed correctly on the
first try only because it was chosen from 6143 addresses.

**Both presets require that share for the ratio signal.** Uploading more than
35% of the download in a day is not enough; the upload must also have been data.

The manual toggle is entry `[15]` on the auto-limit screen, or
`--ratio-needs-packet on|off` on the command line.

**A gigabyte here is exactly one billion bytes**, not 2^30. That is how an ISP
counts, that is what the tariff says, and that is how every threshold is set.
While the display divided by 1024 and the thresholds by 1000, the two diverged by
seven percent, and it looked like a broken rule: a card saying "286.2 MB
uploaded" against a 300 MB threshold, when the threshold had in fact been
crossed.

**There are two lines, and their periods differ.** Volumes are counted over the
day, while the packet field is reset on a format change, so right after an update
it covers minutes. The second line therefore always states its own period
honestly instead of inheriting "for the day" from the first.

The bytes and the packets behind that average live in **one field of two
numbers**, not in two fields. Two fields can be had by halves — a record from an
earlier version that held only one of them — and the division then yields
nonsense: "upload packet 168750 B" against a physical maximum of fifteen
hundred, or "11 B", which does not happen at all. One field is either absent
entirely or present entirely.

Plus plausibility bounds on **both** sides, from 40 bytes to a jumbo frame. A
value outside them is not printed: lying is worse than saying nothing.

Who this is comes from the panel. When it does not, the card says **why**
instead of blaming the configuration:

| What the message says | What it means |
| --- | --- |
| the panel link is not set up on this node | the panel is off on this node |
| the panel has never answered yet | the watchdog has just started, or the panel is unreachable |
| the panel has not answered for N min | set up but unreachable — check `panel show` |
| at the last poll (N min ago) this address was not among the connected ones | the person was not on the node then |

All three used to print the first line, which sent you looking for a fault in
the wrong place. The address and the reason are there either way.

**The name is not lost even once the panel no longer sees the address.** The
panel knows a person only while they are on the node: twenty minutes after an
identification the same card would arrive nameless, though the answer had been
received and thrown away. The owner of an address is now remembered for twelve
hours, and the card states plainly which poll the name came from — a different
person may have taken the address since.

**One address with the same reason is reported at most once every six hours.**
The limit is still applied every time and shows up in the limited list — only
Telegram goes quiet. Without this the penalty expired after an hour, the daily
counters had not changed in that hour, the signal fired again, and one offender
produced six messages in an evening.

```
📊 RU Moscow · digest for 2026-08-11
Traffic: ↓ 352.1 GB · ↑ 31.4 GB
Addresses: 137

Top downloaders:
1. 203.0.113.42 — 24.8 GB
2. 203.0.113.24 — 19.2 GB
```

### Update notification

```
⬆️ An update is available · Node-2

Installed: 3.48
In the repository: 3.49

To update: shaper → Service → Update from GitHub
```

Every six hours the node fetches a single `VERSION` file from the repository —
not a clone, a dozen bytes. If a version newer than the installed one appears, a
message arrives, **one per version**, not a reminder four times a day.

The proxy is the one configured for Telegram: on nodes where Telegram is blocked,
GitHub usually is too.

If the repository is unreachable, nothing happens and the next attempt is in six
hours. The toggle: **Telegram → [13] About updates**, or
`telegram set --updates on|off` on the command line.

**Digest time** is set in the menu, entry `[9]`, `09:00` node local time by
default. The digest always covers the previous calendar day: at midnight a
snapshot of the counters is stashed in `/etc/shaper/digest.json` and waits for
the appointed hour. If there was no connectivity then, it retries every fifteen
minutes for a day and is dropped afterwards — the day-before-yesterday's numbers
are of no use to anyone.

**A digest can be requested manually** with entry `[10]`: it sends the numbers
for the current, not yet finished day. It works even with notifications off, as
long as a token and a chat are configured.

**The node label** is set by hand — for example `RU Moscow` or `DE Frankfurt`.
All nodes can write into one topic: the label shows which one fired.

**Forum group topics** are supported through `message_thread_id`. The topic ID
is the last number in its link. Leave the field empty if you have no topics.

**Proxy.** On Russian nodes `api.telegram.org` is blocked by SNI: TCP goes
through, TLS is cut. Set `socks5://user:pass@host:1080` — SOCKS5 is implemented
inside the script, no `PySocks` needed. With `socks5://` the hostname is
resolved by the proxy, so poisoned DNS stops being a problem too.

**An MTProto proxy will not work.** Links like `t.me/proxy?server=…&secret=…`
only work for the messenger itself: that is the MTProto protocol, while the Bot
API is plain HTTPS. The menu rejects such a string with an explanation.

### The SSH tunnel wizard

Menu → Telegram → **[12] SSH tunnel for the proxy**. Asks for the address of a
foreign node of yours, the SSH port, the user and the local SOCKS port, then
does everything itself: generates an ed25519 key, shows the server's host key
fingerprint for you to confirm, installs `autossh`, writes a systemd unit with
automatic restart, brings the tunnel up and verifies it with a real request to
the Bot API. On success it writes `socks5://127.0.0.1:1080` into the
notification settings by itself.

The tunnel costs the foreign node almost nothing: a couple of kilobytes a day.

---

## Node API

An optional local HTTP interface: an external system can control this node's
shaper through it. Installed separately, runs separately, removed separately.
**Shape is completely self-sufficient without it** — stop or delete the API and
the shaper keeps limiting exactly as before.

```
central system  →  Shape API  →  Shape  →  BPF
```

The API has no limiting logic of its own: it calls the same `shaperctl.py`
functions the menu does. So "limited via the menu" and "limited via the API" are
literally the same code and cannot drift apart.

### Installing

```bash
sudo bash install.sh --with-api      # Shape together with the API
sudo bash install.sh                 # Shape only, as before
```

API files are placed by any installation, but the service is only enabled with
the flag. You can enable it later from the menu: **Service → 🔗 Node API**.
Remove it without touching Shape:

```bash
sudo bash install.sh --uninstall-api
```

### Network

`127.0.0.1:8765` by default. Nothing is exposed to the public internet and
nothing is added to the firewall. To hand the API to a private network — a
WireGuard one, for example — set the listen address and the allowed networks in
the menu:

```
Listen address    : 10.100.0.7
Allowed addresses : 10.100.0.0/24
```

The port can be the same on every node: these are different machines, there is
nothing to conflict. A node knows nothing about other nodes — no shared state,
no database, no cluster identifiers. Addresses and tokens are known only to the
central system.

### Access

Two tokens, both generated on the node itself at first start and stored in
`/etc/shaper/api.json` with mode 600:

| Token | What it allows |
|---|---|
| `read` | status, node, list of limits, statistics, events, BPF state |
| `write` | all of the above plus creating and removing limits, changing settings |

Show and reissue them from the menu. There are no tokens in the repository and
there cannot be.

```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8765/api/v1/status
```

### Endpoints

All under `/api/v1/`. The OpenAPI schema is at `/api/v1/openapi.json`, the
documentation page at `/api/v1/docs`.

| Method | Path | Scope | What it does |
|---|---|---|---|
| GET | `/health` | — | is the service alive |
| GET | `/status` | read | state of Shape, engine, auto-limiter, versions, uptime |
| GET | `/node` | read | hostname, OS, kernel, architecture, interface, IPv4/IPv6 |
| GET | `/limits` | read | active limits |
| GET | `/limits/{ip}` | read | the limit for one address |
| POST | `/limits` | write | create a limit |
| DELETE | `/limits/{ip}` | write | remove a limit |
| POST | `/limits/{ip}/temporary` | write | temporary limit for an address |
| DELETE | `/limits/{ip}/temporary` | write | remove a temporary limit |
| GET | `/stats` | read | traffic, speeds, active and limited address counts |
| GET | `/events` | read | event log with filters and a cursor |
| GET | `/config` | read | the safe part of the settings |
| PATCH | `/config` | write | change the settings that are allowed to change |
| GET | `/bpf/status` | read | whether eBPF is loaded, maps and entry counts |

Creating a limit:

```bash
curl -X POST http://127.0.0.1:8765/api/v1/limits \
     -H "Authorization: Bearer $WRITE_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"ip":"203.0.113.10","download_mbps":1,"duration":43200,"reason":"torrent"}'
```

The kernel holds **one** speed per address and applies it in both directions.
So `upload_mbps` may be omitted, and if given it must equal `download_mbps`,
otherwise you get a 422 with an explanation. That is more honest than silently
applying one of the two values.

Errors come back structured, without tracebacks:

```json
{"error": {"code": "INVALID_IP", "message": "ip: «1.2.3.4;id» is not an IP address",
           "request_id": "9f2c1a4b7e0d5c31"}}
```

The `request_id` is in every response and in every line of the node's log, which
makes it easy to tie an external system's request to what happened on the node.

### Top of the load

```
GET /api/v1/top?limit=20&sort=download
```

Who is loading the channel right now — the same thing the monitor shows, only
as JSON and without the rest.

The point is the cap on the response. With a hundred nodes and three hundred
addresses each, "give me everything" means thirty thousand rows per polling
cycle, of which the first twenty matter. `limit` ranges from 1 to 200,
defaulting to 20.

`sort` is `download`, `upload` or `total`.

Speeds are computed from the difference between two reads of the kernel maps,
so **the first response does not carry them yet**. In that case the list is
sorted by accumulated volume, and the `sorted_by` and `note` fields say so
plainly — rather than passing zeros off as the truth.

```json
{
  "items": [
    {
      "ip": "203.0.113.42",
      "download_mbps": 79.8,
      "upload_mbps": 0.4,
      "download_bytes": 11000000,
      "upload_bytes": 150000,
      "idle_seconds": 0.3,
      "whitelisted": false,
      "limited": false,
      "personal": false,
      "limit_mbps": null,
      "subject": {"label": "Ivan", "user_id": "42"}
    }
  ],
  "count": 1,
  "total_known": 345,
  "sorted_by": "download_mbps",
  "note": null
}
```

`total_known` shows how many addresses are known in total, so a short list
makes it clear what it was cut down from.

The map snapshot is shared with `/api/v1/stats`: the two endpoints do not poke
`bpftool` twice as often, they reuse a single read.

### What the API deliberately cannot do

Run commands, change paths or executables, load BPF programs, invoke `bpftool`
arbitrarily, read or write arbitrary files, or hand out the Telegram bot token
or the API tokens themselves. The list of writable settings is an allowlist;
everything else is rejected with a 422.

### Event log

`/var/lib/shape/events.jsonl`, one JSON line per event, rotated by size. The
engine, the watchdog, the CLI and the API all write there — one history for
everyone. No separate database for this, and none needed.

Types: `limit_applied`, `limit_released`, `limit_expired`, `guard_triggered`,
`config_changed`, `engine_started`, `engine_stopped`, `api_action`, `error`.

---

## Limitations

Shaping applies to the interface the engine is attached to. On a node with
several uplinks pick the one clients actually arrive through — the menu shows
which one was detected.

IPv4 and IPv6 are both handled. IPv4 fragments and IPv6 extension headers are
recognised explicitly rather than parsed as if they carried an L4 header.

Traffic that does not match the port rule is not counted at all — that is the
point of the rule, but it also means the statistics only show what passes
through the shaper.

---

## Files

```
/opt/shaper/               the code
/opt/shaper/api/           the API (optional)
/etc/shaper/config.json    limit, ports, auto-limiter, notifications (600)
/etc/shaper/shaper.conf    interface and interface-level settings
/etc/shaper/whitelist.txt  the whitelist
/etc/shaper/trusted.txt    trusted tunnels and CDN relays
/etc/shaper/penalties.json who is limited, until when and why
/etc/shaper/daily.json     daily activity and volume counters
/etc/shaper/digest.json    the stashed digest waiting for its hour
/etc/shaper/api.json       API settings and tokens (600)
/var/lib/shape/events.jsonl the event log
```

`/etc/shaper` is root-only (750) and `config.json` is 600: it holds the bot
token.

---

## Finding shared subscriptions

A node sees addresses but not their owners. The Remnawave panel knows the
owners. Joining the two lets Shape answer a question neither side can answer
alone: **how many addresses of one user are alive on this node right now**.

Many addresses at once means the key went to other people.

The section is optional and off by default. The panel is only a lookup: if it is
unreachable, rate limiting and the watchdog carry on as if nothing happened.

### Why the device limit does not catch this

Remnawave's HWID limit restricts **fetching the subscription**, not connecting.
The client sends an `x-hwid` header when it downloads the link, and the panel
returns 404 for an extra device. But once someone holds a `vless://…` string,
HWID is out of the picture — at connection time the node only sees a UUID.

That is how a five-device limit happily coexists with hundreds of addresses: it
is enough to share the raw config instead of the subscription link.

### What counts as sharing

Simultaneity, not a total over a period. A person with a phone racks up dozens
of addresses a day, but only one is alive at any moment. Shape counts only the
addresses the panel saw within the last `window_min` minutes.

Default: **20 addresses within a 10-minute window**.

### `panel user` — from an ID to addresses

The reverse of `panel who`. It exists so you can check your bot's reports
against what Shape sees.

The bot takes its numbers from the panel, and the panel **does not store "up"
and "down" separately** — everywhere it is only `totalBytes`. So "123 GB in 24h"
in its report is the sum of both directions, and a download cannot be told from
seeding by it. Shape has those numbers.

```bash
shaperctl panel user 6085
```

```
  Ilya · user_100000001 (100000001)
  Panel login: user_100000001
  Addresses on the node: 2

  203.0.113.33     ↓ 58.2 GB · ↑ 61.4 GB (105%)
                    96% as data · packet 1310 B · uploaded for 9.0 h
  203.0.113.13     ↓ 3.1 GB · ↑ 0.1 GB (3%)
                    0% as data · packet 140 B
```

The first line is seeding, the second ordinary use. The question "what was he
downloading" closes in a second.

### Address threshold from the plan

The device count in a plan and the address count worth treating as normal are the
same number, only the second is larger: a mobile client changes address on
reconnect and on handover, so one device produces several addresses per window.

```bash
shaperctl panel set --per-device 4
```

| Plan | Address threshold |
| --- | --- |
| 1 device | 20 (base) |
| 5 devices | 20 (base) |
| 10 devices | 40 |
| 15 devices | 60 |

**The rule only raises the threshold and never lowers it.** The base stays the
lower bound, so no new triggers appear — only false ones can disappear for
customers who bought many devices.

Change the plan in the panel and the rule changes with it. Nothing to touch on
the nodes.

**It takes `hwidDeviceLimit` — the plan, not the number of registered devices.**
The difference matters: registered devices depend on whether the client installed
the app, and someone handed a config file never appears among them at all. The
plan depends on nothing — it is what you sold.

The field arrives in the user card Shape requests anyway, for the name. Zero
extra requests.

If the plan is unknown (no limit set), the base threshold applies. Guessing how
many devices the owner sold is not something to do on his behalf.

The message shows which threshold was applied:

```
Simultaneous addresses: 25 over the last 10 min
Threshold for his plan: 60 — devices sold: 15
```

### The night: disabling the subscription after a grace period

Cutting off addresses does not cover the night. A long cut-off hits the
innocent: a mobile carrier passes an address from one subscriber to another
within minutes, and someone can inherit another person's 0.05 Mbit/s for half a
day. A short one leaves a gap until the next check.

It is the **account** that shares the subscription, not the address. That is what
to hit.

```bash
shaperctl panel set --disable-after 30
```

```
3:00   146 addresses → cut-off + notice, the countdown starts
3:30   no reaction from you → the subscription is disabled
       ↳ none of his buyers have connectivity, on any node
9:00   shaperctl panel enable 741 — once you have looked into it
```

**The countdown cancels itself.** If you disabled or revoked the subscription in
time, the buyers vanish from the connection list, at the next check the person is
no longer an offender, and Shape does nothing. There is nothing to wait for or
cancel by hand.

**A safety valve.** No more than three are disabled per pass. If the panel one
day returns garbage and hundreds end up flagged, the automation will not disable
them — it will only report. A mistake of that kind costs too much to rely on it
not happening.

**Off by default.** This is the only action Shape takes that changes something in
the panel rather than in itself, and it must be switched on deliberately. The
token will need permission to modify users.

Exceptions by tag and by id apply: a marked user does not even enter the queue.

Menu: **Panel → Disable subscription after**, and next to it — **Turn a
subscription back on**.

### Business accounts

An office on a single subscription is dangerous in a different way than it
looks. On home internet ten computers sit behind **one** address, so sharing
detection never touches them — there is a single address in the window. But that
address carries the combined traffic of ten people, and the volume rules see one
very heavy user.

The opposite case is resale: **one device and two hundred addresses**. The
seller fetched the subscription through the app once and mailed the config to
buyers, who never appear in the device list at all.

Uploading work files looks like seeding: a real-estate agency uploading property
videos produces the same proportion, the same packets filled to the brim and the
same data share as a seeder. **At the network layer they are the same thing, and
no threshold separates them.** Only knowing who it is does.

**A tag is the simplest way.** Every user in the panel has a `Tag` field. Mark
the business accounts, say `BUSINESS`, and tell Shape once:

```bash
shaperctl panel set --exempt-tags BUSINESS,OFFICE
```

The tag is set in the panel — in one place — and applies on every node. A new
client appears: put the tag on them, change nothing on the nodes. Shape requests
the user card anyway, for the name, so the tag costs zero extra requests.

If you would rather not use tags, a list of IDs works too:

```bash
shaperctl panel set --exempt 2442,6672,152
```

Both lists are set whole, not appended to. To check: `panel show`, the
"Exceptions" and "Tag exceptions" lines.

These users fall under **neither sharing detection nor the auto-limiter** — no
penalty, no drop, no notification. The trigger is still written to the event log
as `panel_exempt` for sharing detection and as `guard_exempt` for
auto-limiting, so it can be looked at if wanted.

The number of exceptions is shown on the auto-limit screen too: the setting lives
in the panel section but affects both rules.

Without a panel link the exceptions do not work: there is nowhere else to learn
whose address it is.

### The token: grant the minimum

The key will sit on every node, so it does not need full access. When creating
the token in the panel, these scopes are enough:

```
connections:by-node
connections:by-node-result
connections:drop          ← only if you enable dropping
```

Leaking such a token grants neither access to users nor the ability to change
anything — at most, a look at the addresses on one node.

The lifetime is chosen at creation. Shape reads it from the token itself and
warns in Telegram a week before it expires.

### Setting it up

Menu: **🛰 Remnawave panel** on the main screen. Or from the command line:

```bash
shaperctl panel set --url https://panel.example.com \
                       --token TOKEN \
                       --node-uuid UUID-OF-THIS-NODE
shaperctl panel test        # check the link, change nothing
shaperctl panel set --enable
```

Take the UUID from the panel: **Nodes → the server you need**. That is a node,
not a host: hosts are the entry points shown in subscriptions, they have their
own UUIDs, and those will not work here.

### What to do with an offender

| Action | Effect |
| --- | --- |
| `notify` | a Telegram card: who, how many addresses, examples. **Always on** |
| `limit` | a local penalty on the addresses this node can see itself |
| `block` | cut off access to the node: minimal speed plus a connection drop |
| `drop` | drop connections through the panel — by address, on this node only |

Combine them with commas:

```bash
shaperctl panel set --action-set notify,limit --mbps 1 --minutes 60
```

Only `notify` is on by default.

**Notification cannot be switched off.** An action without it is the one thing
you cannot explain afterwards: connections dropped, the person complains, and
nothing in the log. What to do with an offender is your call, but you must learn
about them either way.

> **Dropping is not a punishment.** The client reconnects a second later. As a
> "we see you" signal it works; as a measure it does not. `limit` is what bites:
> it holds for the configured minutes.

Limiting touches only addresses present in the node's own map. The whitelist and
existing penalties are left alone.


### What arrives in Telegram

```
🔎 Looks like a shared subscription · FRONT-3

👤 Ivan · @ivan_k
🆔 Telegram: 100000003
🔑 Panel login: user_100000003 · #101

Simultaneous addresses: 437 over the last 10 min
🚫 Access to the node cut off for 60 min, addresses: 412
Connections dropped: 437

┌ 1.2.3.4
│ 5.6.7.8
│ …
└ (a collapsed quote, tap to expand)
…and 180 more. The full list follows as a file.
```

The addresses sit in a **collapsed quote**: closed by default, so it does not
stretch the chat over a hundred lines, yet it opens with a tap — no need to
download the file. As many addresses go into the quote as fit in the message;
the rest follow as an attachment.

**A tap copies only what you search by:** the panel login and the Telegram ID.
The address is plain text. It used to be copyable too and stole the tap for
itself — and there is nowhere to search by an address, neither the panel nor the
bot knows it.

The name is tappable: behind it sits a `tg://user?id=…` link that opens the
chat, and it works even for people without a username.

**Where the name comes from.** The panel has no field for it: the login there
looks like `user_100000003`, and the name, if it exists at all, is written into
the account description by a bot — usually as a line like
`Bot user: Ivan @ivan_k`. Shape parses that description into a name and a
handle, and does so cautiously: every bot has its own format, and if the parse
fails the card simply keeps the login, as before. A note like
`Paid: until 3 October` is left alone and shown in full.

### What `block` does

It is not a firewall rule and not a subscription shutdown in the panel. It does
two things at once:

1. **A minimal speed of 0.05 Mbit/s** on every address of the offender this node
   can see, for 60 minutes.
2. **A drop of the current connections** through the panel.

Without the second the first would be useless: already established connections
would merely become slow, and the person would stay "online" until they timed
out.

**Why not just a drop.** The client reconnects within a second. As a signal
saying "we see you" a drop works; as a measure it does not. A reseller loses the
connections and immediately gets them back.

With `block` his buyers reconnect and find that there is practically no
connectivity — for an hour.

**It holds for an hour, and that is enough.** Cutting off addresses is not the
measure but a way to hold the door while the countdown to disabling the
subscription runs. An hour covers a half-hour countdown with room to spare.

The twelve hours that used to be set covered the night but hit bystanders: a
mobile address moves to another subscriber within minutes, and they inherited
someone else's 0.05 Mbit/s for half a day.

**If disabling the subscription is off** and the night still needs covering,
raise the cut-off by hand: `panel set --minutes 720`. The old drawback comes
back with it.

**It can be lifted earlier, and not address by address.** A reseller has a
hundred and fifty of them:

```bash
shaperctl release --user 741
```

Menu: **Limited addresses → Lift from every address of a user**. The id comes
from the Telegram card, the "Panel" line.

**What it does not do.** The limit is local, on this node. A buyer who reconnects
to another node will be free there until that node also sees twenty addresses of
his. Each node answers for itself.

Zero cannot be used as the speed here: zero in the kernel map means "no limit",
and the engine would let the traffic through unaccounted. Hence 0.05, not 0.

### Exceptions

Who is allowed to share — family, colleagues:

```bash
shaperctl panel set --exempt 97,346
```

### Names instead of numbers

In the connections reply the panel returns only the internal user number — 97,
346. The name and Telegram ID live in the user's card, so Shape asks the panel
separately and writes `Olga (100000008)` instead of `#346`.

That needs the **Users → Read** scope. Without it everything still works, just
with numbers. To turn it off entirely:

```bash
shaperctl panel set --resolve off
```

An offender is looked up by number, one request at a time. The full directory is
fetched only for the report and only once a day: a panel with six thousand
accounts is six pages of a thousand, and keeping that in a node's memory every
five minutes serves no purpose.

### Node report

Who is connected right now and from which addresses — once a day at a time you
choose:

```bash
shaperctl panel set --report on --report-at 09:00
shaperctl panel report        # send it right now
```

It looks like this:

```
Node report FRONT-3 · 2026-08-23 09:00
Users connected: 138
Addresses in total: 412
Window: 10 min

Nikita (100000007) — 437  ⚠
    1.2.3.4
    5.6.7.8
    …
Olga (100000008) — 2
    …
```

Sorted by the number of simultaneous addresses: whoever is worth a look is on
top, marked with `⚠`.

The report always arrives as a **file**, even a short one: that way it looks the
same on every node and is easy to compare. The message itself carries only the
summary — node, users connected, addresses.

The report can go to its own topic so it does not clutter the alerts:

```bash
shaperctl panel set --report-thread 777
```

Nothing is written to disk: collected, sent, forgotten. Shape does not keep a
history of addresses and should not.

### All settings

| Key | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | whether to poll the panel |
| `url` | — | panel address, without `/api` |
| `token` | — | token with the `connections` scopes |
| `node_uuid` | — | UUID of this node in the panel |
| `interval` | `300` | how often to ask, seconds |
| `window_min` | `10` | simultaneity window, minutes |
| `ip_threshold` | `20` | addresses above which it is sharing |
| `action` | `notify` | `notify`, `limit`, `block`, `drop`, or a combination |
| `limit_mbps` | `1` | megabits to throttle down to |
| `limit_min` | `60` | for how many minutes |
| `cooldown_min` | `360` | pause between alerts about one person |
| `exempt` | `[]` | who is allowed to share |
| `exempt_tags` | `[]` | the same, but by tag from the panel |
| `per_device` | `0` | threshold multiplier from the plan; 0 — ignore |
| `disable_after_min` | `0` | minutes before disabling the subscription; 0 — never |
| `resolve` | `true` | use the name and Telegram ID instead of the number |
| `report` | `false` | send the node report |
| `report_at` | `09:00` | when to send the report |
| `report_thread_id` | — | topic for the report; empty means the usual one |
| `proxy` | — | http proxy to the panel; socks5 is not supported |

The threshold never drops below two addresses, whatever the settings say: one
would mean "throttle everyone who connected".

### When something goes wrong

```bash
shaperctl panel show        # state, token expiry, last error
shaperctl panel scan --dry-run   # show findings, change nothing
```

The link is visible separately in the metrics:

```
shape_panel_up                      1 if the last poll succeeded
shape_panel_last_success_seconds    time since the last success
shape_panel_token_expires_seconds   time left on the token
shape_panel_sharing_found           offenders on the last poll
```

`shape_panel_up` is separate on purpose: without it, a silent panel looks exactly
like a panel where nobody is cheating.

## Monitoring

Prometheus metrics come out **three ways**, and the API is not required for
any of them. Set up in the menu: **Service → 📈 Monitoring**.

**The node pushes on its own — the only path that works from behind NAT and
from countries where VPNs are blocked.** Not a single inbound port is opened:

```bash
shaperctl metrics set --url https://push.example.com/api/v1/import/prometheus \
                      --token WRITE_TOKEN
systemctl enable --now shape-push.timer
```

A ready-made receiving server lives in [monitor/](monitor/): VictoriaMetrics,
Grafana, Caddy and a gate with a second factor, one command on a bare VPS.

**As a file — if node_exporter is already on the node.** The wizard finds its
textfile directory, installs a systemd timer and writes `shape.prom` there
every minute. No open ports, no tokens, no API:

```bash
shaperctl metrics                       # look at them
shaperctl metrics --out /var/lib/node_exporter/textfile_collector/shape.prom
```

**Through the API — if it is installed** and reachable from your monitoring:

```bash
curl -H "Authorization: Bearer $READ_TOKEN" http://127.0.0.1:8765/metrics
```

Both texts are produced by the same code in `shaperctl.py`, so they cannot
drift apart. On top of the shared set the API adds two of its own metrics:
`shape_api_up` and `shape_api_uptime_seconds`.

Every metric carries a `node` label so graphs are labelled by node name rather
than by address. A ready Grafana dashboard for the whole fleet lives in
[grafana/](grafana/), together with sample `scrape_configs` and a description
of every metric.

Scraping costs next to nothing: heavy reads are cached — map dumps for two
seconds, the event log for thirty. Channel speed is derived from the previous
sample, and that sample lives in a file, so it works for one-off CLI runs too.

Running `shaperctl metrics` without root cannot read the BPF maps. The
`shape_metrics_complete` metric then drops to zero, so monitoring sees
"incomplete data" rather than "no traffic".

### Who notices that a node went quiet

Metrics answer the question "what is happening on the node". There is another
one — "is it alive at all?" — and a node cannot answer it. A node that is down
will not send a message saying it is down; absence of a signal cannot be sent
as a signal.

That is what **[watchman/](watchman/)** is for — a silence watchdog. It runs on
a separate machine, reads the Remnawave panel's `/api/nodes` once a minute and
writes to Telegram when a node loses its clients or the panel loses the node.
It is not installed on nodes and changes nothing on them.

It watches client counts rather than missing metrics: a node can be healthy and
still unreachable from outside — a broken CDN, a vanished DNS record, a dead
route. Metrics keep flowing all the while.


---

## History by day

Daily counters reset at midnight, but now a row is written to
`/var/lib/shape/history.jsonl` first: date, downloaded, uploaded, address
count, limits issued and the five heaviest addresses. About a hundred bytes a
day, forty kilobytes a year.

Menu → **Statistics → 📅 History by day**, or `shaperctl history --days 30`,
or `GET /api/v1/history`. This is the answer to the hoster's "how much did you
push last month".

---

## Personal speeds

The penalty map in the kernel does not check whether a personal speed is below
the shared limit or above it. So the same mechanism grants a permanent speed:
more than the shared limit for a colleague with a work system, less for a
problem address. No kernel changes were needed.

Menu → **Statistics → 🎯 Personal speeds**. Auto-limiting leaves such addresses
alone — a human has already decided about them. They are not shown in the
limited list and are not counted on the main screen.

---

## Who is behind an address

Shape works at the network layer and only knows addresses. A name reads better
in a message though, so there is an owner map at
`/var/lib/shape/owners.json`:

```json
{"203.0.113.23": {"label": "Ivan", "telegram_id": 123456789,
                 "user_id": "42", "shared": false}}
```

Filled in by hand (`shaperctl owners set 203.0.113.23 --label Ivan
--telegram-id 123456789`) or in bulk through `PUT /api/v1/owners` — that is
where a panel resolver will write once it exists. Shape itself never goes
looking for this data, and it should not.

The label is attached to a limit **at the moment it is issued**: later the
person disconnects and the link is lost. Notifications then carry a name with a
`tg://user?id=…` link, which works even for people without a username:

```
🚦 Limited · RU Manassas

👤 Ivan
🆔 Telegram: 123456789

📍 Address: 203.0.113.23
🐌 Speed reduced to 1 Mbit/s for 4 h
Reason: downloaded gigabytes within an hour
```

If an address is marked `"shared": true`, the message says so. Better a warning
than blaming the wrong person one day.

---

## Backup and restore

Everything that makes a node this node goes into a single file: settings,
whitelist, personal speeds, active limits, address owners and daily history.

```bash
shaperctl export --out /root/node.json
```

Menu: **Service → 💾 Backup and restore**.

Three reasons to have it, and with a growing fleet the third matters most:

* moving a node to another server;
* rebuilding after a dead disk;
* rolling out new nodes from an already configured one — with a hundred
  nodes there is nowhere to repeat the setup by hand.

### The token in a backup

By default **the bot token and the proxy password are left out**. The file
almost always leaves the server — into downloads, into a chat, sometimes into
a repository — and a token inside it would leak sooner or later.

The rest of the Telegram settings are kept: `chat_id`, digest time, the
enabled flag. Only the secrets are missing.

When the copy is meant for cloning a node, add `--with-secrets`. Either way
the file is created with mode `600`.

### Restoring

```bash
shaperctl import /root/node.json --dry-run   # look first
shaperctl import /root/node.json             # then apply
```

`--dry-run` parses the file, shows what would be restored and how much of it,
and changes nothing. The menu always does this step first and asks for
confirmation.

Behaviour worth knowing:

* **The node's own token is never wiped.** If the file carries no secrets,
  whatever is configured here stays — otherwise notifications would go
  silent after every restore.
* **The whitelist is merged**, not replaced. Use `--replace` for a full swap.
* **Expired limits do not come back**: the deadline is checked on read.
* **History merges by day**, with no duplicates.
* **The file is not trusted.** It may come from another node or have been
  edited by hand, so every value goes through the same checks as ordinary
  input. Anything unusable is dropped with a note instead of crashing the
  command halfway through writing.
* You can restore a subset: `--only config,whitelist`.

If the engine is loaded at that moment, settings go straight into the kernel
maps. If not, they apply on the next service start.

The event log, metrics and the current day's counters are deliberately left
out: the first is a log rather than state, the rest are recomputed.

---

### Backups over Telegram

A copy sitting on the same disk that will one day die is not a copy. Standing
up a separate server for 200 kilobytes is not worth it, and Telegram is
already configured on the node — proxy included, which Russian nodes need
anyway.

```bash
shaperctl telegram set --backup on --backup-day 1
shaperctl telegram backup        # send it right now
```

Menu: **Service → 💾 Backup and restore**, items [4]–[7].

The file is uploaded once a week, on the chosen day, at the same time as the
daily digest. The topic can be separate from the reports (`--backup-thread`);
without one, the copy goes wherever ordinary messages go.

**The bot token never ends up in such a copy — under any setting.** The bot
posts into the very topic it uploads the file to: anyone in that topic, now
or added six months later, would gain control of the bot and its whole
history along with the token. The payload is checked for secrets one more
time right before sending, and a match cancels the upload entirely — even if
the code were changed badly at some point.

Restoring works as usual: `shaperctl import file`. The bot on a new node is
configured once by hand, everything else arrives from the file — the token is
not wiped on import.

⚠️ **The file holds client IP addresses**, and names and telegram_id values if
owners are filled in. That is personal data, and in Telegram it stays forever,
visible to everyone in the topic. Keep the topic private.

If there is no connectivity, the next attempt happens in an hour rather than
every ten seconds. A missed day is not caught up: the state sent is the
current one, not what it was on Monday.

---

## Which node is this

With twenty-eight nodes you tell them apart by name. With a hundred you no
longer can — and hostnames get changed, nodes get moved to another server,
addresses migrate. After that a year-long graph in monitoring falls apart into
two halves belonging to "different" nodes.

So every node carries a permanent identifier:

```
/var/lib/shape/node_id      16 hex characters, created once
/var/lib/shape/panel.state  cooldowns and the last panel poll error
/var/lib/shape/guard.state  watchdog memory: who was already reported, and who is behind an address
```

It survives a Shape upgrade, a move to another server and a hostname change.
Reinstalling does not touch it — the installer never overwrites an existing
file.

Worth saying why not `machine-id`: nodes are rolled out from an image, and
clones share it — so it would fail in exactly the case this was built for. The
Shape identifier is random, and it is **not** part of a state backup:
restoring a copy on a new server gives you a node with its own identifier, not
a twin.

## Configuration fingerprint

The second problem of a hundred nodes is drift. Someone will one day fix the
speed by hand on a single node, and there will be nowhere to learn about it:
the complaint arrives a month later and you end up chasing the symptom.

`shaperctl show` prints the fingerprint in the footer:

```
  node 3248507562c6ba1b  ·  fingerprint 37026c5a46ca
```

The same fingerprint means the same policy. It is computed from the ports and
the auto-limiter settings — that is, from what should match across every node.

What it deliberately leaves out, and why:

* **the speed** — every node has its own uplink and the limit is set to match
  it. Inside the fingerprint the speed would produce as many groups as you
  have tiers, drowning the "something drifted" signal. It reads better as a
  number — that is what the `shape_speed_limit_mbps` metric is for;
* **the whole `telegram` section** — the node label and topic differ there by
  design, and the fingerprint would become unique per node, i.e. useless;
* **`watch_interval`** — a CPU-load knob rather than policy: on a weak VPS it
  is routinely raised, and keeping such a node permanently "drifted" teaches
  you to ignore the indicator altogether.

You will have as many fingerprint groups as you have **policy variants**. One,
if the auto-limiter is configured identically everywhere. Two, if — say — on a
narrow uplink you catch an offender sooner and punish for longer. That is
fine; what matters is knowing how many groups there should be.

### In monitoring

Both values arrive as `shape_info` labels:

```
shape_info{node="...",node_id="3248507562c6ba1b",config_hash="37026c5a46ca",version="3.8",...} 1
```

Finding drifted nodes is one query:

```promql
count by (config_hash) (shape_info)
```

One row in the answer means the policy is the same everywhere. Two or more
shows at a glance how many nodes fall into each group.

The speed sits next to it as a plain number:

```promql
shape_speed_limit_mbps
```

In the API both fields live in `/api/v1/status` (the `node` section) and in
`/api/v1/node`.

---

## Removal

Menu: **Service → 🗑 Remove Shape**. Or from the repository:

```bash
bash install.sh --uninstall            # keep the settings
bash install.sh --uninstall --purge    # delete the settings too
```

Both paths lead into the same `uninstall.sh` — keeping this in two places is
not an option: the implementations would drift apart, and one of them would
eventually leave a live eBPF program on the node.

### What happens, and in what order

The order matters more than it looks:

1. services are stopped — engine, watchdog, API, metrics, tunnel;
2. **the program is detached from the interface while `/opt/shaper` is still
   there.** Once the files are gone `engine.sh` can no longer run, and the
   filters would stay on the NIC until a reboot;
3. the metrics file is removed from the node_exporter directory. It is
   static: leave it, and Prometheus will show the removed node as alive
   forever;
4. units, `/opt/shaper` and the `shaper` command are deleted.

The `fq` root qdisc is left in place deliberately — it is harmless and often
needed by other software on the same machine.

### What stays

By default `/etc/shaper` and `/var/lib/shape` are untouched: settings, API
tokens, the node identifier and history. Install Shape again and the node
stays itself, with no gap in the monitoring graph.

The `--purge` flag (a toggle in the menu) removes those as well.

### Three barriers in the menu

The action is irreversible and drops the limit for every client instantly, so
a plain "y/N" is not enough — those get pressed without reading. The screen
spells out the consequences, offers to take a backup first, and requires
typing the word `DELETE` in full.

---

## How a release is made

The project's rules live in [RELEASING.md](RELEASING.md): two languages with
Russian as the primary one, the version section in `CHANGELOG.md` doubles as
the release notes, and CI checks the version number across five files at once.

---

## Support the project

Shape is free and will stay that way. If it saved your channel or your nerves,
you can buy a coffee: **https://web.tribute.tg/d/OHz**

This changes nothing: there will be no donor-only features and no restrictions
for anyone else.

---

## License

GPL-2.0. The eBPF part requires a GPL-compatible license — otherwise the kernel
refuses to load the program.
