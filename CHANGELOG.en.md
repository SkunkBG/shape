# Changelog

<p align="center">
  <a href="CHANGELOG.md">Русский</a> · <b>English</b>
</p>

Newest versions on top. The version number lives in `VERSION` and is shown in
the menu header.

**Each section below is also the release notes.** When publishing a release on
GitHub, copy the section for that version as it is — nothing needs rewriting.
The Russian version in [CHANGELOG.md](CHANGELOG.md) is the primary one.

---

## 3.32

**Five presets became two, named by node type rather than by mechanism.**

### Choosing between five was not possible

"Mobile", "universal", "torrents", "fast", "everything" — they differed by their
internals, not by the node they suit. To choose you had to keep in your head how
`both-dl` differs from `download-gbh`.

And the job is always the same: torrents and shared subscriptions. Only the
channel differs, and what sits behind it.

```
  [1] 📱 Phones
      mobile internet, usually 10 Mbit per address
      3 GB per hour · sharing from 20 addresses

  [2] 🖥  Home internet
      wifi and cable, usually 50–100 Mbit per address
      half the channel per hour · sharing from 10 addresses
```

Both catch the same things: torrents by two-way traffic, quiet seeders by the
share of upload over a day, volume per hour and per day, shared subscriptions by
the number of addresses. The penalty is shared too — 1 Mbit/s for an hour, and
sharing gets dropped.

### The hour is counted differently, and that is the point

Three gigabytes an hour is a figure computed for a phone: 1080p fits twice over,
and a download hits the threshold in forty minutes. It is deliberately not
derived from the channel — mobile nodes all have roughly the same bandwidth, and
the threshold here is about what a person needs, not what fits in the pipe.

On a 100 Mbit node those same three gigabytes are one film, and the threshold
would catch everyone. So at home it is derived from the channel: **half the
bandwidth per hour**. Video is untouched, a bulk transfer is caught. The day is
eight such hours; holding half the channel for a third of a day is no longer
"watched a movie".

If no speed is set on the node, the home preset takes 20 GB per hour and 160 per
day, and says so on screen.

### The sharing threshold is looser for phones

20 addresses against 10. A mobile carrier changes the address several times an
hour, and a dozen within the window is possible for an honest person. At home
there is one address for the whole family, and ten at once is already sharing.

### A preset configures both halves

A preset used to touch only the auto-limiter, while sharing had to be enabled
separately on the panel screen — and it was forgotten. The preset now sets the
address threshold and the action (drop connections) as well.

Manual settings are untouched: the auto-limit screen and the panel screen still
change every parameter individually.

### Also

* Both READMEs rewritten around two presets.
* Preset shell tests rewritten — 21 checks instead of scattered ones: that
  there are exactly two presets, that the old keys are gone from both `menu.sh`
  and `lang.sh`, that both catch torrents, quiet seeders and sharing, that the
  address threshold is 20 against 10, that the hour is fixed for one and derived
  for the other, and that the day is exactly eight hours.
* 24 unused language keys removed, 16 new ones added in both languages.

---

## 3.31

**Two mechanisms stopped looking like one, and the action is now picked from a
list.**

### They were confused, and fairly so

"Preset [5] works for both torrents and sharing" — that is how it looked, and
the screen explained nothing. They are in fact different things that only meet
in Telegram:

| What is caught | By what | What it does | Panel needed |
| --- | --- | --- | --- |
| Torrents, hourly and daily volume | Auto-limit, preset [5] | throttles | no |
| Shared subscription | Remnawave panel | drops connections | yes |

The auto-limiter counts traffic on its own and works on any node. Sharing cannot
be found without the panel at all: a node sees addresses but does not know that
three hundred of them belong to one person.

The panel screen now says so on its first line: "Torrents and volume are a
different thing: Auto-limit."

### The action is chosen, not typed

It used to be `notify · limit · block · drop — or several, comma-separated`,
entered as text. Half the options were meaningless: `notify` is always on, and
`block` is already `limit` plus `drop`.

Now there are four mutually exclusive items, each explained:

```
Notification always goes out — that part is not optional.
Here you choose only what happens to the offender besides it.

[1] Only report
    a card in Telegram, nothing else. Good for watching first.
[2] Drop connections   — recommended for sharing
    the panel disconnects every address of theirs on this node
[3] Throttle the speed
    a local penalty on the addresses this node can see
[4] Cut off access
    minimal speed plus a drop — the internet appears to be gone
```

On the command line `--action-set` still accepts comma-separated combinations:
there it is occasionally useful, in the menu it only got in the way.

### Small but noticeable

"Penalty: 1 Mbit/s · 60 min" was shown always, including for the "drop" action
where speed is irrelevant. That line now appears only when the chosen action
actually throttles.

### Tests

10 new: the action is picked from a list, every item has an explanation, the
recommendation is marked, the penalty speed is shown only when it throttles, and
the panel screen states what it does not handle. 1084 in total.

---

## 3.30

**Notification became mandatory, and offender messages became identical.**

A shared subscription and a traffic overrun are different checks, but whoever
reads the message asks the same thing: **who, and what for**. The decision is
yours to make, and for that you need the name, the identifiers and the reason —
whichever check fired.

### Notification can no longer be switched off

`action=drop` without `notify` meant silent drops: connections cut, the person
complains, and nothing in the log. There was no way to tell who or why.

`notify` is now added automatically to any set of actions. What to do with an
offender is still your choice: `drop` cuts connections, `limit` throttles,
`block` cuts off access. But you get told about them either way.

### A shared card

There used to be two different messages. Now both start the same way:

```
🚦 Limited · Erebor

👤 Bashou
🆔 Telegram: 637181482
🔑 Panel ID: 741

📍 Address: 91.78.46.46
🐌 Speed cut to 1 Mbit/s for 1.0 h
Reason: uploaded disproportionately much in 24h
```

```
🔎 Looks like a shared subscription · Erebor

👤 Bashou
🆔 Telegram: 637181482
🔑 Panel ID: 741

Simultaneous addresses: 287 over the last 10 min
Connections dropped: 287
```

The identifiers copy with a single tap in both.

**If the panel is not set up on the node**, the message says so outright:
"identity unknown: the panel link is not set up on this node". The line used to
be simply absent, which read as "the name was not found" — while there was
nowhere to look for it.

### Setting it up for this scenario

Sharing — drop connections at once, throttling is pointless, the addresses come
in hundreds:

```bash
shaperctl.py panel set --action-set drop --threshold 20
```

Torrents and volume — throttle; that is the watchdog's job, configured by preset
**[5]**. Notifications with the reason arrive in both cases on their own.

### Tests

18 new: notification is added to any action, the drop still happens, the card is
identical for both causes, identifiers are copyable, and on a node without the
panel the message says plainly that the identity is unknown. 1074 in total.

---

## 3.29

**The switch that silently disables penalty messages is now visible.**

The ratio signal fired on a node: `95.32.199.197` limited, present in the
"Limited addresses" list, reason stated. And silence in Telegram.

The cause is a separate `events` switch. It governs penalty messages, and when
off it stays quiet: the limit is applied, the notification is not sent.

The `telegram show` screen did not mention it at all:

```
Notifications : enabled
Node label : Erebor
Chat : -100…
Proxy : direct
Digest time : 09:00
```

Everything enabled, everything green — and no messages. Nothing to explain why.

### How it looks now

```
Notifications : enabled
Node label : Erebor
Chat : -100…
Proxy : direct
Events : disabled  — penalty messages are not sent
Digest : enabled
Digest time : 09:00
```

Disabled events are highlighted and explained. One command turns them on:

```bash
shaperctl.py telegram set --events on
```

This is the same class of mistake as the ratio signal two releases ago: a
setting exists, changes behaviour, and there is nowhere to see it. I am going
through the remaining screens with that in mind.

### Tests

9 new: the switches are visible in both states, the warning appears only when
events are off, the labels are translated; separately — that without `events` a
penalty message truly is not sent, and with them it is, carrying a
human-readable reason. 1056 in total.

---

## 3.28

**`panel who` — whose address is this, in one command.**

A penalty message arrives with an address. What follows is exactly one question:
who is that. Until now it meant going to the panel and searching by hand — and
if the name had not made it into the message, guessing why.

```bash
shaperctl.py panel who 91.78.46.46
```

```
✓ address 91.78.46.46 belongs to:
    Panel ID: 741
    Name: Bashou
    Telegram: 637181482
    the panel last saw it at 2026-08-26 14:41
```

The panel is queried afresh rather than reading the in-memory map: that map
lives in the watchdog process, and the command runs separately, where it is
empty.

### It doubles as diagnostics

When a name is missing from a message there are only a few possible causes, and
the command names them outright:

* **address not found** — the panel does not know it. Either it dropped between
  the poll and the penalty, or the configured node is not the one this person
  connects through;
* **address found, no name** — the token lacks the `users:read` scope;
* **panel refused** — the code and the response text are shown.

Each case gets its own line instead of silence.

### Tests

10 new: the address is found, the panel is queried afresh, an unknown address
gives a clear answer with a hint, junk instead of an address is rejected, and
without the users scope the address is still found. 1047 in total.

---

## 3.27

**Any node UUID was accepted, and with a wrong one everything looked healthy.**

On a live node the settings held:

```
Node UUID : 5d8572233c3b934
```

Fifteen characters instead of thirty-six — the head and tail of a real UUID with
the middle lost during entry. And meanwhile:

```
Panel link : enabled
Last successful poll : 2026-08-26 14:32
```

All green. The panel accepts a request with any UUID and answers with an empty
result: the poll counts as successful, the address-to-user map stays empty, and
names quietly stop being filled in. The only symptom was penalty messages
without a name, and nothing tied the two together.

### What changed

**The UUID is checked by shape when saved.** Not 36 characters with dashes —
refused, with an example of a correct value. Whether the UUID exists is the
panel's business; its shape was ours to check.

**The state now shows "Users on the last poll".** Zero on a successful poll is
highlighted in red with an explanation: it almost always means we are asking
about a different node. An already-saved malformed UUID gets a warning — a check
at save time does not repair old settings.

```
Last successful poll : 2026-08-26 14:41
Users on the last poll : 0
  zero on a successful poll almost always means the UUID points at a different node
⚠ the node UUID must look like 5d8bba03-0951-4503-a4d6-572233c3b934
```

### Tests

17 new: the UUID shape in every variant, refusal to save a malformed one, the
user count stored in the state and updated. 1037 in total.

---

## 3.26

**The ratio signal worked, but there was nowhere on screen to see it.**

The main screen on v3.24:

```
🚦 Auto-limit on   both ways ↓1 ↑0.3 Mbit/s 10 min + 3 points → 1 Mbit/s
   or 2.2 GB per hour · 100 GB per day
```

Preset [5] applied, the upload ratio enabled at 35% — and the line does not
mention it. Neither does the auto-limit screen, nor `shaperctl show`. The signal
was issuing penalties while there was no way to tell whether it was on: the
"uploaded disproportionately much in 24h" message arrived out of nowhere.

The cause is plain: I wrote the status line for the volume thresholds before the
ratio existed, and forgot to add it there.

### How it looks now

```
🚦 Auto-limit on   both ways ↓1 ↑0.3 Mbit/s 10 min + 3 points → 1 Mbit/s
   or 2.2 GB per hour · 100 GB per day · upload over 35%
```

On the auto-limit screen it gets its own line next to the other independent
paths, plus item **[12]** to change the threshold without leaving for the command
line. `shaperctl show` prints it too.

### A check so it does not happen again

The status line is assembled from pipe-separated values: one function prints
them, another parses them into names. Add a field to the first and forget the
second, and every value silently shifts by a column.

The suite now runs both functions for real and compares: as many fields on the
output as there are names in the parse.

### Tests

7 new. 1020 in total.

---

## 3.25

**The panel user number no longer disappears from the penalty message.**

A message arrived:

```
🚦 Erebor
Limited 91.78.46.46 → 1 Mbit/s for 1.0 h
uploaded disproportionately much in 24h
```

The signal worked, but who is it?

### What was wrong

The offender's label was built from three fields: name, Telegram ID and panel
number. The first two were shown, the third was not — even though it is almost
always available: the number arrives with the connections list, before Shape
asks for the user's card at all.

So with names disabled, or without the `users:read` scope, we knew `#741` and
printed a bare address.

Now such a case reads `#741 · 91.78.46.46` — the number finds the person in the
panel just as well as a name does.

### Also fixed

A non-numeric Telegram ID broke sending outright. `owners.json` is edited by
hand, and any "no data" in that field meant the penalty message never went out
at all. Such a value is now simply dropped.

### If the name is still missing

Check on the node:

```bash
shaperctl.py panel show
```

The name is filled in only when the panel link is enabled **on that very node**:
the address-to-user map is built by its own poll. On a node without the panel
there is nowhere to take a name from — only the address will show.

### Tests

13 new: the label in every combination of fields, the panel number is not lost,
junk in the Telegram ID does not break sending, the name is escaped. 1013 in
total.

---

## 3.24

**The threshold drops to 35% on data from two nodes, and there is now a tool to
keep tuning it without guessing.**

### Why 50% turned out to be too lenient

Fresh statistics from two servers. One was clean — nobody above 22%. The other
had three:

```
95.32.199.197    857 MB ↓   756 MB ↑   = 88%
176.59.54.33    1015 MB ↓   489 MB ↑   = 48%   ← the 50% threshold missed it
95.26.73.25      1.1 GB ↓   500 MB ↑   = 45%   ← and this one
188.66.34.198    1.1 GB ↓   280 MB ↑   = 25%
…everyone else                           2-17%
```

Two sat right under the threshold. And that is not borderline noise: half a
gigabyte of upload against a gigabyte of download cannot be acknowledgements —
TCP produces 50-80 MB for that volume, not 500. They are seeding, they just
download more than they upload.

The picture is now clear: honest clients end at 25%, seeders start at 45%. The
threshold moves to **35%** — the middle of the gap, with margin either way.

### A tool instead of guesswork

```bash
shaperctl.py status --ratio
```

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

Highest by ratio:
  95.32.199.197      857.2 MB ↓   756.3 MB ↑    88%
  176.59.54.33      1014.7 MB ↓   489.1 MB ↑    48%
  ...
```

The empty bucket in the middle is the border between honest clients and seeders.
It used to be something you hunted for by eye in a list sorted by volume, where
seeders are scattered among thousands of addresses. Now it is immediate.

Every node has its own client profile, and the threshold is better set from
observation. The 100 MB upload floor removes the noise: an address with 10 MB
down and 8 MB up has a ratio of 80%, and in this picture it only gets in the way.

In the menu: **Statistics → 🔍 Upload ratio**.

### Tests

12 new, on live figures from both nodes: the gap in the 30-40 bucket is visible,
two in 40-50 and one in 75-100 are where they should be, the clean node stays
clean, small-upload noise is filtered out, and upload without download does not
divide by zero. 1000 in total.

---

## 3.23

**A "total" column in the monitor: how much an address has moved, not just how
fast it is going right now.**

The monitor showed speed only. "0.1 Mbit now" looked identical for someone who
had moved twenty gigabytes today and for someone who connected a minute ago —
there was nothing to tell them apart without leaving for the statistics screen
and hunting the address down there.

```
IP                       now  upload packet     avg    total holding  share of limit
109.248.47.99           10.1     0.1    140     3.1  12.4 GB  12 min  ████████████ 101%
91.79.15.94              1.4     2.7   1310     1.7  22.8 GB       —  █▊··········  14%
```

Counted down and up together, since the engine loaded — the same figure as in
the statistics. Yellow from 5 GB, red from 20.

The second row is exactly the case the column exists for: 1.4 Mbit, fourteen
percent of the limit, nothing remarkable. And 22.8 GB behind it.

### Tests

7 new: the column is present, the value comes from the kernel maps rather than
being recomputed, the label is translated, and the table width grew with it.
988 in total.

---

## 3.22

**The quiet seeder: a third kind of torrent that nothing caught.**

### Who was slipping through

From the live statistics of a node with 6143 addresses:

```
91.78.14.134   downloaded 379 MB   uploaded 916 MB   ← 2.4× more up than down
91.78.46.46    downloaded 785 MB   uploaded 461 MB   ← 59%
…everyone else                                          5-15%
```

The first fell under no rule at all. Do the arithmetic: even packing all that
upload into four hours gives 0.5 Mbit up and about 0.2 down. The two-way
condition demands at least 10% of the limit downward — one megabit. Instant
thresholds never see it. Neither do volume ones: 916 MB against a two-gigabyte
threshold.

It passed between every sieve. And it uploaded more than twice what it
downloaded — which nothing but seeding does.

### The new signal: upload-to-download ratio

```bash
shaperctl.py guard --upload-ratio 50 --upload-ratio-mb 300
```

Uploaded more than half of the download in a day, with at least 300 MB of
upload — penalty. The path is independent of the two-way condition: otherwise a
quiet seeder would never reach it.

**Why a ratio and not gigabytes.** For an ordinary client, upload is TCP
acknowledgements, and their share is set by packet size rather than by the
person: 5–15% of the download, at ten megabits or at a gigabit. It never rises
above half, whatever the download. Between 21% and 59% in the data above lies a
gap, and a 50% threshold sits in the middle of it with a twofold margin either
way.

The volume floor is mandatory: an address with 10 MB down and 8 MB up has a
ratio of 80%, and that means nothing.

The signal is **off** by default.

### Preset [5]: everything at once

You used to have to choose: the torrent preset caught seeding but ignored
volume; the volume presets caught downloads but let seeders through. The new
preset turns on all three paths:

* instant seeding — the two-way condition with mandatory large packets;
* heavy downloading — an hourly threshold derived from the channel;
* the quiet seeder — the daily upload ratio.

The other presets now switch the ratio off explicitly: a preset must define the
whole state, or settings from another one would linger inside it.

### A column in the statistics

`91.78.14.134` sat sixteenth among six thousand addresses — the list is sorted
by volume, and a seeder downloads little by definition. Spotting it by eye was
nearly impossible.

The statistics now carry an **up/down** column; suspicious rows are highlighted
in red and lifted to the top. The rest stay sorted by volume: the list is also
there to show who loads the channel.

### Tests

22 new: the signal against all seven addresses from the live statistics, the
threshold and volume bounds from both sides, independence from the two-way
counter, the composition of the preset, and that the other presets switch the
ratio off. 981 in total.

---

## 3.21

**A follow-up to 3.20: attaching to `mq` queues does not always work, and then a
fallback is needed.**

The manual fix on a live node failed:

```
# tc qdisc replace dev eth0 parent :1 fq
Error: Failed to find specified qdisc.
```

The message is misleading. `fq` is present in the kernel — it is the **parent**
that cannot be resolved: `mq` on that machine has handle `0:`, so `parent :1`
means `0:1`, and the kernel treats zero as "unspecified". It cannot find a
parent by that.

The 3.20 engine honestly shouted that `fq` had not taken, but could not fix it —
it knew only one way.

### The fallback

If foreign qdiscs remain on the interface after the attempt to attach to the
queues, the engine replaces the root outright:

```bash
tc qdisc replace dev "$IFACE" root fq
```

One `fq` for the whole interface instead of a queue per CPU is a small loss of
parallelism, unnoticeable at tens of megabits. Downloads with no limit at all is
a far bigger loss.

The order matters: the gentle way first, leaving `mq` alone unless necessary —
it spreads queues across cores. Only if that fails, the root is replaced.

The `tc` error is now printed rather than swallowed: it was exactly what
explained the cause, and hiding it was a mistake.

### Tests

3 new: the fallback exists, runs after the check rather than instead of it, and
the `tc` error reaches the operator. 959 in total.

---

## 3.20

**Found the reason downloads could go completely unlimited. Check your nodes.**

### What happened

On a node with a 10 Mbit limit, addresses held 130–160% of the limit steadily,
not in bursts. `tc` showed the root:

```
qdisc mq 0: root
 qdisc fq_codel 0: parent :2 ...
 qdisc fq_codel 0: parent :1 ...
```

The queues carried `fq_codel`, not `fq`. The engine writes a departure time into
`skb->tstamp`, but **only `fq` holds a packet until that time**. `fq_codel` —
the default on Debian and Ubuntu — ignores the field and sends everything at
once.

So downloads were not limited at all. Uploads still worked: they use a token
bucket with drops and need no `fq`.

### Why nobody noticed

The engine assigned `fq` and swallowed the error:

```bash
tc qdisc replace dev "$IFACE" parent ":$i" fq 2>/dev/null || true
ok "fq assigned to $n queues (mq)"
```

The success message printed regardless of the outcome. The doctor looked only at
the root qdisc and cheerfully reported `mq` — technically true, while nobody
checked the queues underneath.

The node looked perfectly healthy otherwise: engine loaded, traffic counted,
penalties issued, autostart in place. The only symptom was percentages in the
monitor, easily written off as bursts.

### What changed

* the engine **verifies the result** instead of merely attempting: after the
  attempt it re-reads the queues and, if `fq` did not take, shouts in red and
  states plainly that downloads are not limited;
* it tries `modprobe sch_fq` first — on some kernels the module is simply not
  loaded;
* this does not abort loading: accounting, uploads and the whitelist work
  without `fq`, and a node with no shaper at all is worse than half a shaper;
* the doctor inspects **all** queues, not just the root, and names the culprit;
* the warning appears on the main status screen, where people actually look;
* a new metric `shape_edt_ready`: across a hundred nodes there is no other way
  to find one in this state. Zero means downloads are not limited.

### How to check your nodes

```bash
/opt/shaper/shaperctl.py show
```

If all is well, nothing new appears. If not, you get a red line. The fix:

```bash
modprobe sch_fq && systemctl restart shaper
```

If `modprobe` complains, `sch_fq` is missing from the kernel — you need a
different kernel image or the `linux-modules-extra` package.

### Tests

17 new: parsing real `tc` output in every variant (`mq` with `fq`, `mq` with
`fq_codel`, plain `fq`, `pfifo_fast`), staying quiet when `tc` fails or there is
no interface, and the honesty of the engine and the doctor. 956 in total.

---

## 3.19

**Seeders no longer slip past the watchdog, and the penalty message names the
person.**

### The download floor caught the wrong people

An address with 3.4 Mbit down, 7.1 up and 1400-byte packets against a 10 Mbit
limit is a torrent, plainly. The watchdog left it alone.

The mandatory condition was the reason: it demanded **both** a download above
50% of the limit **and** upload. But a seeder downloads less than it uploads, by
definition. It never reached five megabits down, so the scoring stage was never
even reached — no matter how much it seeded.

In the torrent preset the download floor drops from 50% to **10%**. That is safe
precisely because the same preset requires large upload packets: an ordinary
download also passes the low floor but fails on packet size — acknowledgements
stay short at any speed.

The other presets are untouched: their download floor is still 50% and they do
not require packets.

### The penalty message says who it is

Before: `Limited 203.0.113.7 → 1 Mbit/s`. Now: `Limited Bashou · 203.0.113.7`,
with a link to the person in Telegram.

The address-to-user map is collected by the same panel poll that looks for
sharing: the data has already arrived, so it costs zero extra requests. The name
is looked up individually and only when a penalty is actually issued — rarely.

The local owners list (`owners.json`) still wins: it is filled in by hand and is
therefore more reliable. The panel is consulted only when it is empty.

The map lives in the watchdog's memory and is never written to disk. Older than
half an hour and it is ignored: by then the address may belong to somebody else,
and signing a penalty with the wrong name is worse than not signing it.

### If penalty messages do not arrive

Check that **both** switches are on: Telegram itself and events.

```bash
shaperctl.py telegram show
shaperctl.py telegram set --events on
```

Without `events` penalties are issued silently — it is a separate setting, not
part of the general one.

### Tests

16 new: the address map is collected without extra requests, name and Telegram
are filled in, a stale map is ignored, a non-numeric identifier does not break
sending, and preset thresholds stay put. 939 in total.

---

## 3.18

**The panel moved to the main screen, and that screen finally shows everything.**

### What was wrong

The panel screen showed some settings and mangled others:

```
Threshold  : 20 / 10 Window
Action     : notify   1/60
Polling    : 300 · Alert pause 360
```

`1/60` is the penalty speed and its minutes, but there was no way to guess
that. Numbers had no units: 300 of what, 360 of what. The "Window" label sat
after its value like a tail. Panel names were not shown at all.

The cause: fields glued into one string when reading the config, and labels
doing double duty as column headers and as units.

### How it looks now

```
State       : enabled
Address     : https://admin.badgerproxy.com
Node UUID   : 5d8bba03
Token       : eyJhbG… · valid until 2848-01-06
Polling     : 300 s
Threshold   : 20 addresses / 10 min
Action      : notify
Penalty     : 1 Mbit/s · 60 min
Alert pause : 360 min
Names       : enabled
Node report : 09:00
Exempt      : 97, 346
```

Every setting on its own line, with units, labels aligned. The config reader
returns one value per field: no more glued pairs to take apart later.

### The panel is on the main screen

It used to be **Service → [11]**, now it is **[9]** on the main screen with its
state beside it. Service is a once-a-month place — updates and removal; the
panel is daily. Service went back to its old numbering: backup is [11] again,
removal [12].

### Why labels are padded with spaces rather than printf

`printf %-14s` in bash counts bytes, and Cyrillic takes two per character in
UTF-8. In English the column is straight; in Russian it drifts. So the width is
baked into the translation strings — and a check now guards it: every label on
the screen must be the same length.

### Tests

7 new, all in the shell suite: equal label widths in both languages, no glued
fields in the config reader, units present, the panel on the main screen, and
the old numbering back in Service. 923 in total.

---

## 3.17

**The report is always a file, and the offender's addresses live in a collapsed
quote.**

Two fixes that came out of running this on live nodes.

### The report arrived in two shapes

A short report was sent as a message, a long one as an attachment. On Narnia
with 61 users it was text in the chat; on Hogwarts with 76 it was a file. The
same report looked different on neighbouring nodes, comparing them was awkward,
and on a node that grew the shape changed by itself.

The report is now **always a file**. The message carries the summary: node,
users connected, addresses.

### The offender's addresses are in a collapsed quote

They used to be a code block: a hundred addresses stretched the chat, and a
"copy" button sat on top of it, which makes no sense here — addresses are not
copied in bulk.

Now it is an expandable quote. Closed by default, opens with a tap, no file
download needed. In the Bot API this is `expandable_blockquote`; in markup,
`<blockquote expandable>`.

The hard cap of twenty addresses went away with it: since the list is collapsed,
showing fewer than fit in the message serves no purpose. About two hundred and
fifty addresses go into the quote; the rest still arrive as an attachment.

### Tests

2 new, 6 rewritten for the new behaviour: the quote is expandable and is not a
code block, a hundred addresses fit whole, four hundred go to a file, and the
report arrives as an attachment regardless of size. 916 in total.

---

## 3.16

**Blocking an offender, and a card you can act on straight away.**

Finding a reseller is not enough — an internal `#741` tells you nothing about
who to write to. The message now carries everything needed to sort it out, and
access to the node can be cut off on the spot.

### The card

```
🔎 Looks like a shared subscription · FRONT-3

👤 Bashou
🆔 Telegram: 637181482
🔑 Panel ID: 741

Simultaneous addresses: 437 over the last 10 min
🚫 Access to the node cut off for 60 min, addresses: 412
Connections dropped: 437
```

The Telegram ID and the panel ID are on their own lines and wrapped in `<code>`:
in Telegram that copies with a single tap. You will be searching by them anyway,
and nobody should retype nine digits off a screen.

A Telegram handle like `@bashoyy` is not stored by the panel — there is no such
field on its user card, so there is none on ours. The name and the numeric
Telegram ID are there.

### The new `block` action

```bash
shaperctl.py panel set --action-set notify,block --minutes 60
```

Cuts off access to the node: a minimal speed on every address of the offender
the node can see, plus a drop of the current connections. It lifts itself after
an hour.

### Why blocking is 0.05 Mbit and not zero

Zero in the kernel map means "no limit". The engine is written that way on
purpose: between the check and the application the limit could have been removed
from userspace, and a packet at zero speed would sail past all accounting.
Blocking with zero would quietly turn into complete freedom — the exact opposite
of the intent.

So a minimal speed is used instead. The arithmetic:

```
0.05 Mbit/s          = 6250 bytes/s
a 1500-byte packet   = 240 ms
queue horizon        = 2 s  →  eight packets fit
```

Everything else is dropped and a TLS handshake never completes. From the outside
it looks like the internet is gone.

Dropping connections is part of blocking and needs no separate switch: without
it, established connections would merely become slow and the person would stay
"online" until they timed out.

If both `limit` and `block` are set, `block` wins.

### Details

* when only `notify` is on, the card says so outright: nothing was done.
  Previously you had to infer it from missing lines;
* the address-list attachment now has a header — name, panel ID, node, time. The
  file gets forwarded and opened away from the message, so it must stand alone;
* blocking leaves the whitelist and existing penalties alone, same as ordinary
  limiting.

### Upgrading

`block` never enables itself. The default action is still `notify`.

### Tests

21 new ones: the card's contents and the copyability of the identifiers,
blocking together with the drop, its precedence over ordinary limiting, and the
bounds of the blocking speed. Separately verified: the engine really does pass
traffic at zero speed — the whole design rests on that fact. 914 in total.

---

## 3.15

**Names and Telegram IDs instead of internal numbers, and a node report: who is
connected and from which addresses.**

In the connections reply the panel returns only a user number — 97, 346. That
tells you nothing about who to write to. The name and Telegram ID live in the
user's card, and Shape now asks for them separately: the message says
`Elena (851400228)`.

This needs the **Users → Read** scope on the token. Without it everything keeps
working, just with numbers; `--resolve off` turns it off entirely.

### Node report

Once a day at a time you choose: who is connected and what addresses they use.

```bash
shaperctl.py panel set --report on --report-at 09:00
shaperctl.py panel report        # send it now
```

```
Node report FRONT-3 · 2026-08-23 09:00
Users connected: 138
Addresses in total: 412

Nikita (7288183505) — 437  ⚠
    1.2.3.4
    …
Elena (851400228) — 2
```

Sorted by simultaneous address count; anyone above the threshold is marked. The
report can go to its own topic: `--report-thread 777`.

### Long things go as files

A Telegram message holds 4096 characters. Four hundred addresses of one reseller
is seven kilobytes, and a report on a hundred and fifty people is larger still.
Truncating silently is not an option: the address list is the whole point.

So short stays a message and long goes as an attachment. In the sharing alert:
the first twenty addresses inline, the full list as a file right after. Shape
could already send documents — that is how weekly backups travel; now it is one
shared function rather than two similar ones.

### What this costs the panel

An offender is looked up by number — one request, and only once they are found.
The full directory is fetched for the report alone, once a day, a thousand
records per page: on a panel with six thousand accounts that is six requests
against a hundred and forty if each connected user were asked about separately.

Three fields are kept from each card — number, name, Telegram ID. The other
twenty are dropped immediately: on a node with 512 MB of RAM the difference
shows. The directory is never written to disk — it is other people's personal
data, and a node has no business storing it.

### Details

* a denied directory does not sink the report: it goes out with numbers instead
  of names;
* page walking does not rely on "the page is shorter than requested" — a panel
  may legitimately return less, which would cut the directory off at page one;
* a missed report is not caught up: if the node was down past the hour, it waits
  for tomorrow. A report about who is connected now is worthless a day later.

### Upgrading

The new fields arrive switched off: no report is sent by default, and names are
resolved only if the token has the scope. Nothing needs reconfiguring.

### Tests

46 new ones: directory pagination and caching, the user label in every variant,
the boundary between a message and a file, the report's contents and ordering,
its schedule, and the behaviour when the scope is missing. 893 in total.

---

## 3.14

**Shared-subscription detection: Shape asks the Remnawave panel who owns the
addresses it sees, and finds the users who gave their key away.**

A node sees addresses but not their owners. The panel knows the owners. Putting
the two together answers a question neither side can answer alone: how many
addresses of one user are alive on this node right now.

### Why the device limit does not catch this

Remnawave's HWID limit restricts **fetching the subscription**, not connecting.
The client sends an `x-hwid` header when it downloads the link, and the panel
returns 404 for the sixth device. After that the client holds a `vless://…`
string, and no HWID is involved at connection time — the node only sees a UUID.

Three holes follow, and any one of them explains hundreds of addresses under a
five-device limit:

* the reseller shares the raw config instead of the subscription link, so the
  device counter never moves while the key works for everyone;
* the client does not send the header at all (several apps have it off by
  default);
* the limit is disabled for that user individually.

Shape comes at it from the other side: it looks at addresses, not devices.

### What separates sharing from mobile internet

Simultaneity. A person with a phone racks up dozens of addresses a day, but only
one is alive at any moment. So Shape counts only the addresses the panel saw
within the last `window_min` minutes — every address in the panel's reply
carries a `lastSeen` stamp.

Defaults: 20 addresses within a 10-minute window.

### What to do about it

Three actions, combinable with commas:

| Action | Effect |
| --- | --- |
| `notify` | a Telegram card: who, how many addresses, examples |
| `limit`  | a local penalty on the addresses this node can see itself |
| `drop`   | drop connections through the panel — by address, on this node only |

Only `notify` is on by default. Throttling someone else's customers without the
node owner's knowledge is not acceptable, so that is switched on by hand.

Dropping without limiting is a signal, not a punishment: the client reconnects a
second later. `limit` is what bites — it holds for the configured minutes.

### The token needs narrow scopes

A panel key will sit on every node, so it should not carry full access. This is
enough:

```
connections:by-node
connections:by-node-result
connections:drop          ← only if you enable dropping
```

Leaking such a token grants neither access to users nor the ability to change
anything — at most, a look at the addresses on one node.

The token's lifetime is chosen when it is created. Shape reads it from the token
itself, with no panel request, and warns in Telegram a week before it expires —
otherwise the feature would fall silent on every node at once, with nothing to
notice it by.

### The node stays independent

That is the property that matters, and it is covered by tests. Panel
unreachable, token expired, different API version — the watchdog and the rate
limiting carry on exactly as before. The poll has its own hard deadline so a slow
panel cannot delay penalties, and a 15-minute pause after an error so a broken
panel is not hammered.

### What is new

* a `panel` section in the config; the token and proxy are marked as secrets and
  stay out of backups;
* the **Service → 🛰 Remnawave panel** screen;
* `shaperctl.py panel show|set|test|scan`; `test` and `scan --dry-run` report
  findings without changing anything;
* metrics `shape_panel_up`, `shape_panel_last_success_seconds`,
  `shape_panel_token_expires_seconds`, `shape_panel_sharing_found`;
* a `sharing_found` event in the log.

`shape_panel_up` is a separate metric on purpose: without it, a silent panel
looks exactly like a panel where nobody is cheating.

### Details

* `exempt` lists the users who are allowed to share; a `userId` may be written as
  a number or a string;
* the threshold never drops below two addresses, whatever the settings say — one
  would mean "throttle everyone who connected";
* limiting touches only addresses present in the node's own map; the whitelist
  and existing penalties are left alone;
* a 6-hour cooldown per user, so the alerts stay worth reading.

### Upgrading

The `panel` section is added to an existing config disabled, with an empty
address and token. After the upgrade a node sends nothing anywhere until you turn
it on yourself.

### Tests

79 new checks against a fake panel that replies exactly like the live 3.2.3 one:
the two-step job, the `response` wrapper, the numeric `userId`. Plus 5 checks for
carrying settings over from an older version. 847 in total.

---

## 3.13

**Large upload packets as a mandatory condition, and packet size in the monitor.**

A torrent with weak seeding escaped auto-limiting: it never reached the 15%
upload floor. Lowering the floor was the obvious move, but on its own it is
dangerous.

### Why lowering the floor is not enough

Downloading generates acknowledgements upstream, and their volume grows
together with the download speed:

```
37.9 Mbit/s down ≈ 1700 acknowledgements/s ≈ 1.5–2.0 Mbit/s of "upload"
```

On a 50 Mbit node an ordinary download already produces about two megabits
upstream, and twice that on a 100 Mbit one. An absolute threshold would catch
it along with the seeding.

### What tells them apart reliably

The average upload packet size — the only figure independent of channel speed:
100–170 bytes for acknowledgements, 1200–1400 for data.

Shape measured it before, but it was worth two points out of three, so a
penalty could land without it. There is now `--require-packet on`: with it the
two-way counter does not grow while upstream packets stay short.

### The torrent preset

The upload floor drops from 15% to **3%** — one and a half megabits at a
50 Mbit limit — with the large-packet requirement enabled at the same time. A
low floor is safe with it: acknowledgements never pass, at any speed.

The lower bound of `--both-ul` moves from 5% to 1%: the old one would not
accept one and a half megabits at a 50 Mbit limit.

### Packet size is visible in the monitor

A new `packet` column between upload and average. Values from 600 are
highlighted:

```
IP                       now  upload packet     avg holding  share of limit
88.135.124.138          37.9     4.6   1280    23.4     4 s  █████████▏··  76%
89.109.51.149           13.9     0.8    150     5.1       —  ███▍········  28%
```

The difference is immediate: 1280 bytes for the seeder against 150 for the
downloader. Previously only the watchdog saw this number, leaving no way to
check a hunch.

### Fixed

**`shaperctl.py guard --help` crashed with `ValueError: incomplete format`.**
Three help strings contained a bare percent sign, and argparse runs them
through %-formatting. The bug was long-standing and unrelated to this release —
it surfaced while adding the new argument. The texts now spell the word out,
and a check was added so it cannot return.

### Checks

23 new checks: gate behaviour with and without the signal on slow and fast
nodes, edge values of packet size, setting bounds, and `--help` parsing. The
core suite now holds 102.

### Upgrading

Existing settings are untouched: `require_packet` is off by default. To adopt
the new behaviour — **Auto-limit → Presets → [3]**.

## 3.12

**A preset for fast nodes: the hourly cap is derived from the channel.**

There was a gap between the "mobile" preset with its hard 3 GB per hour and
the "universal" one, where the hourly cap is off entirely. On a 100 Mbit node
a client comfortably pulls forty gigabytes an hour while the watchdog stays
silent until the daily cap builds up — more than an hour later.

### Why a fixed number will not do

Gigabytes per hour mean nothing on their own:

| per-address limit | a full hour at that speed | what 3 GB/h is |
|---|---|---|
| 10 Mbit/s | 4.5 GB | two thirds of the channel |
| 100 Mbit/s | 45 GB | six percent |

The same threshold catches a downloader on a slow node and fires on a single
film on a fast one.

### What the new preset does

It takes **half the channel per hour**:

```
cap = limit_Mbit/s ÷ 8 ÷ 1000 × 3600 × 0.5
```

That is 2.2 GB/h for 10 Mbit/s, 11.2 for 50, 22.5 for 100. The meaning is one
thing: "held more than half of its own bandwidth for a full hour". 4K video
runs around 7 GB per hour and stays below; a sustained bulk transfer gets
caught.

The computed number is shown before it is applied, together with what a full
hour at the limit would amount to. With no speed limit set there is nothing to
derive from: the preset says so plainly and offers a fixed 20 GB.

The rest: a 100 GB daily cap and a 1 Mbit/s penalty for an hour. An hour
rather than four — the trigger is already strict, and whoever carries on will
be caught again.

### Checks

10 new checks in `tests/audit_shell_tests.sh`, including the conversion
arithmetic for four speeds. An error in that formula would quietly make the
cap eight times stricter or looser, and it would surface as complaints.

### Upgrading

Existing settings are untouched. The preset is applied by hand:
**Auto-limit → Presets → [4]**.

## 3.11

**Removing Shape from the menu.**

Until now, taking Shape off a node required `install.sh --uninstall` from the
repository — and the installer is not copied onto the node, so it is not there
when you need it. It is now a menu item: **Service → 🗑 Remove Shape**.

### One implementation instead of two

The removal logic moved into `uninstall.sh`, which is installed alongside the
other files. Both the menu and `install.sh --uninstall` call it. Keeping this
in two places is not an option: the implementations would drift apart, and one
of them would eventually leave a live eBPF program on the node.

### What got fixed along the way

The previous inline removal block did not clear the **metrics file** from the
node_exporter directory. The file is static — after Shape was removed,
Prometheus would keep serving its numbers and showing the node as alive. It is
now deleted.

A `--purge` mode was added: by default `/etc/shaper` and `/var/lib/shape` stay,
so reinstalling gives the node back its identifier, tokens and history. With
`--purge` those go too.

### The order of steps

It matters more than it looks, and is now covered by a test:

1. stop the services;
2. **detach the program from the interface while `/opt/shaper` is still
   there** — once the files are gone `engine.sh` cannot run, and the filters
   would stay on the NIC until a reboot;
3. remove the metrics file;
4. delete units and files.

The script lives in the directory it deletes, so it works from a copy in a
temporary directory: bash reads a script as it executes, and removing
`/opt/shaper` could otherwise cut it off midway.

### Three barriers in the menu

The action is irreversible and drops the limit for every client instantly, so
"y/N" is not enough here — those get pressed without reading. The screen spells
out the consequences, offers to take a backup first, and requires typing the
word `DELETE` in full.

### Checks

A new `tests/uninstall_tests.sh` suite — 36 checks. The script is destructive,
so it runs end to end in a sandbox: paths come from `SHAPE_*_DIR`, `systemctl`
and `tc` are replaced by stubs that log their calls. What is checked is not the
text of the script but the order of actions and what is left on disk.

### Upgrading

Nothing to configure. `uninstall.sh` lands on the node with the first upgrade.

## 3.10

**Top of the load in the API, and an upgrade check from an older version.**

Two items that are cheaper to do now than after rolling out to a hundred
nodes.

### `GET /api/v1/top`

Who is loading the channel right now — the same thing the monitor shows, only
as JSON.

```
GET /api/v1/top?limit=20&sort=download
```

The point is the cap on the response. With a hundred nodes and three hundred
addresses each, "give me everything" means thirty thousand rows per polling
cycle, of which the first twenty matter. `limit` ranges from 1 to 200; `sort`
is `download`, `upload` or `total`.

Each row already carries everything a central system needs to decide: current
speeds, accumulated volume, idle time, whitelist and active-limit flags, the
personal speed and the address owner.

Speeds are computed from the difference between two reads of the kernel maps,
so the first response does not carry them yet. The list is then sorted by
accumulated volume, and the `sorted_by` and `note` fields say so — rather than
passing zeros off as the truth. The map snapshot is shared with
`/api/v1/stats`: the two endpoints reuse a single read instead of poking
`bpftool` twice as often.

### Upgrade check from an older version

A new `tests/upgrade_tests.py` suite — 46 checks.

The installer is not run in CI: it needs root, installs packages and registers
units. But what breaks on upgrade is not the installer — it is reading the old
state, where the config lacks fields added later and the `node_id` file does
not exist yet. The suite drops state into a sandbox exactly as version 3.4
wrote it and checks that the current Shape picks it up in full: settings are
filled in from defaults, limits and personal speeds survive, history and
owners are read, metrics build, and a backup is produced and restored.

Separately it checks the one place in the installer that could quietly ruin a
node: creating `node_id`. The fragment is taken from the real `install.sh` and
executed twice in a temporary directory — overwriting the identifier would
break the metrics history with nothing to notice it by.

### Fixed in the tests

The `/api/v1/top` block initially landed after the test server was shut down,
so the requests went nowhere. Cyrillic in the query string and in the
`Authorization` header crashed the HTTP client rather than the server, so the
wrong thing was being tested. Both were fixed.

### Upgrading

Nothing to configure. The new endpoint is available with a read token wherever
the API is installed; nodes without the API are unaffected.

## 3.9

**The speed is out of the configuration fingerprint.**

The fingerprint arrived in 3.8, and the very first check against a real fleet
showed that deriving it from the speed was wrong.

### Why

Nodes have different uplinks, and the per-address limit is set to match:
10 Mbit/s here, 100 there. That is a deliberate decision, not drift. Inside
the fingerprint, though, the speed produced as many groups as there were
tiers — and the question "is this intended, or did someone change something?"
would come up every time you looked at the panel. An indicator that lights up
for no reason stops being noticed.

The fingerprint is now derived from **the ports and the auto-limiter settings
only** — from what genuinely should match. You will have as many groups as you
have policy variants: one if the auto-limiter is identical everywhere, two if
on a narrow uplink you catch an offender sooner and punish for longer.

The speed has not gone anywhere: it is exposed as its own metric,
`shape_speed_limit_mbps` — a number that graphs well and shows at a glance
where 10 is and where 100 is.

### What changes in practice

**Fingerprint values have changed.** If you wrote them down after upgrading to
3.8, write them down again — the old ones will not match. Nothing breaks: the
fingerprint is stored nowhere, it is computed on the fly on every call.

Changing the speed via `apply --speed` no longer changes the fingerprint.
Changing watchdog thresholds or ports still does, as before.

### Checks

Checks were added that the speed does not affect the fingerprint in any
form — including removing the limit altogether — and that it is nonetheless
exposed as its own metric. The backup suite now holds 188 checks.

### Upgrading

Nothing to configure; shaper behaviour is unchanged.

## 3.8

**A node can now be recognised, and drifted settings can be seen.**

Two small changes that are cheaper to make before the central system than
after: otherwise all twenty-eight nodes would need updating for one field.

### Permanent node identifier

`/var/lib/shape/node_id` — sixteen hex characters, created once at install.
It survives a Shape upgrade, a move to another server and a hostname change.
Without it a year-long monitoring graph falls apart into two halves belonging
to "different" nodes the moment a host gets renamed.

`machine-id` will not do: nodes are rolled out from an image and clones share
it — so it would fail in exactly the case this was built for.

The identifier is **not** part of a state backup. Restoring a copy on a new
server gives you a node with its own identifier, not a twin.

### Configuration fingerprint

Twelve characters derived from the speed, the ports and the auto-limiter
settings. The same fingerprint means the same policy; a different one shows up
in monitoring at once.

With a hundred nodes someone will one day fix the speed by hand on one of
them, and there is otherwise nowhere to learn about it — the complaint arrives
a month later.

Deliberately excluded from the fingerprint:

* **the `telegram` section** — the node label and topic differ there by
  design, and the fingerprint would become unique per node, i.e. useless;
* **`watch_interval`** — a CPU-load knob rather than policy: on a weak VPS it
  is routinely raised, and a permanently "drifted" node would teach you to
  ignore the indicator altogether.

### Where it shows

* `shaperctl.py show` — a dimmed footer line: `node … · fingerprint …`
* `node_id` and `config_hash` labels on the `shape_info` metric
* `/api/v1/status` (the `node` section) and `/api/v1/node`

The query that reveals drift across the fleet:

```promql
count by (config_hash) (shape_info)
```

One row in the answer means every node is configured identically.

### Node independence check sharpened

The `api_independence_tests.sh` suite forbade any identifier matching a name
pattern, `node_id` included. The point of the check was different — nodes must
not be tied together by a shared key or shared state. It has been rewritten to
match that intent: `cluster_id`, `global_state` and shared secrets are
forbidden, and three new checks were added — the identifier is generated
randomly on the node itself, is not derived from `machine-id`, and does not
travel in a state export.

### Upgrading

Nothing to configure. The identifier is created on the first upgrade; the
installer never overwrites an existing one.

Once the fleet is upgraded, fingerprints are easy to compare:

```bash
shaperctl.py show | tail -2
```

## 3.7

**Notifications work without a proxy.**

On nodes that need no proxy — American, European, anything outside the
Russian blocking — sending to Telegram always failed with
`module 'urllib.request' has no attribute 'open'`.

### Fixed

* **Sending without a proxy.** In the proxy-less branch the `urllib.request`
  module itself was used in place of an opener: it has `urlopen`, but no
  `open`. Every send — test message, event, daily digest, backup — died on
  `AttributeError`.

  The bug survived for an understandable reason: Shape was deployed on
  Russian nodes, where a proxy is always configured, so that branch never
  ran. The first node without a proxy exposed it.

* **The proxy hint no longer misleads.** It was appended to any error, so a
  fault inside Shape looked like Telegram being blocked and sent diagnosis
  down the wrong path. The hint now appears only on network errors, and only
  when no proxy is actually configured.

* **Environment variables no longer override the setting.** Without a proxy,
  requests would have gone through `http_proxy` from the environment if one
  was set. Shape has its own proxy setting and should not pick one up from
  anywhere else.

* **UDP is now covered by tests.** The UDP parsing branch has been in the
  eBPF program from the start — Hysteria2, and QUIC in general on 443, is
  shaped exactly like VLESS over TCP. But the whole harness only ever fed
  it TCP, so that branch was never exercised. 13 checks were added:
  accounting in both directions, delay under the limit, direction
  strictness (the node's own outgoing QUIC does not match the rule), a
  truncated header, the whitelist. The harness now holds 36 checks.

### Why the tests missed it

Every previous Telegram check replaced `_post` wholesale — meaning the
transport itself never ran. 33 checks were added that patch one level lower,
at `urllib` and sockets, and exercise the real sending code both directly and
through SOCKS5. The suite now holds 156 checks.

### Upgrading

Nothing to configure. On a node without a proxy, after upgrading:

```bash
shaperctl.py telegram test
```

Leave the proxy field empty — that is now a working setting rather than a
broken one.

## 3.6

**Backups go to Telegram.**

A copy sitting on the same disk that will one day die is not a copy. Shape now
uploads node state as a file to Telegram once a week — to the same place the
reports arrive, or to a separate topic.

### Added

* Weekly backup upload: `telegram set --backup on --backup-day 1`. The weekday
  is configurable; the time is the same as the daily digest.
* A separate topic for backups: `--backup-thread`. Empty means the copy goes
  wherever ordinary messages go.
* `shaperctl.py telegram backup` — send a copy right now.
* Items [4]–[7] on the **Service → 💾 Backup and restore** screen.
* File upload via `sendDocument` with `multipart/form-data` assembled on the
  standard library — works both directly and through the SOCKS5 proxy that
  Russian nodes rely on.
* 43 new checks in `tests/export_tests.py`, 128 in the suite overall.

### What is not in the copy, and never will be

**The bot token does not go into a copy uploaded to Telegram under any
setting.** The bot posts into the very topic it uploads the file to: anyone in
that topic — now or added six months later — would gain control of the bot and
its whole history along with the token.

The check does not rest on a flag alone: right before sending, the payload is
compared against the configured secrets once more, and a match cancels the
upload entirely. That is insurance against the code being changed badly some
day — it should fail before the token reaches the chat, not after.

A copy with secrets is still possible, but only as a file on disk:
`export --with-secrets`, for moving a node.

### Worth remembering

The file holds client IP addresses, and names and telegram_id values when
owners are filled in. That is personal data, and in Telegram it stays forever,
visible to everyone in the topic. The menu warns about this when you enable it
and asks for confirmation.

### Behaviour on failure

* No connectivity — the next attempt is in an hour, not every ten seconds.
* A missed day is not caught up: the state sent is the current one, not what
  it was on Monday.
* A malformed weekday, a corrupted state file and an unreachable API do not
  bring the watchdog down — each is covered by its own test.

### Upgrading

The setting is off by default and shaper behaviour is unchanged. To turn it
on:

```bash
shaperctl.py telegram set --backup on --backup-day 1
shaperctl.py telegram backup        # check it straight away
```

## 3.5

**Node state backup.**

Node state — settings, whitelist, personal speeds, active limits, address
owners and daily history — can now be exported to a single file and restored
from it.

The reason is plain: going from twenty-eight nodes to a hundred leaves no
room for repeating setup by hand, and a backup sitting on a dead disk is not
a backup.

### Added

* `shaperctl.py export --out FILE` — export state into a single JSON.
* `shaperctl.py import FILE` — restore, with `--dry-run`, `--only`
  and `--replace`.
* A **Service → 💾 Backup and restore** screen: save, restore with a
  mandatory parse-and-confirm step, and a separate file check.
* A `tests/export_tests.py` suite — 85 checks, including the round trip
  "export → wipe → restore → state matches".

### How it is protected

* **Secrets are not exported by default.** The bot token and proxy password
  stay out of the file; `--with-secrets` is there for cloning a node. The
  file is created with mode `600`, and the mode is set before writing rather
  than after.
* **The receiving node's token is never wiped.** Restoring from a
  secret-free backup leaves the token configured here in place — otherwise
  notifications would go silent without a word.
* **The file is not trusted.** It may come from another node or have been
  edited by hand, so every value goes through the same checks as ordinary
  input: addresses, speeds, ports, field types in the `guard` and `telegram`
  sections. Anything unusable is dropped with a note instead of crashing the
  command halfway through writing.
* **Writes go through the normal functions only** — `save_config`,
  `penalties_update`, `owners_update`. An import writing to files directly
  would bypass the locks that protect them from concurrent edits by the
  watchdog.
* The format carries a version: a file from a newer Shape is rejected with a
  clear message rather than parsed halfway.

### Fixed

* The CI secret scanner matched the sample tokens in the test suites and
  would have failed the build. The values are unchanged, but the sources no
  longer contain a contiguous literal that looks like a real token.

### Upgrading

Nothing to configure; shaper behaviour is unchanged. Right after upgrading it
is worth taking a copy:

```bash
shaperctl.py export --out /root/shape-$(hostname -s).json
```

and copying the file off the server.

## 3.4

**Holding time is back, and the whitelist became visible.**

- **The "holding" column returned.** In 3.3 it became a mark on the left, and
  the important part went with it: how many minutes in a row an address has
  been loading the channel. The mark only says "over thirty seconds", while
  the difference between two minutes and forty-four is the difference between
  a burst and a torrent.
- **Whitelisted addresses now show up in the monitor, the statistics and the
  metrics.** The whitelist check used to sit in eBPF **before** accounting, so
  such an address vanished everywhere: there was no way at all to tell how much
  of the channel it was eating. And it can eat any amount — the limit does not
  apply to it. Now everyone is counted and not everyone is limited.
- A **✓** mark tags those addresses in the monitor so they are not mistaken for
  ordinary ones.
- The "1-min avg" header was shortened to "avg": next to "upload" it did not
  fit and ran into the neighbouring column.

The change touches the eBPF program, which is rebuilt automatically on update.
Settings, penalties and the whitelist are untouched.

## 3.3

**The monitor got a new look.** Rendering only — not a single extra call into
the kernel, apart from reading the penalty list once every five seconds.

- **Bars are smooth now.** A block used to be either whole or absent: at twelve
  characters wide that gave twelve levels in total, and the difference between
  7.3 and 7.4 Mbit/s was invisible. Eighth-width blocks give 96 levels at the
  same width.
- **Colour follows the share of the limit, not the "holding" flag.** Grey up to
  20%, green to half, yellow to 80%, red above. Previously colour appeared only
  when an address had been holding load for over thirty seconds, so on a quiet
  node the screen was monochrome and the eye had nothing to catch.
- **Upload has its own colour scale.** Mobile carriers give a narrow uplink, so
  noticeable upload is the first sign of seeding. An address that downloads
  little but uploads a lot is now visible at once.
- **The "holding" column became a mark on the left.** In a quiet hour it was
  nothing but dashes and wasted nine characters. The freed space now shows the
  share of the limit in percent, which is what the bar length means anyway.
- **A ⊘ mark on limited addresses.** The monitor used to give no hint that an
  address was already under a penalty — you had to open another screen.
- **A channel sparkline for the last minute** in the header: you can see
  whether load is rising or falling.
- A "showing N of M" footer instead of "… N more active", separators and
  aligned columns.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.2

**Metrics no longer require the API.**

Metric text assembly moved from `api/server.py` into `shaperctl.py`, next to
the rest of the logic. This fixes a violation of the project's own rule: logic
lives in the shared layer, the API is a thin shell over it.

- **`shaperctl.py metrics`** prints the same metrics to stdout, and with
  `--out` writes a file for the node_exporter textfile collector — through a
  temporary file and a rename, so the exporter never reads half a file.
- **A monitoring wizard** in the menu: Service → 📈 Monitoring. It finds the
  node_exporter directory, installs a systemd timer, shows a ready
  `scrape_configs` snippet and can switch everything back off.
- The timer refreshes the file once a minute. No open ports, no tokens and no
  API are needed for monitoring any more.
- **New metric `shape_metrics_complete`:** zero means the BPF maps could not be
  read and the numbers are incomplete. "No traffic" and "we could not look" are
  different things, and monitoring now tells them apart. The dashboard got a
  panel for it.
- On top of the shared set the API adds two of its own metrics: `shape_api_up`
  and `shape_api_uptime_seconds`.
- Channel speed is derived from the previous sample, and that sample lives in a
  file rather than in process memory — so it works for one-off CLI runs and for
  any mix of sources.
- State and configuration directories can be overridden with `SHAPE_VAR_DIR`
  and `SHAPE_ETC_DIR`, which lets the tests run the real CLI without touching
  the system.
- The test suite now checks that the metric set from the CLI matches the one
  from the API, apart from the two API-only metrics. CI runs the no-API path as
  a separate step.

In the menu, "Monitoring" is item nine under Service; the API moved to ten.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.1

**Monitoring, history and groundwork for user names.**

- **Prometheus metrics** at `/metrics` — with a `node` label on every metric so
  graphs are labelled by node name rather than by address and port. A ready
  Grafana dashboard for the whole fleet and a sample `scrape_configs` live in
  `grafana/`. By default metrics require a read token; on a private network
  they can be opened with the `metrics_public` flag.
- **History by day.** Before the counters reset at midnight, a row is written
  to `/var/lib/shape/history.jsonl`: date, volumes, address count, how many
  limits were issued and the five heaviest addresses. A hundred bytes a day.
  Menu → Statistics → History, `shaperctl.py history`, `GET /api/v1/history`.
- **Personal speeds.** A permanent speed for one address — above or below the
  shared limit. Built on the existing penalty mechanism; no kernel changes were
  needed. Auto-limiting leaves such addresses alone and they are not shown in
  the limited list.
- **An owner map for addresses.** `/var/lib/shape/owners.json`: name,
  telegram_id, panel identifier, shared-address flag. The label is attached to
  a limit at the moment it is issued and reaches the notification — with a
  `tg://user?id=…` link that works even without a username. Filled in by hand or
  in bulk through `PUT /api/v1/owners`. A Remnawave resolver will write here
  once it exists; Shape itself never goes looking for this data.
- **Graceful API token rotation.** The previous pair is accepted for another
  day, so the central system can be updated at a comfortable pace without 401s
  on half the fleet.
- **Tests moved into the repository** (`tests/`) and run in GitHub Actions on
  every push: syntax, ShellCheck, ruff, bandit, an eBPF build with the real
  clang, the program run against synthetic packets, 208 API checks, version
  consistency and interface strings, and a search for accidentally committed
  secrets.

Updating is safe: settings, penalties and the whitelist are untouched.

## 3.0

**Node API — an optional interface for external systems.**

```
central system  →  Shape API  →  Shape  →  BPF
```

- A local HTTP service `shape-api`, versioned from the start at `/api/v1/`.
  It listens on `127.0.0.1:8765` by default, exposes nothing outward and does
  not touch the firewall. For a private network the address and the allowed
  networks are set in the menu.
- **The API has no limiting logic of its own.** It calls the same
  `shaperctl.py` functions the menu does, so behaviour cannot drift apart.
- Endpoints: health, status, node, limits (list, one address, create, remove,
  temporary), stats, events, config, bpf/status. The OpenAPI schema is served
  at `/api/v1/openapi.json`, the documentation page at `/api/v1/docs`.
- Two tokens: read-only, and read plus write. Generated on the node itself at
  first start, stored in `/etc/shaper/api.json` with mode 600, absent from the
  repository. Reissued from the menu.
- Rate limiting separately for reads, writes and failed authorisations. Limits
  on body size, on the number of concurrent handlers and on process memory.
- Structured errors with a code and a `request_id`; no tracebacks reach the
  client. The same `request_id` is written to the node's log.
- **Shape stays self-sufficient.** The API unit is tied to the shaper unit by
  nothing but `After=`: a crash, a stop or a removal of the API does not affect
  the shaper. Verified by a dedicated test suite.
- Installation: `install.sh --with-api`. Without the flag exactly the previous
  Shape is installed; API files are placed but the service is not enabled — it
  can be enabled later from the menu. Removing only the API:
  `install.sh --uninstall-api`.
- The same port on every node creates no conflicts: a node knows nothing about
  other nodes, there is no shared state and no database.

Shared between Shape and the API:

- Penalties are now written under a file lock: the watchdog, the CLI and the
  API all edit them, and without a lock one write could erase another.
- An event log appeared at `/var/lib/shape/events.jsonl` — limits, releases,
  watchdog triggers, engine start and stop, API actions. Every part of Shape
  writes there and reads from there.

Documentation and small things:

- An English README — [README.en.md](README.en.md), with a language switcher in
  the header of both files. The Russian version stays primary.
- A link to support the project: in the README and as one line in the footer of
  the main menu screen. It is absent from the working screens — they are dense
  enough already.

## 2.8

**Security audit: a pass over the whole project, with fixes.**

Fixes you can see in operation:

- **Editing any auto-limit setting wiped the entire Telegram section.** Token,
  chat, topic, proxy and digest time silently returned to empty values —
  saving the config rebuilt the file and simply left that section out. The
  config is now written by merging with what is already on disk, so a section
  cannot be lost even by accident.
- **Daily counters were not kept while auto-limiting was off** — the Telegram
  digest always arrived empty on such nodes. Traffic accounting is now separate
  from issuing penalties.
- **A non-first IPv4 fragment was parsed as if it carried a TCP header.**
  Payload bytes were read as port numbers and sometimes matched a rule by
  accident. Fragments are now recognised explicitly.
- **An IPv6 packet with any extension header bypassed the shaper:** the
  protocol in it is neither TCP nor UDP, and the code gave up at the first
  step. A bounded walk over the header chain was added.

Security:

- External commands (`bpftool`) run without a shell — the command line used to
  be assembled and handed to `/bin/sh` as root.
- Every value a human types is validated: IP, ports, speed, token, chat_id,
  topic, proxy, digest time, SSH address and user. Junk in a field previously
  ended up either in a Python traceback or in files that are later executed as
  root.
- Writes to `shaper.conf` are escaped: the file is read through `source` as
  root, and a quote in a value would have meant command execution at every
  start.
- The SSH tunnel wizard shows the server host key fingerprint and asks for
  confirmation, then works with its own `known_hosts`. Previously the first
  connection was taken on trust, and the bot token travels through that tunnel.
- The token is scrubbed from error texts that reach journalctl.
- The node label is escaped: a `<` in it used to break message delivery.
- `/etc/shaper` is 750 and `config.json` is 600, set at install time.
- The watchdog unit gained systemd restrictions (ProtectSystem, ProtectHome,
  PrivateTmp). They were deliberately not added to the engine: it mounts
  `/sys/fs/bpf`, and its own mount namespace would make the maps invisible.
- Removing Shape also removes the SSH tunnel unit.

Updating is safe: settings, penalties and the whitelist are untouched.

## 2.7

**The Telegram digest gets fixed and gains a schedule.**

- **Fixed: the daily digest was never sent at all.** The digest text was
  assembled, but the watchdog loop had no midnight rollover, so the function
  was never called. Days are now closed explicitly.
- **Digest time is configurable** — menu → Telegram → `[9]`, `09:00` node local
  time by default. Midnight used to be implied.
- **A digest can be sent by hand** — menu → Telegram → `[10]`. It reports the
  current, not yet finished day. Works with notifications off too, as long as a
  token and a chat are set.
- The snapshot of the finished day is stashed in `/etc/shaper/digest.json` and
  waits for the appointed hour. With no connectivity it retries every fifteen
  minutes for a day, then the digest is dropped: the day-before-yesterday's
  numbers are of no use to anyone.
- Items in the Telegram screen were renumbered: the test message is now `[11]`,
  the SSH tunnel `[12]`.

Updating is safe: settings, penalties and the whitelist are untouched.

## 2.6

- **The SSH tunnel wizard** — menu → Telegram → SSH tunnel. It asks for the
  address of a foreign node, the port, the user and the local SOCKS port; then
  generates an ed25519 key, installs `autossh`, writes a systemd unit with
  automatic restart, brings the tunnel up and verifies it with a real request
  to the Bot API.
- On success the proxy is written into the notification settings automatically.
- Removal in a single item, with the proxy cleared.

## 2.5

- **Telegram notifications.** Off by default.
- Events: an address gets limited — a message with the reason and the duration.
- Daily digest: traffic, address count, the five heaviest.
- Forum group topics through `message_thread_id`.
- An editable node label: all nodes write into one topic and it is clear which
  one fired.
- SOCKS5 and HTTP proxies implemented on the standard library, no `PySocks`
  needed. MTProto `t.me/proxy` links are rejected with an explanation.

## 2.4

- Wording fixed everywhere: the limit applies to an **IP address**, not to a
  user. Several people can sit behind one address.
- The limited list shows the time an address was limited.
- A banner and a screenshot in the README — a link to the project now unfolds
  nicely in Telegram.

## 2.3

- **An hourly volume threshold**, and it is the main rule: someone watching
  video for ten hours straight is not punished, while a download hits the limit
  in forty minutes.
- A ready **"phone-only node"** preset: 3 GB per hour, 25 GB per day as a
  backstop, a four-hour penalty.
- The daily threshold stayed as a fallback.

## 2.2

- Optimised for weak hardware: one core and 2 GB of RAM.
- LRU maps reduced from 65536 to 8192 entries — the watchdog cycle got about
  ten times cheaper.
- The menu stopped spawning a dozen `python3` processes per screen redraw.

## 2.1

- The logo in the main menu, plus the state of the shaper, autostart, speed and
  ports on the first screen.
- Autostart guaranteed at install time.

## 2.0

- **Auto-limiting of heavy addresses** on a combination of signals: two-way
  load, average upload packet size, hours of activity, volumes per hour and per
  day. Each signal scores points; a penalty is issued once the threshold is
  reached.
- A real-time per-address speed monitor.

## 1.x

- The first standalone version: ports, speed in Mbit/s per address, a
  whitelist, a Russian and English menu, systemd, updates from the repository.
