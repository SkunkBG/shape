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

## 3.84

**A node now notices on its own that the CDN relay changed address.**

The failure this was built for looks like this. The CDN moves to another node. The new address is not in the trusted list, the PROXY header from it is not parsed — and real client addresses stop being recognised. All traffic behind the CDN collapses into one address, so a hundred people share **one limit between them**. From outside it is "the internet is gone", while the node stays silent: processes run, no errors, an empty journal. That is exactly what happened on 5 September, and it was found by accident while looking into something else.

The signal turned out to be the node's own, with nobody to ask. While headers are parsed the resolved packet counter grows; once they are not, the whole increase goes to unresolved and resolved stands still. A healthy unresolved share on a live node is 8–10%: handshakes of new connections and the relay's own service traffic. So a 95% threshold with a stalled counter is not noise.

Having noticed it, the node looks at who holds connections on its PROXY ports, drops the trusted ones, and sends the new relay's address to Telegram together with a ready `trusted add` command. It will not add the address itself: a trusted source can claim any client address, and that decision belongs to a person.

The check runs every five minutes, costs **zero outside requests**, repeats about one address no more than once every six hours, and switches on only where PROXY ports are configured. On nodes without a CDN it does nothing.

**On update** settings are unchanged and nothing needs turning on.

---

## 3.83

**Disabling a subscription for sharing never fired — the block itself reset the countdown.**

The design was this: sharing found, access cut off, and you get half an hour to step in; if you do not, the subscription is disabled entirely, on every node at once. Disabling through the API worked, the countdown worked, and together they did not.

The reason is that a block removes the offender from view. At 0.05 Mbit/s the handshake never completes, connections are dropped, traffic stops — so `lastSeen` on his addresses stops updating and within `window_min` they fall out of the window. He stops counting as an offender, and cancellation is written as "gone from the list means the owner sorted it out". The countdown reset on every pass.

Measured on two live nodes: addresses go stale in about ten minutes, and out of 243 addresses only four were older than ten minutes. With a thirty-minute grace and a ten-minute window, disabling could not happen at all — only an endless cycle of hourly blocks.

The pending entry now survives while **our own** sharing penalty is alive: it carries `source=panel`, `reason=sharing` and the user id, so "vanished because of us" is told apart from "the owner sorted it out" precisely. Cancellation still works where it was meant to: clear the penalty with `release --user`, revoke the subscription, and the countdown stops.

Hence a new rule that `panel show` warns about: **the grace period must be shorter than the block**. The countdown lives while the penalty lives, and that lasts `limit_min` minutes — 60 against 30 by default, a twofold margin.

**A block no longer drops connections.**

`block` used to pull a drop along with it. The drop was not needed — the limit lives in the kernel map by address and applies to already open connections at once — and it did harm: sessions vanished from the panel, so the owner, coming in on a notification to see who this is and from which nodes, found an empty card instead of addresses. It was also what reset the countdown to disabling the subscription.

A drop now happens only when asked for explicitly: `--action-set block,drop`.

**On update** settings are unchanged. If you have the disable grace turned on, it will start seeing things through for the first time.

---

## 3.82

**Presets applied no sharing-detection settings at all — on any node.**

Both presets called `panel set` with a `--limit-min` flag that does not exist: minutes are set with `--minutes`. Argument parsing rejected **the whole line**, and the error was swallowed by `2>/dev/null || true`. You picked a preset, saw "done", and kept the old settings: no threshold, no window, no `block` action. Checked on two live nodes — both sat on `notify`, meaning Shape would have seen sharing and said nothing.

The error is no longer swallowed: if the command ever breaks again, it will show rather than hide. The same non-existent flag was in the README.

**Presets now also set the plan-based threshold — `--per-device 4`.** It protects offices: fifteen devices sold give a threshold of 60, so a legitimate company sitting on one node stays out of the rule. For a family with five devices nothing changes — 5 × 4 = 20, the base threshold. It does not help a reseller either: his plan is five devices and his addresses are a hundred.

**Tag exemption did not protect against disabling a subscription.** It worked for limiting and dropping, but the grace path received only the user id, without the tag: the card had not been fetched by that point. A business account tagged in the panel could be disabled automatically — contrary to what the documentation promised. The tag is now checked where the card is already in hand, so not a single extra request is spent.

**The `shape_panel_sharing_found` metric measured something else than promised.** It returned the number of cooldown records, and those live up to two days: after a single hit the graph held one for forty-eight hours. It is now offenders on the last poll.

**Seven panel events were written to the journal as errors.** Their types were never declared, and the journal replaces an unknown type with `error`: telling a refused disable from a real error was impossible, and in `shape_events_24h` all of it poured into the `type="error"` series. Now declared: `panel_exempt`, `panel_under_tariff`, `panel_disabled`, `panel_disable_refused`, `panel_disable_failed`, `panel_user_enable`, `panel_user_disable`.

**On update** settings and state files are untouched. A preset does not touch values you set by hand — it applies only when you pick it yourself.

---

## 3.81

**Clients behind a CDN no longer run unlimited after an update.**

The PROXY header arrives once, in the first bytes of a connection, and never again. From it the shaper learns the real address of a client behind the CDN and keeps the binding in kernel memory. An update restarts the service, and stopping and starting are two separate processes: the bindings map was destroyed before anything could save it. Live connections through the CDN then ran **with no limit at all**, for hours, until the client happened to reconnect.

Worse than the failure was how quiet it was: an update like that left no line about bindings in the journal.

Now the map is spilled to `/run/shaper/pp_conn.json` on stop and restored on start. `/run` is deliberate: it survives a service restart and disappears when the machine reboots — and after a reboot there is nothing left to restore anyway. A dump older than two minutes is refused: over a long gap the relay port goes to another client, and a restored binding would bill them for someone else's traffic.

Verified on a node behind a CDN with a real service restart: 759 bindings before it, 755 restored. On the same path before the fix, zero survived.

There is now always a line about bindings in the journal — "restored: N" or "none found". The silence was more dangerous than the loss itself: there was no way to tell working persistence from broken.

**On update** settings and state files are untouched. This very update already keeps the bindings: the new `engine.sh` is in place before the service restarts.

---

## 3.80

**Watchman arrived — a silence watchdog for the node fleet.**

A separate program in [watchman/](watchman/). It is installed **not on a node**, reads the Remnawave panel's `/api/nodes` once a minute and writes to Telegram when a node loses its clients or the panel loses the node.

Why it is needed when the shaper already sends notifications. The shaper's Telegram answers "what happened **on** this node": who was limited, who is seeding, how much went through in a day. There is another question — "is it alive at all?" — and a node cannot answer it: a node that is down will not send a message saying it is down. Absence of a signal cannot be sent as a signal.

Watchman watches client counts rather than missing metrics, and that is the point. A node can be perfectly healthy — processes running, panel connected, certificates valid — and still be unreachable for clients: the CDN in front of it broke, a DNS record vanished, a route went down. Metrics keep flowing all the while, and a metrics watchdog stays silent. The number of people collapses in both cases.

So that it does not become the thing people mute:

- a node's normal level is the median over the last fifteen minutes, with the most recent three excluded: otherwise a collapse in progress would lower the very bar it is judged against;
- a fleet correction — at night the online count drops everywhere, so watchman compares a node against the overall sag rather than an absolute threshold;
- nodes that normally hold fewer than ten people are not checked for collapse, because zero proves nothing there. Loss of connection is watched on every node without exception;
- an alert is sent after three consecutive passes, repeats about one node come no more than hourly, and an all-clear follows when clients return.

A daily "watchman alive" summary arrives once a day. It is not decoration: without it, watchman's own death looks like silence, which reads as "all is well".

It installs with one command, is configured through the `watchman` menu, listens to nothing and opens no inbound ports. Thresholds are edited in the menu and covered by `selftest.py`, which runs the rules against invented scenarios without touching the network.

**On upgrade** nothing changes on the nodes: watchman is unrelated to them and is installed separately.

---

## 3.79

**Reloading the engine left a fifth of the traffic unshaped.**

`engine.sh reload` removed the pinned maps wholesale, `pp_conn_map` among them — and that map holds the binding from a CDN connection to the real client behind it. The PROXY header arrives once, in the first bytes of a connection, and never again: every live session went past the limiter until it closed on its own.

Measured on a production node: six minutes after a reload, 20% of the bytes were unshaped at an average packet size of 1100 bytes — real client data, not handshakes. The decay is slow, hours long, because the sessions on 443 are long-lived.

The map contents are now saved before the unload and put back after the load — before the filters go on, otherwise the first packets of live sessions would already be gone unshaped. Key and value sizes are compared, so old bytes cannot land in a map whose layout has changed. Any failure means the previous behaviour rather than a failed load: a shaper without bindings beats a node without a shaper.

Measured after the fix: the share of CDN packets without a binding was 11.7% before the reload and 10.8% after. No collapse.

While here, `reload` no longer calls `unload_quiet` separately — `load()` unloads on its own, and the old order tore the maps down before anything could save them. A side benefit: if the build or the interface check fails, the old shaper stays in place instead of having been removed ahead of the failure.

**Records of CDN connections got stuck forever, and traffic landed in someone else's account.**

TCP closes in two halves, and different programs handle them: the client's FIN arrives on ingress, the node's FIN leaves on egress — near-simultaneously and on different cores. The half-counter was incremented with a plain `++`: both sides read zero, both wrote one, and it never reached two. The record stayed in the map until LRU evicted it.

On its own that would be litter, but a new header is parsed **only** when no record exists. So the next client handed that same relay port was silently attributed to the previous one — along with their traffic and someone else's limits.

Measured: records holding a single half had no live TCP connection in 96% of cases (51 of 53), against 14% for healthy ones. These were not long half-closes but genuinely stuck records. The increment is now atomic; two hours after the fix their number had fallen rather than grown.

**Files holding client addresses were created world-readable.**

`penalties.json`, `daily.json` and the deferred daily snapshot were written through a temporary file created with the default mode — 644. They hold client addresses and the history of their limits. The temporary file is now created as 600, and the mode travels to the final file with it.

**The Settings menu entry allowed arbitrary code execution.**

`cfg()` in `menu.sh` substituted its arguments straight into the text of a Python program, so a value that reached a setting was executed. Arguments now go through `sys.argv`.

**The unresolved-header counter fell silent when a relay address reached the whitelist.**

The whitelist branch returned before the counter could be incremented. Missing PROXY headers stopped being visible exactly when the port hands out no limit at all — the worst possible case.

**On upgrade** settings, limits and lists are preserved: the state files in `/etc/shaper` are left alone and the format has not changed. The first engine reload after the upgrade already keeps the bindings.

---

## 3.78

**The processing counters showed zeros while the kernel held real numbers.**

With `-j`, `bpftool` returns a per-CPU map value as a **byte array** rather than
a number: the map has no BTF for its value type, so the raw bytes are printed.
The parser expected a number and silently returned zero for every cell — the
metrics came out complete and tidy, all six lines present, and all zero.

Found by comparing against `bpftool map dump` by hand: 23 thousand packets down
and 49 thousand up in the kernel, zeros in the metrics. Exactly the class of
error these counters were added for in 3.77: numbers that look trustworthy and
mean something else.

Both forms are now understood: byte array and number (builds with BTF print a
number). The `formatted` field that `bpftool` places alongside with a ready
value is deliberately not used — not every build prints it.

The harness now carries both forms, taken from a live node rather than invented.

### Also

`ruff` is pinned in CI. Without that its rule set drifts on its own, and the
very first run went red over `B904` in panel code nobody had touched since 3.6.
Those four sites are fixed: re-raising from `except` now uses `from`, so the
traceback shows the real cause rather than only the outer one.

---

## 3.77

**Changing CDN addresses no longer breaks anything. And the shaper's drops are finally visible.**

### Trusting PROXY by port

The trusted-source list is keyed by the relay's address, and CDN addresses
change. On the day they do it misses silently, and the rest follows: header
parsing turns off → every client behind the relay collapses into **one** key →
that key gets the shared limit → an hour later it trips the hourly threshold and
gets auto-limited. The whole CDN path drops to messenger speed, and no check
says a word. From outside it looks like "the CDN is slow", while the cause sits
in a file nobody touched.

A port is a stable signal. If Xray has `acceptProxyProtocol` on the inbound, it
rejects header-less connections itself: the header is there by construction, and
asking "did it come from the right address" adds nothing.

```bash
shaperctl apply --ports 443 --speed 10 --proxy-ports 443
```

The flag lives in a spare bit of the `port_map` value — no new maps were needed.
The trusted-source list stays and works as before; the two grounds are
independent and either one suffices.

**The price is stated plainly.** Trust moves from the address to the port. If the
same port also serves **direct** clients, any of them can claim someone else's
address: bypass their own limit and push a neighbour into a penalty. This is safe
exactly when the port is relay-only, which is verifiable from the Xray config.
Hence the flag is per-port rather than one switch for the whole node.

### Unattributed relay traffic is no longer limited

The header arrives once, in the first bytes of a connection, and never again.
So after every engine reload all live CDN connections lose their attribution:
`pp_conn_map` is recreated empty. Such traffic used to be shaped under the
relay's address — meaning every client behind the CDN shared a single limit, for
hours, until the connections were re-established. Handshakes and the relay's own
health checks landed there too.

That traffic is now counted but not limited: a relay is not a client, and a
client's limit does not apply to it. How much of it there is shows up in a
counter.

### Processing counters

There was no way to tell "the limit holds gently" from "the limit is cutting a
quarter of the traffic": drops were counted nowhere. Trusting by port added a
second blind spot — if headers stop arriving, the port silently goes unlimited.

Both are now metrics:

```
shape_packets_total{direction="download|upload",action="pass|drop"}
shape_proxy_packets_total{state="resolved|unresolved"}
```

The counters are per-CPU, cost nanoseconds, and are race-free by construction.

### Tests

The harness reaches `TC_ACT_SHOT` for the first time: until this version no check
covered the EDT horizon or upload bucket overflow — that is, neither of the two
points where the shaper drops packets. New sections "Trusting PROXY by port" and
"Processing counters", 16 checks in total.

---

## 3.76

**Three ways to silently do nothing, and one reason to undercount hours.**

The 3.75 audit found places where a node reports itself healthy while not doing
its job. This release closes the ones that live in userspace: the eBPF filter is
not touched by a single line, so the update needs no maintenance window.

### An interface without an Ethernet header

The filter reads an L2 header unconditionally: `struct ethhdr *eth = data`.
Tunnel and tun devices — ipip, gre, wireguard, tun — have none. `h_proto` lands
in the middle of the IP header, yields neither ETH_P_IP nor ETH_P_IPV6, and the
program returns `TC_ACT_OK` for every packet.

Nothing could catch this. The engine is loaded, the filters are attached, and
tunnel devices carry a `noqueue` root qdisc — so even `shape_edt_ready` reads
one. Nobody is limited.

The interface is picked from the route to the internet, so if the default route
goes through the tunnel itself, the tunnel is what gets picked. The IPIP
unwrapping added in 3.75 covers the other case: the route stays on the physical
interface and the wrapper is visible there.

`engine.sh` now checks `/sys/class/net/<iface>/type` at load time and shouts if
it is not Ethernet. `shaperctl show` prints the same warning, and the
`shape_iface_ethernet` metric surfaces it across a fleet. Not a hard failure:
such nodes already exist somewhere, and breaking their service on upgrade would
be worse.

### The watchdog died from its own check

`die()` raises `SystemExit`, which does not inherit from `Exception` — it passed
straight through the handler in the loop. A full `penalty_map`, unpinned maps or
a `bpftool` failure killed the daemon outright, and `Restart=always` turned that
into a restart every fifteen seconds: auto-limiting was not working, but the
service looked alternately active and activating. The unit also had no restart
ceiling, unlike `shape-api`, which has had one from the start.

### Hours were counted on schedule rather than in fact

`d["active"] += interval` added the **configured** poll period instead of the
time the pass actually took. The two diverge whenever the cycle stretches: a
panel poll, a Telegram digest, a busy CPU. So active hours and upload hours were
undercounted exactly when the node was loaded — when the signal matters most.
The actual `dt` is now used; it was already computed a line above for the rates.

On nodes with the panel enabled the counters will grow a little after the
upgrade: those are the hours that were being lost.

### Changing the interface left a filter behind

`unload_quiet` detached the program only from the current `IFACE`. After the
name changed in the config the previous one stayed on the old interface, and if
both were alive the traffic was shaped twice. Both are now detached.

### Smaller things

- `apply --speed` below 0.05 Mbit/s is rejected. `int()` truncates, so anything
  below 0.000008 became zero bytes per second — that is, no limit at all, with a
  non-zero number on screen. The API has had this bound from the start.
- README: the state maps have long been 8192 entries, not 65536 — the prose
  lagged behind the table one section above.
- README: says that packets past the two-second horizon are in fact dropped.
  "Nothing is lost" holds only up to it.
- README: under the "all ports" rule the egress key becomes the remote site's
  address — so a popular site gets one client's limit applied to the whole node.
  SSH was mentioned, this was not.
- README: the limit applies to encapsulated traffic, so the client's payload
  runs a few percent below the nominal figure.
- README: packet-size thresholds are calibrated on the values the kernel
  produces with GRO on. `ethtool -K gro off` invalidates them.

---

## 3.75

**Nodes where Shape silently did nothing: behind an IPIP tunnel and behind a
CDN.**

Both were found by **[Gy9vin](https://github.com/Gy9vin)**, in his
[fork](https://github.com/Gy9vin/shape). He did not just report the problem —
he wrote the parsing in the eBPF filter and the checks for it. The changes are
carried over here with two modifications, described below.

### What was broken

**IPIP tunnels.** Some hosters hand the node its public address through a
tunnel: on the external interface every packet is wrapped in an extra IP header
with protocol 4. The shaper saw "not TCP, not UDP" and let **all** of that
node's traffic past without accounting or limiting. The symptom — "Shape is
installed, it limits nothing, the monitor is empty" — gives no clue as to why.

**Clients behind a CDN.** A CDN terminates the client's connection at its edge
and opens a separate one to the node. At the packet level the sender is the
relay, so **every client behind it shared a single limit**. The real address
arrives in the PROXY protocol header, in the first bytes of the stream — the
same ones Xray reads with `acceptProxyProtocol`.

### What changed on the way in

**Byte order.** In the fork the address was assembled with shifts:

```c
out->addr[0] = ((__u32)p[16] << 24) | ((__u32)p[17] << 16) | ...
```

Everywhere else the key is the raw bytes from the IP header (`ip->saddr`,
network order), and `ip_key()` in `shaperctl.py` puts the same thing into the
map (`ip.packed`). An address built with shifts lands back to front: client
`203.0.113.5` becomes `5.113.0.203`. Limits, the whitelist and the statistics
miss it forever, and an address that does not exist shows up in the monitor.
The address is now copied byte for byte.

The fork's tests did not catch this: the fixture wrote the address onto the
"wire" using the same reversed convention the parser read it with. Two mistakes
cancelling out. In the harness, addresses are now built only through
`inet_pton` — that is, the way they arrive from the wire.

**A list of trusted sources.** In the fork the wrapper was unwrapped for anyone.
But both the PROXY protocol header and the inner address in protocol 4 are
written by the sender: whoever opened a connection to a shaped port could pick
which address got charged — evading their own limit and pushing someone else's
address into a block. Hence the list:

```bash
shaperctl trusted add 198.51.100.7  --tunnel   # IPIP tunnel endpoint
shaperctl trusted add 198.51.100.20 --relay    # CDN relay
shaperctl trusted list
```

**While the list is empty, neither unwrapping runs at all** — behaviour is
exactly what it was before this version. The list lives in
`/etc/shaper/trusted.txt` and is reloaded on every engine start. In the menu:
Whitelist → Trusted sources.

**Closing connections.** In the fork the connection record was deleted on the
first FIN. TCP closes one side at a time, and the opposite direction may still
be sending data — which would then be charged to the relay. The halves are now
counted: two means done. RST tears down immediately, so there is nothing to
wait for.

### Also in the parsing

* The `LOCAL` command in a v2 header is skipped: that is the relay's own
  service connection, with no client behind it.
* The textual v1 variant is parsed with octet length checks — older load
  balancers still send exactly that.

### What the kernel verifier caught

The first build refused to load on a live node:

```
470: (4f) r4 |= r3
R4 bitwise operator |= on pointer prohibited
```

The textual header parser collected octets into a stack array —
`oct[part++] = cur`. The index is a runtime value, so clang turned the store
into pointer arithmetic on the stack pointer using `OR`, which the kernel
forbids.

Neither gcc in the harness nor `clang -target bpf` in CI complains: the code
is legal, and only the verifier rejects it at load time. The octets are now
shifted into a single integer, with no array at all.

The lesson: the harness and the compiler check different things, and neither
checks the third — **eBPF is only truly verified by loading it into a kernel.**

### Tests

The `bpf_harness.c` harness: 61 checks, up from 36. New sections cover IPIP
tunnels (5), PROXY protocol (17) and map key layout (3). Among them the ones that matter: the
address from the header is not reversed, a wrapper from a stranger is not
unwrapped, and a forged header from an untrusted address is ignored.

---

## 3.74

**Deploying the monitoring server: six steps across two consoles became three
questions.**

### What the first live deployment showed

Someone deployed the server and got stuck. What followed: compute the password
hash with a separate command, paste it into a file by hand, restart the
container, go to the browser, click "Register device", receive a notice about an
e-mail that will never arrive, go back to the console, dig the code out of a file
inside the container, go back to the browser, type it in — and only then the QR
code.

Six steps, two consoles, switching between them. Halfway through, the code turned
out to be eight characters instead of the expected twenty, and it all had to
start over.

**Protection that cannot be used does not protect** — people simply stop using
it.

### The second factor is gone

```yaml
policy: one_factor    # was two_factor
```

There are still two layers: the gate password and Grafana's own login. From
outside it is still impossible to tell what stands behind the gate — which was
the point all along. The scanners that found the names three minutes after the
certificates were issued get a login page and nothing else.

What was lost is protection against theft of the password itself. The trade is
stated plainly: TOTP without a mail server cost six steps, and that price was due
every time.

To bring it back: `two_factor` in `configuration.yml` plus `notifier.smtp`.

### The installer asks everything at once

```
Domain, without a subdomain (for example example.com):
E-mail (Let's Encrypt and the gate login):
Password:
```

Then it does the rest: computes the hash **using Authelia itself** (its own
algorithm, its own parameters), writes `users.yml`, generates the secrets, brings
the stack up and prints both passwords along with the ready-made command for the
nodes.

You do not have to invent a password — an empty answer and the installer
generates one.

**The password never reaches the process arguments.** The first method feeds it
through `stdin`; the `--password` flag is kept as a fallback, because it does not
exist in every build and it is visible in `ps`.

### Input checks

A domain with a scheme or a slash is rejected outright — `https://example.com` in
that field would mean three broken names and wasted Let's Encrypt attempts. So is
an e-mail without a dot in its domain: that is exactly what tripped certificate
issuance. A password shorter than eight characters is not accepted.

### Other

* `users.yml.example` is now an illustration of the structure rather than a
  template to edit by hand: the installer writes the file itself.
* Tests: 16 new, 97 in the monitoring set. The password is asked for and
  confirmed twice, Authelia computes the hash, the password stays out of the
  arguments, the installer writes the file, the stack does not come up without a
  working hash and the check runs before startup, the domain and e-mail are
  validated, a generated password is displayed.

---

## 3.73

**Two bugs found by the first live deployment of the monitoring server.**

### The e-mail never reached Caddy

```
contact email has invalid domain: Domain name needs at least one dot
```

The `Caddyfile` had `email {$ACME_EMAIL:admin@localhost}`, while
`docker-compose.yml` passed the container only the domain and the token. The
variable never arrived, Caddy took the default — and Let's Encrypt refused,
because `localhost` has no dot.

**Worse than the bug was how it looked.** The logs complain about the domain,
so you start looking in DNS, in the records, in the firewall — everywhere except
the forgotten line in compose.

The variable is now passed and mandatory, and **the Caddyfile default is gone**:
an empty value makes Caddy fail immediately and for the right reason. A silent
default that is guaranteed not to work is the worst of both worlds.

### The installer brought the stack up with a broken password

```
failed to parse hash for user 'admin': argon2 decode error:
provided encoded hash has an invalid format
```

The installer copied `users.yml.example` with a placeholder instead of a hash
and went on to start the stack. Authelia cannot parse such a hash and dies at
startup — once a minute, forever. Caddy then fails to resolve the container by
name and returns **502 to everything**, with `no such host` in the logs.

So a problem in the password file looked like a problem with the network.

The installer now **stops before starting anything** if the placeholder is still
in `users.yml`, and prints three steps: compute the hash, paste it, run again.

### What this says about the checks

Both bugs lived in the files, and both slipped past 81 checks. What was verified
was the presence of variables in compose and the presence of routes in the
Caddyfile — but not that **values from one file reach the other**, and not that
the installer refuses to start a combination known to be broken.

Seven new checks close exactly that.

### Other

* `chown: /config/...: Read-only file system` in the Authelia log is not an
  error but noise: the configs are mounted read-only on purpose.
* Tests: 7 new, 88 in the monitoring set.

---

## 3.72

**The `monitor/` directory: the monitoring server deploys with one command.**

```
node in Russia ─┐
node in Europe ─┼─→  https://push.<domain>  ─→  VictoriaMetrics
node behind NAT ┘         (token)                     │
                                                      ↓
    you ─→  https://grafana.<domain>  ─→  Authelia  ─→  Grafana
                                          (gate)     (own login)
```

```bash
git clone https://github.com/SkunkBG/shape.git
cd shape/monitor && sudo bash install.sh
```

### The rule that matters has not changed

**The dashboard only reads.** No rule on any node looks at the central source.
The server dies, the domain expires, the VPS burns down — nothing changes on the
nodes.

This is not a promise but a property of the design: Shape has no line that reads
a decision from outside.

### Two layers of access

Grafana has a recognisable login page: its version can be read off it, and known
holes follow from the version. The gate in front returns the same thing to every
unauthenticated visitor, and from outside it is **impossible to tell what stands
behind it**.

| Layer | What it is | What for |
| --- | --- | --- |
| Authelia | password + TOTP | strangers cannot even see that this is Grafana |
| Grafana | its own login | someone inside the perimeter is still outside |

The second factor was chosen not out of strictness but because the node owner
travels. An IP allowlist is out from the start; a client certificate would mean
that a new device on a trip locks you out.

### The most dangerous place is the intake

A node cannot go through an interactive login, so it has a route of its own. That
route is **deliberately narrow**:

```
@push {
    path /api/v1/import*
    method POST
    header Authorization "Bearer {$SHAPE_PUSH_TOKEN}"
}
```

All three conditions must match. The path is restricted because VictoriaMetrics
keeps series deletion next door (`/api/v1/admin/tsdb/delete_series`): opening the
whole storage here would hand whoever holds the token the ability to **erase the
history**. And the token sits on 28 nodes and will leak sooner or later.

A stolen token buys exactly one thing: writing junk metrics.

### What is inside

| Container | Version | Exposed |
| --- | --- | --- |
| caddy | 2.8-alpine | **80, 443** |
| victoriametrics | v1.102.0 | none |
| grafana | 11.2.0 | none |
| authelia | 4.38 | none |

One container faces outward. Versions are pinned: Authelia's configuration
changed incompatibly between 4.37 and 4.38, and `latest` will simply fail to come
up one morning.

The dashboard is not copied but mounted from `grafana/` next to the node code:
two copies of one file drift apart, and the one that drifts is always the one out
of sight.

### What is checked, and what is not

Docker and Caddy do not run in the sandbox. But nearly everything that breaks in
a stack like this is visible in the files themselves — **81 checks**: published
ports (caddy only), the write route with its three conditions, the absence of
deletion and reading in it, secrets as variables rather than in the config, every
variable being mandatory, `.env` and `users.yml` in `.gitignore`, the installer
taking randomness from the kernel, image versions matching the documentation.

**What cannot be checked** is whether Authelia comes up with exactly this config
schema. That is stated plainly, and the installer calls `authelia
validate-config` before the first start rather than after.

### Other

* `README.md` and `README.en.md` in `monitor/` — how it works, what it costs,
  maintenance, backups.
* Metrics push was added to the main README's "Monitoring" section as the first
  of three paths.
* The intake endpoint was confirmed against the VictoriaMetrics documentation:
  `POST /api/v1/import/prometheus`, body in Prometheus text format.

---

## 3.71

**Real people's data removed from the repository. And a check added so it does
not come back.**

### What it was

Examples in the documentation were written from life: you take a real card from
a node, paste it into the README — and along with it go the customer's name,
their Telegram handle, subscription number, address and server name.

The public repository held **46 real addresses in 155 places**, four handles,
eight Telegram identifiers and the names of five nodes. This cannot be spotted by
eye: in a hundred pages of text such a line stands out in no way, and documents
live for years.

### What it is now

Addresses were replaced with the ranges reserved for documentation (RFC 5737):
`203.0.113.0/24`, `198.51.100.0/24`, `192.0.2.0/24`. They are not routed on the
internet and cannot belong to anyone.

Names, handles, identifiers and node names were replaced with examples: `Ivan`,
`@ivan_k`, `100000001`, `Node-1`. The replacement is consistent — the same person
stayed the same person across all documents, otherwise the examples would stop
reading.

The edits touched the README in both languages, both changelogs, the code and the
tests.

### `tests/privacy_scan.py`

The point here is not the cleanup but that it will not be needed a second time.

```
$ python3 tests/privacy_scan.py
  ✓ данных живых людей не найдено
```

The check walks the repository and fails on any public address outside the
documentation ranges, on any handle outside a short list of examples, and on any
number standing next to `Telegram:`, `user_` or `tg://user?id=`.

**The allowlist is explicit and short.** A new address or handle has to be put
there by hand — and at that moment you ask yourself where it came from.

### Checking the check

A green scanner that finds nothing is worse than none. So 22 checks try it on
planted data: a real address is found, a documentation one stays silent,
resolvers stay silent, a customer handle is found, `@BotFather` stays silent, a
Python decorator does not count as a handle while a Markdown line starting with
one does, an identifier is found in three different spellings, the `123456789`
placeholder stays silent, and a number of bytes is not an identifier.

The samples for those checks **are assembled from pieces**: written out in full
they would sit in the same file and the scanner would find itself. Exactly the
trap it guards against — "but this data is for a good reason".

### An honest caveat

The check catches addresses, handles and identifiers. **It cannot catch a
person's name** — "Darya" is indistinguishable from "Maria". There only attention
helps: examples get invented names.

---

## 3.70

**A node can push its metrics on its own. The first step towards a monitoring
server.**

### Why push rather than scrape

The monitoring server has to see 28 nodes, some of them in Russia. WireGuard is
blocked there by the fingerprint of its handshake, and opening an inbound port on
every node is a bad idea in itself.

So it is not "the server comes for the metrics" but **the node sends them**:
outbound HTTPS to an ordinary domain with a real certificate is
indistinguishable from a person opening a website. Not a single inbound port is
opened, and NAT stops being a problem.

```bash
shaperctl metrics set --url https://metrics.example.com/api/v1/import/prometheus \
                      --token WRITE_TOKEN
systemctl enable --now shape-push.timer
```

Check it right away: `shaperctl metrics push` and `shaperctl metrics show`.

### What is sent

The same text that goes into the node_exporter file. Every series already carries
a `node` label, so the receiver needs to add nothing and it does not matter how
many nodes write into one storage.

**The address is given in full, path included.** Binding to a particular
storage's endpoint is wrong: today VictoriaMetrics, tomorrow anything else, and
the node should not know about it.

### Where the secrets live

The token travels in an `Authorization: Bearer` header and lives in
`/etc/shaper/config.json` — not in the systemd unit: a secret in a unit is
visible to anyone who can read `/etc/systemd`.

**Plain `http` to the outside world is refused.** The token would travel in clear
text, and that cannot be spotted by eye in a config — easier not to allow it. To
`127.0.0.1` and private networks it is allowed.

`scrub`, which strips secrets out of error text, was rewritten along the way. It
used to know only about the bot token: every new secret would have to be
remembered separately in every place that prints an error. Nobody remembers that.
It now takes the list from `SECRET_PATHS` — one place for the whole program.

### Small things that matter across 28 nodes

The timer fires once a minute **with a 15-second spread**: nodes updated by one
command would otherwise arrive in the very same second and produce a neat spike
on the server every minute.

An unreachable network does not count as a service failure: `SuccessExitStatus=1`.
Otherwise the journal would fill with red every minute while a node is offline.

### Other

* `grafana/README.en.md` — there was no English version of that document at all.
* Tests: 37 new. Address parsing (https, http to self, http outward, garbage),
  the config section and neighbouring sections surviving, pushing with and
  without a token, the content type, a disabled push not touching the network, a
  failure neither crashing nor leaking the token into the journal, units present
  and free of secrets.
* **A check on the counter inside the tests themselves.** One of the new blocks
  said `ok, err = ...` — and `ok` is the global counter of passed checks. The
  boolean landed in the counter, the total read 189 instead of 441, and **every
  check was green while it happened**. `check` now verifies the counter's type at
  every step: a silent loss of count is worse than a crash.

---

## 3.69

**The monitor gained a "data" column.**

```
   IP                       now  upload  packet     data     avg    total holding  share of limit
 ▪ 203.0.113.19            12.4     3.1    1420      79%     8.2  82.0 MB   5 min  ███·········
 ▪ 203.0.113.11            4.2     0.6     209       1%     3.9 212.0 MB       —  █···········
 ▪ 203.0.113.39          0.4     0.9    1508      95%     0.5 578.0 MB  15 min  ▏···········
 ▪ 203.0.113.6           22.0     0.4      88        —    18.1   3.2 GB   1 min  █████▍······
```

### Why, when "packet" is already right there

They answer different questions. **Packet** answers "what is going up right
now" and jumps from window to window: someone sends an attachment in a
messenger and the column reads over a thousand for ten seconds. **Data** is the
share of the day's upload that went in large packets; it knows no jumps and
shows behaviour rather than a moment.

They diverge precisely for the addresses worth looking at: a high instantaneous
packet with a low daily share means a burst; the reverse means it is quiet now
but the day was spent seeding.

This is the very number the watchdog uses to decide whether an upload counts as
data (`ratio_needs_packet`). Until now it could only be seen in `status --bulk`
or after the fact in a card.

### How to read it

| Colour | Share | Meaning |
| --- | --- | --- |
| grey | under 55% | acknowledgements, ordinary downloading |
| yellow | from 55% | reached the watchdog's threshold |
| red | from 80% | little room for doubt |
| `—` | — | no upload at all today |

A dash, not a zero: zero would mean "uploaded, but in acknowledgements", and
that is a different statement.

### Other

* The monitor re-reads the daily counters every five seconds, together with the
  penalty list. The watchdog writes them; the monitor only reads.
* Table width 87 → 96.
* Tests: 20 new. The dash for a missing record, for zero upload and for a
  corrupted field; the percentages and three colour thresholds; the share never
  exceeding a hundred. Plus a structural check: **the column widths in the
  header and in the table row must match field for field** — they are built by
  two separate f-strings, and a column is easy to add to one and forget in the
  other.

---

## 3.68

**`panel user` printed the upload hours twice.**

```
data 1% · packet 209 B · max 1101 · lasted 0.0 h · sent data for 0.0 h
```

The hours were added to the packet breakdown in 3.67, for the Telegram card
where they were missing. In `panel user` they already had a field of their own,
so the same number came out under two names. On one line that reads as two
different quantities.

`penalty_packets` gained an `hours` parameter; `panel user` calls it with
`hours=False` and prints the hours under its own label.

```
data 1% · packet 209 B · max 1101 · sent data for 0.0 h
```

### Other

* Tests: 5 new. Hours switched off by the parameter, the other fields still
  present, the number appearing once in the assembled line, hours on by default,
  and `panel user` actually calling the breakdown without them.

---

## 3.67

**A lifted limit no longer comes back on its own. The upload floor is raised
to 3 GB. The card now shows hours.**

### The main thing: clearing the list now means something

The live case behind all of this: the node owner lifts a limit, and ten seconds
later the person is blocked again. And so on until midnight.

The cause is in the code, not in the person. A daily counter **never goes
down**. The penalty is lifted, the day's figures stay the same, the watchdog
runs every ten seconds, and the signal fires again.

```
cleared the list        → blocked again 10 seconds later
penalty expired after 1h → blocked again 10 seconds later
```

For hourly windows this was solved long ago — the window is cleared after a
penalty. The daily signals were missed, and three of them ran in an endless
loop: disproportionate upload, daily upload, daily download.

Now the counter the person was caught on is recorded at penalty time. A repeat
penalty for the same signal happens only if the **counter grows by another
quarter**. Someone who keeps seeding comes back in an hour or two; someone who
stopped does not come back at all. Lifting a limit by hand works the same way:
until midnight, or until a quarter more volume.

### Upload floor: 300 MB → 3 GB

In a single evening three people were limited: 306.9, 302.6 and 335.6 MB of
upload. All three crossed the 300 MB floor and were caught at once — meaning it
was the floor doing the catching, not the signal.

Three hundred megabytes are worth neither the link, nor the traffic, nor a
conversation with the customer.

**The cost is stated plainly:** a quiet seeder pushing less than three gigabytes
a day is no longer caught. None of the past confirmed catches — 1.0 GB, 590 MB,
520 MB — clear the new floor either. This is a deliberate trade: fewer false
positives at the price of the smallest true ones.

### Hours in the card

```
📦 Upload over 16.4 h: data 91% · packet 898 B · max 1853 · lasted 9.4 h
```

The signal that separates seeding from an upload never made it into the card:
there were percentages and bytes, but no time. From such a card there was no way
to tell why one person is limited and a neighbour with the same percentages is
not.

`over 16.4 h` is the age of the packet counter. `lasted 9.4 h` is how much of it
the address actually spent sending data.

### Other

* The threshold-rendering test was rewritten: it converts the number back from
  the string instead of comparing against a value written into the test. The old
  one broke whenever the threshold changed and reported a mismatch where there
  was none.
* Tests: 27 new. Repeat penalty before and after counter growth, one signal's
  mark not silencing another, garbage in the mark, the amnesty on a manual
  release, hours in the card at nine hours and at twenty minutes, a corrupted
  counter, field order, and no repetition of the word "data".

---

## 3.66

**The "Also delete settings and history" item now shows its state.**

### What was wrong

```
  Settings, tokens, node identifier and history: will be kept
  ────────────────────────────────────────────────────────────
  [1] Save a backup first (recommended)
  [2] Also delete settings and history
  [3] Remove Shape
```

Item `[2]` is a toggle, but it is phrased in the imperative, exactly like `[3]`.
A person presses it expecting an action; the screen redraws, one line above it
changes — and the item looks broken.

The mechanism worked all along: `--purge` reached `uninstall.sh` and the
settings were removed. Only the label was broken.

### How it looks now

```
  [2] Also delete settings and history: no — press to toggle
  [3] Remove Shape
```

```
  [2] Also delete settings and history: YES — press to toggle
  [3] Remove Shape together with the settings
```

The state sits inside the item itself — the same device as `[15]` on the guard
screen. Line `[3]` changes along with it, so before typing the word `DELETE`
you can see what is about to happen.

### Checked by running it, not by grepping

The body of the screen is extracted into its own `uninstall_menu` function, and
the test **calls it** with both toggle values in both languages. Grepping is
useless for this: the string was there all along, and a search of the source
found it.

This is the second screen in a row to break in a way a source search cannot see.
The first was in 3.59: items `[18]` and `[19]` were shown on one screen while
their handlers sat in another.

### Also: interface strings are checked in pairs

`tests/lang_parity.py` compares the keys of the Russian and English blocks of
`lang.sh`. A key added to one block and forgotten in the other breaks nothing
visibly: bash substitutes an empty string, a hole appears on screen — and only
in one language, so it can only be noticed by accident. There are 521 keys now,
with no divergence.

### Other

* Tests: 21 new. Rendering of both states in both languages, `[2]` and `[3]`
  differing, all items present, no item trailing off after a colon, the default
  value, `--purge` passed only when the toggle is on, and the language key
  comparison.

---

## 3.65

**A disproportionate upload only penalises together with duration.**

### The live case

A mobile node, an ordinary user:

```
📈 24h: ↓ 418.8 MB · ↑ 326.0 MB (78%)
📦 Upload over 2.1 h: data 55% · packet 907 B · max 4246
🐌 Speed reduced to 1 Mbit/s for 1.0 h
```

A conversation or seeding? The packet filter did its job — an average of 907
bytes and a maximum of 4246 come from no voice or video call, those run on small
packets: the confirmed video-call case had 267 and 349.

But **a video sent to a chat looks exactly like seeding**, and by proportion the
two cannot be told apart. And the data share scraped through: 55% against a
threshold of 55.

Then there is the volume — 326 MB over two hours, 0.35 Mbit/s. On a quota node
that costs the owner nothing. The signal caught someone economically irrelevant.

### Why it happened

The data-share distribution on the mobile node (`status --bulk`) is a **smooth
slope with no gap**: 161 addresses in the first bucket and a thin layer running
up to ninety. On home nodes there was emptiness between the honest and the
seeders, and the threshold went into it. Here there is nowhere to put it — the
threshold cuts the slope, and the first borderline case fell into it.

### What was added

```bash
shaperctl guard --upload-ratio-hours 2
```

The ratio penalises only if the address **sent data for at least N hours in a
day**. The hours come from the same counter as the `--upload-hours` signal fixed
in 3.64: only data upload is counted there — acknowledgements and conversations
do not get in.

| | Ratio | Hours of data upload | Penalty |
| --- | --- | --- | --- |
| Video sent to a chat | 78% | 0.5 | no |
| A phone's first backup | 90%+ | 1-2 | usually no |
| Seeding | 78% | 8-12 | yes |

Proportion answers "how much", hours answer "how long". An upload ends, seeding
does not.

### Two hours in the presets

Both presets set `--upload-ratio-hours 2`. The condition is optional:
`--upload-ratio-hours 0` restores the behaviour from before 3.65.

**An honest caveat.** Every confirmed catch by ratio — 665%, 392%, 75% —
happened before 3.64, while the hours counter was broken, and we do not know how
many hours those had. Seeding that does not send data for two hours a day is not
seeding, but that cannot be checked against the past cases. If the catches stop,
the value is worth lowering to one hour, and `panel user` will show it: the
"sent data for N h" line says what the address was short of.

### Other

* The setting shows up in `shaperctl guard` output on its own line.
* Tests: 12 new. The live case at half an hour and the same at eight hours, the
  boundary exactly at the threshold and a minute below, a missing counter,
  garbage in the setting, the condition switched off, the command-line flag,
  both presets.

---

## 3.64

**The "hours of upload" signal never worked. Now it does.**

### What happened

The ratio rule fired on someone with borderline numbers: 1.8 GB down, 1.2 GB up,
ratio 66%, data share 67%. Both figures are above their thresholds, but both sit
in the middle rather than at the edge — they cannot tell seeding from a backup.

Duration was supposed to tell them apart: an upload ends, seeding does not. So
we asked:

```
shaperctl panel user 1377
  203.0.113.9    ↓ 1.8 GB · ↑ 1.2 GB (66%)
                    data 67% · packet 801 B · max 2357 · sent data for 0.0 h
```

**Zero hours against 1.2 gigabytes of upload.** The signal built precisely for a
quiet seeder could not see a quiet seeder.

### Why

Seconds were counted on a single condition: upload in the sample above
`upload_hours_mbps`, 0.3 Mbit/s by default. This address pushed 1.2 GB in an
even trickle across 12.7 hours — 0.21 Mbit/s. Not one ten-second sample reached
the floor.

The floor was there to filter out acknowledgements of an ordinary download —
otherwise "hours of upload" would become "hours online". But **a rate floor
cannot filter them out at all**. The volume of acknowledgements is set by
download speed, not by the person:

| Downloading at | Acknowledgements up |
| --- | --- |
| 1 Mbit/s | ~0.03 Mbit/s |
| 10 Mbit/s | ~0.33 Mbit/s |
| 100 Mbit/s | ~3.3 Mbit/s |

At ten megabits the 0.3 floor already let acknowledgements through, while still
eating the quiet seeder. It did nothing but harm.

### How it works now

Three conditions, each aimed at its own class.

**Rate** filters noise only: the floor drops from 0.3 to **0.05 Mbit/s**.

**Share of the download** filters acknowledgements. Theirs is structurally 3-5%
and does not depend on link speed at all; a sample counts when upload is **at
least 20% of the download**. A fourfold margin. No download in the sample — the
condition passes at once: that is what pure seeding looks like.

**Packet size** filters conversations. A video call sends as much up as down and
is indistinguishable by share; what separates it is a 267-byte packet against
1300 for a torrent chunk. The condition reuses the existing `ratio_needs_packet`
setting.

| Who | Up | Down | Packet | Counted |
| --- | --- | --- | --- | --- |
| Quiet seeder | 0.21 | 0.31 | 1300 | yes |
| Download at 10 Mbit | 0.33 | 10 | 100 | no — share |
| Same, GRO-coalesced | 0.33 | 10 | 1400 | no — share |
| Download at a gigabit | 30 | 900 | 1400 | no — share |
| Video call | 1.0 | 1.0 | 267 | no — packet |
| Seeding, no download | 0.5 | 0 | 1300 | yes |

### What it cost

On QUIC nodes (Hysteria2) packets are small for everyone and
`ratio_needs_packet` is turned off there. The hours signal then loses its
protection against conversations: someone on a video call all day will show up
in a notice. Protocol independence is kept — the download share works the same
on QUIC as on TCP.

The signal used to be documented as independent of the protocol entirely. That
is no longer true, and the code now says so plainly.

### Upgrading

The old 0.3 default is replaced with 0.05 on the first config read. That exact
value counts as "not configured": nobody picked it by hand, it was the default
from 3.52 through 3.63. **Any other number is left alone** — that is the node
owner's choice.

The presets set the floor explicitly, so applying a preset fixes it too.

### Other

* Wording: "uploaded for N h" → "sent data for N h", in the card and in
  `panel user`. The hours now count data upload, not presence.
* Tests: 21 new. The live 0.21 Mbit case, acknowledgements at three speeds, GRO
  coalescing, a video call with and without the packet check, a QUIC seeder,
  both boundaries, an empty sample, migration for three values, the presets.

---

## 3.63

**The address threshold is derived from the plan: as many devices sold, as many
addresses are normal.**

### Why

One threshold for everyone stops working once plans differ. The node owner is
introducing a grid: 5 devices for 500 GB, 10 for 1 TB, 15 for 3 TB. Twenty
addresses for someone on a fifteen-device plan are normal; for someone on a
one-device plan they are not.

```bash
shaperctl panel set --per-device 4
```

| Plan | Threshold |
| --- | --- |
| 1 device | 20 (base) |
| 5 devices | 20 (base) |
| 10 devices | 40 |
| 15 devices | 60 |

The multiplier exists because **a mobile client changes address** on reconnect
and on handover: one device produces several addresses per window.

### The rule only raises the threshold

The base stays the lower bound. No new triggers appear — only false ones can
disappear. That makes the setting safe: switching it on tightens nothing.

### The plan, not registered devices

It takes `hwidDeviceLimit` — what was sold.

The count of registered devices will not do: it depends on whether the client
installed the app. And above all — **someone handed a config file never appears
in the device list at all**. That is exactly how resale works, and exactly why a
device limit does not stop it.

The field arrives in the user card Shape requests anyway, for the name. **Zero**
extra requests.

If no plan is set, the base threshold applies. Guessing how many devices the
owner sold is not something to do on his behalf.

### How it shows

The plan check is the second stage, after the base threshold: the base acts as a
pre-filter, so there is no need to ask about the plan for all six thousand users.

The message states which threshold was applied:

```
Simultaneous addresses: 25 over the last 10 min
Threshold for his plan: 60 — devices sold: 15
```

Menu: **Panel → [20] Threshold from the plan**. Off by default.

### Also

* Tests: 15 new ones. Thresholds for five plans, the setting off, a missing card,
  junk in the field, the rule never lowering the threshold, a full pass — a
  fifteen-device plan clears the suspicion, a one-device plan keeps it.

---

## 3.62

**A repeat sharing message no longer says "addresses: 0".**

The pause between actions on one offender is six hours, while the cut-off lasts
an hour. When the pause ends and the check fires a second time, there is nothing
to add: all of his addresses are already limited. The message meanwhile said:

```
🚫 Access to the node cut off for 60 min, addresses: 0
```

The zero meant "added on this pass" but read as "nothing was done". The cut-off
was in fact in place.

What is counted now is what is limited **right now**, not what was added. On a
repeat it will show the same 146 as the first time.

### Also

* Tests: 3 new ones. The first pass cuts off 25 addresses, the second shows the
  same 25 rather than zero, while genuinely adding nothing.

---

## 3.61

**In the status line "Panel" became "Remnawave".**

There are many panels, and on someone else's node "Panel on" says nothing about
what the link is actually to. The product name does.

```
  🛰  Remnawave  connected  disables the subscription after 60 min
```

The column width is preserved: labels in the status line are padded with spaces
inside the strings themselves, because `printf %-10s` in bash counts bytes while
Cyrillic in UTF-8 takes two per character — the column would drift precisely in
Russian.

Verified by running it on a fake config, both on and off.

---

## 3.60

**The status line now shows the links to the outside world: Telegram, the panel,
the API.**

### What was missing

The main screen answered questions about the shaper and the auto-limiter but said
nothing about whether Telegram, the panel and the API were configured. Learning
that notifications go nowhere, or that the panel is not connected, required
walking into the section.

```
  🟢  Shaper    running    interface ens3
  🔁  Autostart on         survives a server reboot
  🚀  Speed     50 Mbit/s  for every IP address
  🔌  Port      443
  🚦  Auto-limit on        both ways ↓5 ↑1.5 Mbit/s 10 min → 1 Mbit/s for 60 min
      or 11.2 GB an hour · 150 GB a day · upload over 50%
  ✉️   Telegram   on         node label: Node-1
  🛰  Panel      connected  disables the subscription after 60 min
  🔑  API        running
```

The subscription-disable grace period is shown in red: it is the only thing Shape
does in the panel rather than in itself, and it should be known from the first
screen.

### "On" means a working configuration

Not a checkbox. Telegram with the flag on but without a token or a chat is shown
as **off**. So is a panel without a UUID.

Half a configuration is worse than none: one is sure it works when it does not.
That is exactly what a status line is for.

### The API has three states

`running` · `not running` (installed but the service is down) · `not installed`.

### Verified by running it

In the previous version the menu items were on the screen while their handlers
were in another function, and a `grep` over the file did not notice. So this test
does not search for strings — it **calls** `status_line` on a fake config and
looks at what it printed:

* everything on — eight lines, the node label and the grace period in place;
* everything off — it says notifications go nowhere;
* on but without a token and a UUID — shown as off;
* broken JSON — the line is still printed in full.

Verified that the test fails when the output is broken.

`links_state` also takes the config path from `ETC_DIR` instead of hardcoding it:
otherwise such a test would have to run against the real `/etc`.

### An old hole in the tests turned up along the way

There is a check that "the number of output fields matches the number of
variables in the parse" — it catches column drift, where values silently shift by
one. It only worked with the **last** parse line in a function, and `status_line`
now has two, which made the check meaningless.

It now looks for the line that reads the specific function, and covers five pairs
instead of two: `links_state`, `tg_read` and `pn_read` were added.

### Also

* Tests: a new file `tests/status_line_tests.sh`, 14 checks.

---

## 3.59

**The menu items "Disable subscription after" and "Turn a subscription back on"
did not work. Plus a test that stops it happening again.**

### What was broken

The items were drawn in the panel screen, while the `case` branches that handle
the keypress ended up in the whitelist screen. The items are visible, pressing
them does nothing.

The cause is how I inserted them: anchored on "before the line `0|"") return`".
**Every** screen ends with that line, and the match landed on the wrong one. The
same mistake this project has already seen, when an insertion found the first
match instead of the intended one.

### Why the tests missed it

The check was this:

```bash
grep -q "panel set --disable-after" menu.sh
```

The string is in the file, so the check is happy. That it ended up in someone
else's function is something a whole-file `grep` cannot see in principle.

### What was added

`tests/menu_wiring.py` matches **within each screen**: every displayed item `[N]`
must have an `N)` branch in the same screen.

There turned out to be three subtleties, all real:

* The comparison must be against the `case` blocks that read the user's choice,
  not every `case` in the function. The panel screen has another one that
  translates an action name into text, and its `*)` would have disabled the check
  entirely.
* There can be several such blocks: the API screen first asks "install?" and only
  then shows the menu.
* A screen with a `*)` branch needs no checking — it catches everything left.

Verified that the test fails when a handler is removed and stays silent on the
intact file.

### Also

* The handlers were moved into the panel screen and removed from the whitelist.

---

## 3.58

**The address cut-off is back to an hour. And the disable message now says
plainly that it was Shape.**

### Twelve hours became redundant

They were introduced in 3.56 to cover the night: the notice arrives at three and
is seen at nine. But 3.57 brought disabling the subscription after a grace
period, and that covers the night — more precisely and without collateral.

The harm of a long cut-off remained: **a mobile address moves to another
subscriber within minutes**, and a bystander inherited someone else's
0.05 Mbit/s for half a day.

The roles are now cleanly separated:

| | What for |
| --- | --- |
| Address cut-off, 1 hour | hold the door while the countdown runs |
| Subscription disable, after 30 min | the actual measure |

An hour covers a half-hour countdown with room to spare. A bystander loses an
hour at worst instead of half a day.

If disabling the subscription is off and the night still needs covering, the
cut-off is raised by hand: `panel set --limit-min 720`. The old drawback returns
with it.

### The disable message

It existed before but did not say plainly who had done it. Now it does:

```
⛔ Subscription disabled · Node-1

👤 Ilya · @ilya
🆔 Telegram: 100000001
🔑 Panel login: user_100000001 · #101

🤖 Disabled by Shape: there were 146 addresses and no reaction for 30 min.

To turn it back on: shaperctl panel enable 741 or in the panel.
```

### Also

* Tests: the check for 720 in the presets was replaced by a check for 60 and for
  the absence of 720.

---

## 3.57

**Disabling a subscription after a grace period. The night is covered by hitting
the account rather than the addresses.**

### Why cutting off addresses does not cover the night

Two arguments, both from the node owner.

**A long cut-off hits the innocent.** A mobile carrier passes an address from one
subscriber to another within minutes. Twelve hours on an address means a
bystander can inherit someone else's 0.05 Mbit/s and sit like that for half a
day without understanding why.

**A short one leaves a gap.** An hour of cut-off against a six-hour pause is five
hours of free running.

It is the **account** that shares the subscription. That is what to hit.

### How it works

```bash
shaperctl panel set --disable-after 30
```

```
3:00   146 addresses → cut-off + notice, the countdown starts
3:30   no reaction → POST /api/users/741/actions/disable
       ↳ none of his buyers have connectivity, on every node at once
9:00   shaperctl panel enable 741 — once you have looked into it
```

**The countdown cancels itself.** If you disabled or revoked the subscription in
time, the buyers vanish from the connection list and at the next check the person
is no longer an offender. There is nothing to cancel by hand.

The queue lives in the panel state and is checked on every pass, bypassing the
notification pause: the pause is about messages, this is about a deadline the
owner set for himself.

### The safety valve

No more than **three** are disabled per pass. If the panel one day returns
garbage and hundreds end up flagged, the automation will not disable them — it
will only report.

A mistake of that kind costs too much to rely on it not happening.

### Off by default

This is the only action Shape takes that changes something in the panel rather
than in itself. Presets do not set it, it is switched on deliberately, and the
token will need permission to modify users.

Exceptions by tag and by id apply: a marked user does not even enter the queue.

### The way back

```bash
shaperctl panel enable 741
shaperctl panel disable 741
```

Menu: **Panel → [18] Disable subscription after**, **[19] Turn a subscription
back on**.

### Also

* Tests: 23 new ones. The countdown does not fire early and fires exactly on
  time, a manually handled user leaves the queue, a returning one starts from
  zero, junk in the state does not break it, the per-pass cap, an exempted user
  never enters the queue, the disable reaches the panel and comes with a message
  explaining how to undo it.

---

## 3.56

**The access cut-off now holds for twelve hours instead of one. And it can be
lifted from every address of a user with a single command.**

### The night

The notice arrives at three in the morning and is seen at nine. With an hour of
cut-off and a six-hour pause between checks it worked out like this:

```
3:00   caught, access cut off
4:00   the limit expired — free
9:00   the next check on him is possible at all
```

**Five hours of running as if nothing had happened.** During the day this does
not matter — the owner sees the message and disables the subscription in a
minute. At night there is no one.

Twelve hours cover the night entirely and are still less than a day.

### Lifting — from every address at once

A reseller has a hundred and fifty addresses, and lifting them one by one through
the menu is physically impossible.

```bash
shaperctl release --user 741
```

Menu: **Limited addresses → Lift from every address of a user**. The id comes
from the Telegram card, the "Panel" line.

For this the panel's penalty now remembers whose it is: the user's id and name.
The record used to say only "sharing", with no way to tie it to a person.

### Why not the simple route

The pause between checks could have been lowered to an hour, so the cut-off would
renew itself every hour. But the pause also governs notifications: over a night
that would be six messages about the same person instead of one.

### Also

* Tests: 12 new ones. The id and name in the penalty record, lifting by id, a
  non-numeric id, someone else's id, twelve hours in both presets, the menu
  numbering.

---

## 3.55

**Both presets now cut off a sharer's access rather than merely dropping his
connections.**

### Why the drop did not work

`drop` tears down established connections through the panel. The client
reconnects within a second. As a signal saying "we see you" that works; as a
measure it does not: a reseller lost his connections every six hours and
immediately got them back.

### What `block` does

Two things at once:

1. **0.05 Mbit/s** on every address of the offender the node can see, for
   60 minutes.
2. **A drop of the current connections** through the panel.

Without the second the first is useless: already open connections would merely
become slow and the person would stay online until they timed out. Without the
first the second is useless — he is back in a second.

Together they mean the buyers reconnect and find there is practically no
connectivity. For an hour.

### What it does not do

The limit is **local**, on this node. A buyer who moves to another node will be
free there until that node also sees twenty addresses of his.

That is deliberate: the auto-limiter and sharing detection in Shape answer for
their own node and depend on no one. Each node will catch him in its turn.

### Zero cannot be used as the speed

Zero in the kernel map means "no limit" — the engine would let the traffic
through unaccounted. Hence 0.05, not 0.

### Also

* Tests: 2 new ones — both presets set `block`, and no bare `drop` remains in
  them.
* The blocking section in the README was rewritten: it used to explain the
  mechanics, now it also explains why they are needed instead of a drop.

---

## 3.54

**The sharing threshold is the same on both nodes — 20 addresses. And
`panel show` reports how far back the node can see.**

### Why the threshold differed and why it should not

Ten addresses on home nodes and twenty on quota nodes followed from the reasoning
"a mobile carrier changes the address several times an hour, while at home there
is one address for the whole family".

The reasoning is right and the conclusion is not: **a home node is not only
wifi**. Mobile clients connect to any node. So the threshold describes the
client, and the client is unknown to us — which means taking the larger value.

A family of five phones produces fifteen to twenty addresses in ten minutes
through reconnects and handovers. Real resellers caught on those same nodes
produce **146 and 230**. At a threshold of twenty the margin is tenfold.

### How much the node remembers

The node owner asked how long an active session lives in the panel. There is no
answer either in the documentation or in the environment variables — and that is
not an omission by the panel's authors: the connection list is not a history but
a **live snapshot from Xray**. How long a dropped address lingers there is up to
Xray.

But it can be measured. The age of the oldest address is now recorded on every
poll, and `panel show` prints it:

```
  Oldest address in the list : 14 min
```

And when it is **shorter than the window**, a warning follows: the window is then
capped by the node rather than by the setting, and adjusting it is pointless.

### What stayed the same

The 10-minute window and the 300-second poll interval. The window is not
responsible for how fast an offender is caught but for how many addresses are
counted; the speed comes from the interval. The scenario "a hundred addresses
connected within three minutes" is caught in five to six minutes, and that is
enough: a reseller's buyers stay for hours, not minutes.

### Also

* Tests: 8 new ones. The oldest address's age is recorded and visible in
  `panel show`, a node with short memory is flagged, the threshold is identical
  in both presets and no ten remains in them.

---

## 3.53

**Hours of upload became a notice without a penalty. And nodes with paid traffic
finally limit the upload, not just the download.**

### Why hours of upload do not punish

A question from the node owner: what if someone's phone is running a backup?

We did the arithmetic:

| What | Volume | At 20 Mbit up |
| --- | --- | --- |
| Daily automatic backup | 0.1–2 GB | 1–13 minutes |
| Back from a holiday | 30 GB | 3.3 hours |
| **First iCloud setup** | **100–200 GB** | **11–22 hours** |

A routine backup comes nowhere near six hours. But someone switching on the
upload of ten years of photos for the first time pushes for a whole day — and
**everything** lines up: a proportion above a hundred percent, a data share near
a hundred, the hours, a volume above thirty gigabytes.

Exactly one thing tells them apart: a backup ends, seeding does not. We do not
count that.

So the signal arrives as a notice and the decision stays with the owner:

```
🔔 Long upload · Italy

👤 Chopiks
🔑 Panel login: user_100000006 · #104

📍 Address: 203.0.113.33
Uploaded for 9.4 h in 24h — the threshold is 6 h
📈 For the day: ↓ 4.2 GB · ↑ 11.3 GB (269%)

No limit applied. Seeding and a phone's first backup look the same: it is your call.
```

The signal has no weight at all — it takes no part in the penalty decision.

### Upload on quota nodes

The second question from the same message: the download is capped at 3 GB an hour
and the address gets blocked — what about the upload?

There was nothing on the upload. The traffic bill covers **both** directions, and
the budget was leaking the other way.

```bash
shaperctl guard --upload-gbh 3 --upload-day 25
```

A mirror of the download thresholds, with the same numbers.

And here the whole headache of today disappears: **on a quota node it does not
matter whether it is a torrent or a backup** — a gigabyte costs the same,
whatever it is. Intent matters only where the traffic is free.

### Presets

| | Quota node | Regular |
| --- | --- | --- |
| Hourly upload | **3 GB** | — |
| Daily upload | **25 GB** | 30 GB |
| Volume notice | — | 10 GB |
| Hours notice | 6 h | 6 h |

### Also

* A corrupted timestamp in the packet counter no longer produces "over 496620 h":
  a window longer than a day means garbage, not a long upload, and the line is
  not printed at all.
* Tests: 24 new ones. Twenty hours of upload give no penalty, the signal has no
  weight, the hourly upload threshold exactly on and below the line, an empty
  window, a corrupted timestamp, both presets.

---

## 3.52

**Hours of upload — a new signal. The daily download threshold became a number.
And a command tying the bot's report to Shape's data.**

### Hours of upload

Every previous seeding signal measures "how much". This one measures **"how
long"**, and that is exactly where a torrent differs from work:

| | How long it lasts |
| --- | --- |
| Three gigabytes at 50 Mbit | 8 minutes |
| An archive for a client | 20 minutes |
| Seeding | 12 hours, 16, around the clock |

```bash
shaperctl guard --upload-hours 6
```

What is counted is the number of samples where the upload exceeded 0.3 Mbit/s.
The lower bound is mandatory: the acknowledgements of an ordinary download come
to a noticeable fraction of a megabit, and without it "hours of upload" would
become "hours online".

The signal depends on neither proportion, nor packet size, nor protocol — kernel
packet merging, QUIC and encryption have no effect on it. Of everything we have
built, it is the most robust.

Set on regular nodes only. On quota nodes the job is different: there one counts
the money spent on traffic, not hunts for seeding.

### Daily download threshold: 360 → 150 GB

It was derived from the channel — sixteen hourly thresholds — giving 180 GB at
fifty megabits and 360 at a hundred. The node owner put it briefly: even a
hundred is too much.

He is right, and arithmetic had nothing to do with it. Honest use does not reach
such figures: 4K is 7–16 GB an hour, a Steam game is 120 GB once and over three
hours. Three hundred and sixty is barely reachable at all.

It is now a number, not a derivative: **150 GB**. One game fits whole, two do
not. The penalty for volume alone stays soft — a third of the channel — so even
someone who hits it finishes the download, just slower.

### `panel user 6085`

The reverse of `panel who`: there an address maps to a person, here a person to
addresses.

It exists for checking the bot's reports. The bot takes its numbers from the
panel, and the panel **does not store "up" and "down" separately** — everywhere
in its responses there is only `totalBytes`. So "123 GB in 24h" is the sum of
both directions, and a download cannot be told from seeding by it.

```
  Ilya · user_100000001 (100000001)
  Addresses on the node: 2

  203.0.113.33     ↓ 58.2 GB · ↑ 61.4 GB (105%)
                    96% as data · packet 1310 B · uploaded for 9.0 h
  203.0.113.13     ↓ 3.1 GB · ↑ 0.1 GB (3%)
                    0% as data · packet 140 B
```

### What was decided against

There will be no fleet-wide checks. Hopping between nodes does not let an
offender escape; it lets him be caught on each node in turn. And cross-node rules
would break the main property of the auto-limiter: **it works without a panel at
all**. A node answers for itself.

### Also

* The daily counter gained an `up_sec` field. Old files read as before.
* Tests: 22 new ones. The hour threshold exactly on and below the line, a missing
  field, the upload lower bound, `panel user` with a non-numeric id and with an
  absent user, the up/down split in its output.

---

## 3.51

**Exceptions by panel tag. And the address in a message links to ipinfo rather
than to the client's own machine.**

### A tag instead of a list of IDs on every node

Every user in the panel has a `Tag` field. Shape requests the user card anyway —
for the name and the Telegram ID — so the tag costs zero extra requests.

```bash
shaperctl panel set --exempt-tags BUSINESS,OFFICE
```

Mark the business accounts in the panel — **in one place** — and every node stops
touching them. A new client: put the tag on them, change nothing on the nodes.

The list of IDs (`--exempt`) remains and works as before; there are two lists now
and a match in either is enough. Tag case does not matter.

The tag applies to **both** checks: the auto-limiter and sharing detection. In
sharing detection it is checked after the offender's card is fetched — there is
no sense in pulling cards for all six thousand users just to read a tag.

The event is written to the log as `panel_exempt`.

### The address links to ipinfo

The address used to be plain text, and Telegram linked it itself — to
`http://<address>`, so tapping opened an attempt to reach the client's own
machine.

The link is now explicit and points to `ipinfo.io`, as in the Remnawave
interface.

That is an external service: the address goes to it the moment you tap. Nothing
is sent on its own.

### A correction about offices

In earlier notes I wrote that an office on one subscription looks like resale —
many addresses under one user. That is wrong.

On home internet ten computers sit behind **one** address. Sharing detection
never touches them. What is dangerous to them is the volume rules: that one
address carries the combined traffic of ten people.

Resale looks the opposite way — **one device and two hundred addresses**: the
seller fetched the subscription through the app once and mailed the config to
buyers, who never appear in the device list.

The same device count, two opposite conclusions. What matters is its ratio to the
address count, and that is the subject of the next version.

### Also

* Tests: 17 new ones. A tag match and case-insensitivity, a foreign and an empty
  tag, a tag without an ID, the tag in sharing detection (connections not
  dropped, Telegram silent), and the same user without the tag — caught.

---

## 3.50

**A gigabyte became a billion bytes. The thresholds and what the message showed
were in different units.**

### How it looked

```
Reason: uploaded disproportionately much in 24h
📈 For the day: ↓ 472.6 MB · ↑ 286.2 MB (61%)
```

The signal's threshold is 300 MB of upload. The card says 286.2. It looks as
though the rule fired for nothing.

It fired correctly. The display divided by 1024 while the threshold is set via
`1e6`: 286.2 × 1024² is 300.1 million bytes. The threshold was crossed, it was
simply shown in different units.

A discrepancy of seven percent on megabytes and seven and a half on gigabytes is
enough to make a decision look unfounded exactly in the borderline cases — that
is, exactly where it gets checked.

### What changed

`fmt_bytes` now divides by 1000. A gigabyte is a billion bytes, as in an ISP
tariff and as in every threshold in this project: `download_gb_per_day * 1e9`,
`upload_day_gb * 1e9`, `upload_ratio_min_mb * 1e6`.

Numbers in all messages, in the monitor, in the statistics and in the digest will
grow by about seven percent. No traffic was added — it is simply named the same
way the thresholds are.

### The rule

The number by which a person checks a decision must be in the same units as the
decision. Otherwise it cannot be checked, only believed.

### Also

* Tests: 7 new ones, including a direct check that the display of the lower
  upload bound matches the bound itself.

---

## 3.49

**A Telegram notification when a newer version appears in the repository.**

```
⬆️ An update is available · Node-2

Installed: 3.48
In the repository: 3.49

To update: shaper → Service → Update from GitHub
```

### How it works

Every six hours the node fetches a single `VERSION` file from the repository. Not
a clone — a dozen bytes. Cloning the repository from the background watchdog
would mean tens of megabytes and minutes of work on a slow node, every few hours
at that.

The message arrives **once per version**. Otherwise it would turn into a reminder
four times a day, and people would stop reading it — as they do with everything
that repeats.

The proxy is the one configured for Telegram: on nodes where Telegram is
unreachable, GitHub usually is too.

If the repository does not answer, nothing happens and nothing is written; the
next attempt is in six hours. Both `main` and `master` are tried: guessing inside
code that runs on other people's nodes is not acceptable.

### Version comparison is numeric

`3.5` is older than `3.48`, though as strings it is the other way round. The
number is parsed into components and compared component by component.

If the installed version cannot be read, there is no alarm: without a reference
point there is nothing to compare against.

### The toggle

**Telegram → [13] About updates**, on by default. On the command line:
`telegram set --updates on|off`.

### Also

* The check state lives in the same `guard.state` as the rest of the watchdog's
  memory — no new file appeared.
* Tests: 20 new ones. Numeric version comparison, one message per version, the
  six-hour pause, an unreachable repository, the toggle off, an unreadable
  installed version.

---

## 3.48

**The ratio threshold on home nodes went from 35% to 50%. The first confirmed
false positive.**

### What happened

A penalty went to someone whose panel description reads "marketing and art". Over
ten hours he uploaded 621 MB — that is 0.14 Mbit/s, a thin trickle, and 85% of it
went in large packets. The ratio came out at 38% against a threshold of 35.

The portrait of a quiet seeder and the portrait of a specialist sending mockups
to clients coincide completely at the network layer. They cannot be separated —
one can only avoid drawing the line where one does not know what lies beyond it.

### Where the line was

Thirty-five was chosen from your statistics over 6143 addresses: honest clients
ended at 25%, seeders started at 45%, and in between it was empty. Thirty-five is
the middle of that emptiness — that is, a line drawn through the unknown.

The first person to land in it turned out to be innocent.

### What the accumulated statistics showed

An important correction to what I said earlier. The 300 MB lower bound on upload
volume cuts off more than half the list: out of thirteen addresses on each node,
only a few reach the ratio check at all.

The real picture across two nodes:

```
392%  seeding
229%  seeding
 75%  seeding
  ·
  ·   ← empty
  ·
 38%  the marketer, a false positive
```

The gap is between 38 and 75, the middle is 56. Fifty was chosen, erring towards
caution.

### Mobile nodes are untouched

They stay at 35: neither accumulated statistics nor work uploads from a phone. If
the same thing shows up there, it will be raised too.

### The rules are independent, and that is worth remembering

The 30 GB threshold added yesterday had no bearing on this case: the person had
621 MB, sixteen times less than the notice level. Volume is the **fourth** rule,
not a replacement for the others. If any one of them fires, a penalty follows.

### Also

* Tests: 6 new ones. The marketer passes at 50 and is caught at 35, a seeder at
  75% stays caught, an address with less than 300 MB of upload never reaches the
  check at all.

---

## 3.47

**Daily upload in gigabytes: 10 GB is a notice, 30 GB is a limit. On home nodes
only.**

### Why another signal

Every previous seeding signal measures something indirect, and each one errs in
its own way because of it:

| Signal | What it measures | Where it misses |
| --- | --- | --- |
| Upload ratio | up/down disproportion | a conversation is exactly 100% |
| Data share | packet size | depends on protocol and kernel merging |
| Two-way | speed in both directions | a quiet seeder never reaches the thresholds |

Upload in gigabytes measures nothing indirect. Thirty gigabytes up is thirty
gigabytes up, whatever they are and over whatever protocol. It can be explained
to a customer in one sentence, and there is nothing to argue about.

It is also the best available answer to the business-account question: a law firm
with three gigabytes of documents a day is nowhere near the threshold.

### Two levels

```bash
shaperctl guard --upload-warn 10 --upload-day 30
```

**10 GB — a notice and nothing else.** One message per address per day:

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

**30 GB — a limit.** With the usual penalty, reason `uploaded tens of gigabytes
in 24h`.

The signal is independent: there may be no download at all, no current upload at
the moment of the check, and any packet sizes. Only the volume matters.

### Presets

The home preset sets 10 and 30. The mobile preset sets **zeros, explicitly** — at
ten megabits such numbers are meaningless, and switching over from the home
preset must not leave its leftovers behind.

### Exceptions apply

A user in `panel set --exempt` gets neither a notice nor a penalty from this
signal, as with all the others.

### Also

* The notice level is remembered in `guard.state` by date rather than by a flag:
  the day closes itself, with no separate cleanup at midnight.
* Both levels are visible on the auto-limit screen and editable by hand — entries
  `[17]` and `[18]`.
* Tests: 20 new ones. The threshold exactly on and below the line, independence
  from download and from the data share, the notice not limiting, the message
  text, visibility.

---

## 3.46

**Panel exceptions now apply to the auto-limiter as well. A business account is
not limited at all.**

### Why

A law firm, a real-estate agency, a company on Bitrix — people paying for
connectivity in order to work. They must not be touched, and both of our checks
see them as offenders.

**Sharing detection.** Twenty employees on one subscription are twenty addresses
under one panel user. The rule counts addresses, not who they are. On home nodes
the threshold is ten with the `drop` action — meaning the office has its
connections cut in the middle of a working day.

**The upload ratio.** An agency uploading property videos produces the same
proportion, the same packets filled to the brim and the same data share as a
seeder. At the network layer they are literally the same thing, and no threshold
separates them — only knowing who it is does.

### What was done

```bash
shaperctl panel set --exempt 2442,6672,152
```

The same list that sharing detection already used now means "leave alone
entirely". These users get no penalty, no drop and no notification.

The trigger is still written to the event log as `guard_exempt`: it can be looked
at, and it will not disturb anyone.

The owner of an address is now resolved **before** the penalty rather than after.
The order used to be the reverse — limit first, label second; that does not work
for exceptions.

### Visibility

The number of exceptions is shown on the auto-limit screen, even though the
setting itself lives in the panel section. A setting that changes the outcome
while staying invisible on its own screen is a recurring class of mistake in this
project, and there are dedicated tests for it.

### A limitation

Without a panel link the exceptions do not work: there is nowhere else to learn
whose address it is. On nodes without a panel the auto-limiter behaves as before.

### Also

* Tests: 12 new ones. An exempted user is left alone, others are not, an ID as a
  number and with spaces, a missing panel and a missing ID, visibility on the
  screen.

---

## 3.45

**The share threshold went 70 → 55. The second node showed a seeder in the gap
the first node thought was empty.**

### What the distribution showed

The `status --bulk` command, added in 3.44, was run on two nodes.

On the first the gap fell between 39 and 73 — a threshold of 70 looked
acceptable. On the second there was an address in the 60–70 range:

```
203.0.113.46   150.6 MB ↓   589.7 MB ↑   ratio 392%   66% as data
```

It uploads four times what it downloads, mostly as data. That is seeding, and a
70% threshold was missing it.

The combined picture, 26 addresses across two nodes:

```
    0-39   ███████████████ 15    calls sit at 1-6%
   40-65   ·  none
   66-100  ███████████ 11        seeding
```

The real gap is between 39 and 66. The threshold is set in its middle: **55%**.

### Why the threshold moved three times

| Value | Chosen from | How it was wrong |
| --- | --- | --- |
| 30 | three Telegram cards | a video call passed it with 32 |
| 70 | the same three points, other side | sat at the cluster edge, a seeder at 66 missed |
| 55 | 26 addresses across two nodes | the middle of the gap |

The lesson is written into the code next to the constant: a threshold set from a
handful of observations is almost certainly in the wrong place. The 35% ratio
threshold landed correctly on the first try only because it was chosen from 6143
addresses.

### What was confirmed

Calls on both nodes sit at 1–6%, far from the threshold:

| Ratio | As data |
| --- | --- |
| 87% | 1% |
| 46% | 2% |
| 34% | 6% |

All three cross or nearly cross the 35% ratio threshold. Without the share they
would be penalised every evening.

### Also

* The menu texts described the previous rule (by maximum packet) — they now
  describe the current one, by share.
* Tests: 8 new ones, all live data points from both nodes.

---

## 3.44

**`status --bulk` — the distribution of the data share in uploads. So the
threshold is set from data rather than from three Telegram cards.**

### Why

The 35% ratio threshold hit the mark because we looked at the distribution across
6143 addresses and saw where it was empty: honest clients at 2–25%, seeders at
45–242%, nothing in between.

The 70% share threshold was set from three points in notifications. That is
guesswork, and it already sits suspiciously close to a live address at 78%.

```bash
shaperctl status --bulk
```

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

  top of the list          down        up  as data    avg    max
  ...
```

The emptiness between 40 and 70 is where the threshold goes. What falls under the
current one is highlighted in red.

Menu: **Statistics → 📦 Data share in uploads**.

### Where the numbers come from

From the daily counters in `/etc/shaper/daily.json`, not from the kernel map: the
split of bytes into large and small lives only there. So the picture covers the
current day, from midnight.

A lower bound on upload volume (100 MB by default, changed with `--ratio-mb`)
cuts out the noise: for an address with two megabytes of upload the share means
nothing.

### On privacy

The distribution itself does not use addresses — it is just a histogram. Addresses
appear only in the top-of-list section, which is there to look up a particular
offender on your own node.

If the picture needs discussing with someone, the ten histogram rows are enough:
there is nothing in them that relates to a person.

### Also

* Tests: 12 new ones. Sorting, bucketing, the volume floor, a corrupted field, an
  empty day printing an explanation instead of blankness.

---

## 3.43

**The watchdog's memory moved to disk. Both maps I had left in memory were being
wiped by every update.**

### The name is lost after twenty minutes

At 20:18 the address carried a name from the panel. At 20:34 the same address
with the same reason arrived nameless: "the panel does not see it".

The panel knows a person only while they are on the node. We received the answer,
showed it and threw it away — and when the person dropped off, everything about
them vanished too, though it had been in our hands twenty minutes earlier.

The owner of an address is now remembered for **twelve hours**. The card states
plainly which poll the name came from:

```
👤 Olga Podshibiakina · @olga_v
🆔 Telegram: 100000004
🔑 Panel login: user_100000004 · #103
the panel does not see it now — name from the 20:18 poll
```

The caveat is mandatory: a different person may have taken the address since.
Twelve hours were chosen for exactly that reason — enough for an evening's work,
too little for the address to change hands.

### The six-hour cooldown never worked at all

A message about the same address arrived twice, sixteen minutes apart.

The "already reported" map lived in the watchdog's memory. I chose that
deliberately and wrote so in a comment: "a restart costs one extra message, while
a file on disk costs its own code and its own failures."

The choice was wrong. The node owner updates several times an evening, the
watchdog restarts with the update, and at that rate a six-hour cooldown never
fires once.

Both maps now live in `/var/lib/shape/guard.state` and survive a restart.

### The maps do not grow without bound

Pruning by age achieves nothing on a node with thousands of addresses: everything
there is fresh. So after the age prune the owner map is trimmed by size, oldest
first. The ceiling is 2048 addresses.

### Also

* The file was added to the README list; uninstalling removes it along with
  `/var/lib/shape`.
* Tests: 15 new ones. An owner is remembered and forgotten on schedule, junk in
  the map does not break it, the map is trimmed oldest-first, stale details are
  marked, a corrupted timestamp does not break the card.

---

## 3.42

**The share threshold went from 30% to 70%. Thirty did not work — it missed in
the right direction.**

### A video call passed the filter with two points to spare

```
📈 For the day: ↓ 361.5 MB · ↑ 361.5 MB (100%)
📦 Upload over 10 min: 32% as data · packet 497 B · max 1354
```

It uploaded exactly as much as it downloaded — matching to hundredths of a
percent. Seeding never looks like that: the seeders caught so far were at 660%,
242%, 88%. An exact 1:1 comes from a conversation, where both sides send the same
stream at the same bitrate.

Yesterday the same address was at 267 B with a maximum of 349 — pure audio. Today
497 and 1354: video was turned on. A video stream travels in packets just under a
thousand, so its share is not a few percent but a third.

It passed my 30% threshold with 32.

### Where the threshold sits now

| Ratio | As data | What it is |
| --- | --- | --- |
| 660% | **100%** | seeding |
| 100% | **32%** | a video call |
| 102% | **1%** | audio plus one attachment |

Seventy percent is the middle of the real gap. The method is the same one used
for the ratio threshold: not from theory, but from where the live data is empty.

A real seeder uploads almost nothing but chunks: 90–100%. It can drop to seventy
only if something else is going on alongside — and then the ratio still stays
above 150%, while a conversation hovers around a hundred.

### A caveat

The packet field for that address covered ten minutes, not a day: the field is
reset on a format change, and the format changed in 3.41. Over a full day the
share may come out differently, and then the threshold will have to move again.

Three data points so far. That is few, but the gap between 32 and 100 is wide
enough not to wait: the cost of waiting is people on video calls getting 1 Mbit/s
for an hour.

### Also

* The 3.41 release notes name the threshold as thirty percent. That is true for
  3.41 and untrue from 3.42 onwards.
* Tests: 4 new ones, all three live data points plus a seeder with a call
  running alongside.

---

## 3.41

**What decides is "how much", not "did it ever". And the packet line no longer
labels itself "for the day" when that is untrue.**

### The maximum turned out not to be enough

The maximum added in 3.39 is a "it got there once" mark, and a **single
ten-second window** sets it. Send a video in a messenger or a file to the cloud,
and the maximum is 1400 for the rest of the day — after which calls pass the
filter as seeding.

Here are two live addresses, indistinguishable by the maximum:

| Daily upload | Average | Maximum | **As data** | What it is |
| --- | --- | --- | --- | --- |
| 976 MB | 1279 B | 1400 | **96%** | seeding |
| 347 MB | 780 B | 1539 | **1%** | a conversation plus one attachment |

How many bytes of the upload went in packets of 1000 and above is now counted.
The gap between 1% and 96% is wide enough that the threshold can sit anywhere in
the middle; it sits at **30%** — with room for mixed windows where someone talks
and uploads at once and the in-window average is diluted.

The ratio signal now requires that share rather than the maximum. The maximum
stays in the message: together with the share it reads correctly, separately each
one misleads — and each one did.

### Two lines now, each with its own period

```
📈 For the day: ↓ 146.7 MB · ↑ 976.1 MB (665%)
📦 Upload over 11.9 h: 96% as data · packet 1279 B · max 1400
```

Volumes are counted over the day. The packet field is reset on a format change,
and the format changed in 3.39 and changes now — so right after an update it
covers minutes, not a day.

This was checkable by arithmetic in the messages themselves: on one address the
average packet grew from 267 to 781 over sixteen minutes, while the packet count
derived from the daily bytes "fell" from 1.23 million to 445 thousand. That does
not happen — the bytes in those two numbers simply came from different periods.

One line covering two periods was lying about one of them. The second line now
always states its own period honestly.

### What to do

Update. The packet field will reset once more — this is the last format change
for this task; all five numbers now live in one field and start together.

For the first hours after the update the second line will cover a short period,
and that is written plainly in it. By tomorrow the period will match the day.

### Also

* Tests: 22 new ones. A call with an attachment does not pass the filter, a
  seeder does, the share is computed from its own window's bytes, the threshold
  exactly on the boundary, the window length returned separately, a field of the
  wrong length not breaking the line.

---

## 3.40

**The ratio signal was catching video calls. It now requires the upload to be
data.**

### Three calls in one evening

The maximum packet size added in 3.39 answered the question on its first day:

| Address | Ratio | Average packet | Daily maximum |
| --- | --- | --- | --- |
| 203.0.113.40 | 38% | 538 B | **697** |
| 203.0.113.38 | 100% | 267 B | **349** |
| 203.0.113.5 | 55% | 368 B | **399** |

Not one came near 1300 over a whole day. A torrent uploading pieces would have
reached the segment limit at least once — a peer's chunk is always filled to the
top. Here the ceiling is 697.

329 MB down against 328 up, exactly 100%, is a conversation: both sides speak
equally. Discord, Telegram and WhatsApp were the ones being penalised.

The 35% threshold is still right. Disproportionate upload really is suspicious —
it just is not unique to seeding.

### What changed

A new setting, `ratio_needs_packet`. With it the ratio signal fires only if the
**maximum** upload packet of the day reached 1000 bytes.

Both presets turn it on. The signal catches the same thing on a phone and at
home, and conversations happen everywhere.

**Why a thousand rather than six hundred.** Six hundred is the threshold of the
instantaneous signal, chosen for an average over ten seconds of active transfer.
On a daily maximum a video call reaches seven hundred, and six hundred does not
cut it off.

**Why the maximum and not the average.** The average is arithmetic and small
packets outnumber large ones by an order of magnitude — 440 MB in 1400-byte
chunks plus 550 MB in 60-byte acknowledgements come to 109. The maximum says it
outright: did anything reach the segment limit or not.

### The maximum's update floor was lowered

From 100 KB to 20 KB per sample — that is 16 Kbit/s.

Otherwise a quiet seeder would not gather a single qualifying window in a day and
would slip past the very check that is meant for him. He uploads half a megabit,
and one megabit while limited; at a hundred kilobytes per ten seconds the margin
was too thin.

### What to do

Update and apply the preset again — the setting is off by default and will not
turn itself on.

To confirm it did: the Auto-limit screen, the line under the ratio signal. Or
`shaperctl guard`.

### Also

* The manual toggle is entry `[15]` on the auto-limit screen; presets moved to
  `[16]`.
* Tests: 16 new ones. All three live calls go free, a seeder is caught, the
  maximum threshold exactly on the boundary and one byte below, a corrupted
  field, the update floor admitting a quiet seeder.

---

## 3.39

**The daily average packet answered the wrong question. A maximum was added. And
the panel no longer stays silent about why it is silent.**

### "upload packet 109 B" against a gigabyte of upload

I offered this figure as the answer to "torrent or not". It does not answer that,
and here is why.

It is an arithmetic mean, and a stream carries an order of magnitude more small
packets than large ones. 440 MB in 1400-byte chunks plus 550 MB in 60-byte
acknowledgements is 314 thousand large packets against 9.2 million small ones,
and the mean comes out at 109. Exactly what you saw. Data was going up, and the
mean does not show it.

The "from 600 bytes it is data" threshold came from the monitor, where the
average is taken over ten seconds of active transfer. In a daily aggregate it
does not hold: that is a different quantity.

A **maximum** is now tracked as well — the largest average packet over any
ten-second window in the day:

```
📈 For the day: ↓ 1.5 GB · ↑ 997.2 MB (67%) · upload packet 109 B (max 1340)
```

| The line | What it was |
| --- | --- |
| upload packet 109 B | no data went up at any point |
| upload packet 109 B (max 1340) | it did, it just drowned in the average |

The maximum is only updated on samples with more than 100 KB uploaded: a handful
of stray packets must not set it.

### The panel was silent for three hours and did not say so

`panel show` displayed a last successful poll at 16:32 and not a word about an
error, even though the field for it exists and is printed.

`panel_scan` caught `PanelError` only. Everything else — broken JSON, an
unexpected response, a socket failure outside the wrapper — escaped into the
watchdog loop's generic handler and settled in the journal as a `watch: ...`
line. There was a cause, and there was no way to learn it from `panel show`.

Everything is caught now, and `last_error` receives the exception name with its
text.

### "the panel has never answered yet" with a successful poll at 16:32

The address map lives in the process memory and is empty after every watchdog
restart — that is, after every update. Hence "never".

But the disk holds the timestamp of the last successful poll, and it answers more
precisely. With an empty map that timestamp is now used: "the panel has not
answered for 179 min" is a diagnosis, while "never" is left for the case where
there genuinely were no successful polls.

### Also

* The `upkt` field is now three numbers: bytes, packets, maximum. Records of the
  earlier length are reset wholesale — all three must start together.
* Tests: 15 new ones. A mixed stream yields a low mean and a high maximum, the
  volume floor, an impossible maximum is not printed, four different exceptions
  from `panel_fetch` are not lost, the silence period is taken from disk.

---

## 3.38

**The `shaperctl` command finally exists. And an average packet is no longer
eleven bytes.**

### `shaperctl.py: command not found`

The hint in Telegram suggested a command that did not exist. The file sits in
`/opt/shaper` and is not on `PATH` — only the `shaper` menu was in
`/usr/local/bin`. Meanwhile the README mentions `shaperctl.py` seventy-one
times, and not one of those mentions worked in a fresh shell.

The installer now places two commands:

```
shaper       — the menu
shaperctl    — everything else
shaperctl.py — an alias, so older notes and past release notes keep working
```

Both READMEs were rewritten to `shaperctl`. Uninstalling removes both commands.

### "upload packet 11 B"

The same mistake as "168750 B" in 3.36, only in the other direction — and that
is my fault twice.

In 3.37 I split the bytes and the packets into two fields and put a **ceiling**
on the result. But two fields can be had by halves: a record from 3.36 carried
packets and carried no bytes, so after the update the bytes started from zero
against already accumulated packets, and the quotient went down instead of up. A
one-sided check catches half the cases by definition.

It is now **one field of two numbers**, not two fields. Half of such a field
cannot be had: it is either absent entirely or present entirely.

Plausibility bounds are on both sides: from 40 bytes (a bare acknowledgement, 20
IP plus 20 TCP) to a jumbo frame. A value outside them is not printed at all.

A corrupted field, a field of the wrong length and zero packets are covered too —
the line simply arrives without the packet.

### What to do

Update. On the first day after the update the average is computed from the
moment the new version started, which is correct and does not drift.

### Also

* Tests: 12 new ones. Both sides of the bounds, a corrupted field, half a field,
  zero packets, the presence of both commands in the installer and their removal.

---

## 3.37

**Two lies in the penalty message. Both from 3.35 and 3.36, both mine.**

### "the panel has not answered for 29796012 min"

Fifty-six years. That is the whole Unix epoch.

The "address → whose it is" map lives in the process memory, and after the
watchdog restarts — that is, after every update — the timestamp is zero. The age
was computed from it: `now - 0` is the current unix timestamp.

There are now four reasons why an owner fails to resolve, not three:

| What is printed | When |
| --- | --- |
| the panel link is not set up on this node | the panel is off on this node |
| **the panel has never answered yet** | the watchdog has just started, or the panel is unreachable |
| the panel has not answered for N min | there was a successful poll, but long ago |
| at the last poll (N min ago) this address was not among the connected ones | the person was not on the node |

In the new case no age is printed at all — there is nothing to print. Instead it
says what to check it with: `shaperctl.py panel show`.

In the first minutes after an update this message is normal: the panel is polled
every five minutes, and until the first poll the map is empty.

### "upload packet 168750 B"

The maximum for a packet is fifteen hundred bytes. A hundred and sixty-eight
thousand does not happen.

The average was computed as "daily bytes ÷ daily packets". After an update the
byte counter held the whole day gone by, while the packets had only started
counting when the new version launched. Hence the number.

In 3.36 I wrote in these very release notes that "on the first day after the
update the line simply arrives without the packet". That was wrong: the field
was not missing, it was partial, and I did not account for it.

The bytes behind that average are now kept by **their own pair of counters**,
incremented in the same place at the same moment. Their quotient is meaningful
from the very first sample after an update, with no transitional day.

Plus a ceiling in case they drift apart anyway: an average above a jumbo frame
(9000 bytes) is not printed at all. Lying is worse than saying nothing.

### What to do

Update. Nothing needs reconfiguring, old `daily.json` files read as before — the
missing field defaults to zero, and until the first sample the line arrives
without the packet. The first sample is ten seconds away.

### Also

* Tests: nine new ones. A separate cause code for an empty map, the absence of
  an epoch-sized number in the text, an impossible average not being printed, a
  possible one being printed, the ceiling equalling a jumbo frame.

---

## 3.36

**The penalty message now says what exactly for — in numbers, not just by the
name of the rule.**

### The reason named the rule, not the act

```
Reason: uploaded disproportionately much in 24h
```

True, but it does not answer "what was he doing?". The same proportion comes
from seeding a torrent, from uploading a backup to the cloud, and from a day of
video calls. To find out you had to go to the node and look at `status --full`.

All the numbers needed are in the watchdog's hands at the moment of the penalty.
Now they are in the message:

```
📍 Address: 203.0.113.36
🐌 Speed reduced to 1 Mbit/s for 12 h
Reason: uploaded disproportionately much in 24h
📈 For the day: ↓ 2.1 GB · ↑ 3.4 GB (162%) · upload packet 1310 B
```

| The line | What it was |
| --- | --- |
| ↓ 40 GB · ↑ 0.4 GB (1%) · packet 150 B | a download: only acknowledgements go up |
| ↓ 2.1 GB · ↑ 3.4 GB (162%) · packet 1310 B | seeding: data goes up |
| ↓ 0.1 GB · ↑ 5.0 GB · packet 1400 B | a cloud upload: almost nothing comes down |

### The packet is averaged over the day, not taken from the last sample

The average upload packet size is the decisive number: a TCP acknowledgement is
100–170 bytes, a torrent chunk is 1200–1400, and this does not depend on the
channel speed.

Taking it from the last ten-second sample will not do: at the moment of the
penalty the address may have been silent upward, and the message would carry a
zero. So the daily counter gained a fourth number — how many packets went up —
and the average is computed across the whole day.

Old `daily.json` files read as before: the missing field defaults to zero, and
on the first day after the update the line simply arrives without the packet.

### What stayed the same

The line is added for every reason, not just the upload ratio. For hourly volume
it is just as useful: "↓ 40 GB, acknowledgements upward" is a game download, not
a torrent.

If there are no counters at all, there is no line. If there was no download, the
proportion is not printed: no need to divide by zero for it.

### Also

* `penalty_figures()` was pulled out into a function and covered by tests: both
  pictures (a download and seeding), zero download, missing counters.
* `traffic_sample()` returns `up_pkts` alongside `up_pkt`.

---

## 3.35

**A penalty no longer goes to an address nobody is behind. And the "panel link
is not set up" message no longer lies.**

### What was happening

Home nodes were sending cards like this:

```
🚦 Limited · Node-1

identity unknown: the panel link is not set up on this node

📍 Address: 203.0.113.32
Reason: uploaded disproportionately much in 24h
```

Three in a row — and next to them, in the same minute, a fourth one with a full
name. So the panel was set up and working, and the message claimed otherwise.

### The cause: the ratio signal fired on addresses that had left

The upload ratio is counted **from daily counters**, and it had no "the person
is here now" condition. The kernel map is an LRU of 8192 entries: an address
that downloaded in the morning and left at noon sits there until midnight along
with its figures. In the evening the signal looked at them and penalised an
address nobody was behind. The panel does not know such an address — it is not
connected — hence "unknown".

The penalty expired after an hour, the daily counters had not changed in that
hour, the signal fired again. And so on until midnight: one offender, six
messages in an evening.

The signal now requires the address to be **uploading right now**. The floor is
deliberately low, 0.05 Mbit/s: a real seeder uploads continuously (about a
megabit while limited), one that left uploads nothing. As a bonus, the risk of
punishing the new holder of a dynamic address is gone.

### Four different causes were all reported as one

The owner fails to resolve for four reasons, and the message named the first:

| What is printed now | When |
| --- | --- |
| the panel link is not set up on this node | the panel is off on this node |
| the panel has not answered for N min | set up but unreachable |
| at the last poll (N min ago) this address was not among the connected ones | the person was not on the node |

I wrote that line, and it sent you looking for a fault in the wrong place. Sorry
about that.

### Reminders once every six hours

Telegram reports one address with the same reason at most once every six hours —
the same as the cooldown on sharing detection.

The limit is still applied **every time**, as before, and shows up in the limited
list and in the event log. Only Telegram goes quiet.

The reason is part of the key on purpose: the same address caught for something
else is news, and it arrives immediately.

### Also

* Both conditions are visible on the auto-limit screen: a line under the ratio
  signal and a line under the penalty. A setting that changes the outcome while
  staying invisible on screen is now the fourth case this month, and it has its
  own tests.
* `notify_due()` and `panel_owner_reason()` were pulled out into functions —
  their logic lived inside the watchdog loop and nothing tested it.
* Tests: 24 new ones. An address that left is not penalised, the liveness floor,
  the cooldown and its reset on a new reason, four cause codes and three
  distinct texts.

---

## 3.34

**Buying a game on Steam stopped counting as a torrent. Applies to home nodes.**

### The threshold caught the wrong people

An hourly threshold set as a share of the channel fires **after exactly thirty
minutes at full speed** — on any channel, because that is what a half means:

| limit | a full hour at that speed | threshold | fires after |
| --- | --- | --- | --- |
| 10 Mbit/s | 4.5 GB | 2.2 GB | 30 min |
| 50 Mbit/s | 22.5 GB | 11.2 GB | 30 min |
| 100 Mbit/s | 45 GB | 22.5 GB | 30 min |

A modern Steam game weighs about 120 GB, the heaviest reach 235. Someone who
honestly bought one got 1 Mbit/s after half an hour — and then fell into a
cycle: thirty minutes fast, an hour crawling, thirty minutes again. The game
took eight hours instead of three, and the node owner got five notifications
about an honest customer.

### Told apart by the packet, not by the volume

By volume a store download cannot be told from a torrent. By upload packet size
it can, and Shape was already measuring it:

| | Steam | Torrent |
| --- | --- | --- |
| Upload as a share of download | 1–3% | 20–200% |
| Upload packet size | 100–170 B, acknowledgements | 1200–1400 B, data |

New setting `volume_needs_upload`: hourly volume stops being a standalone reason
and also requires large upload packets.

The cost is known and accepted: a torrent with uploading turned off entirely
will not be caught within the hour — at the network layer it *is* an ordinary
download. The daily threshold catches it.

### The penalty for volume got softer

Volume is the one signal that fires on honest behaviour too. Cutting to
messenger-grade 1 Mbit/s for it means punishing someone for buying a game.

New setting `volume_penalty_mbps`: the penalty speed when **only** volume fired.
The home preset sets a third of the channel — 30 Mbit/s on a hundred, 15 on
fifty. The download does not die, the channel does not suffer. If torrent
signals fired alongside the volume, the usual penalty applies.

### The home preset

| | was | now |
| --- | --- | --- |
| Hourly volume | a reason on its own | only with upload packets |
| Daily threshold | 8 hourly ones | **16 hourly ones** |
| Penalty for volume alone | 1 Mbit/s | **a third of the channel** |

The daily figure went up because on fifty megabits eight hourly thresholds
(90 GB) simply were not enough for a single game.

**The mobile preset is unchanged.** There 3 GB/h is "what a person needs", not
"what fits in the channel", and game downloads are beside the point: on ten
megabits a game takes a day regardless. The preset now sets both options
explicitly to off, so switching over from the home preset leaves no leftovers.

### After updating

Both settings are off by default, so **the update on its own changes nothing**.
To make them take effect, go to Auto-limit → ⚡ Presets and apply the home preset
again.

### Also

* Both settings are visible on the auto-limit screen and editable by hand:
  entries `[13]` and `[14]`. A setting that changes the outcome while staying
  invisible on screen is now the third case of its kind, and it does not repeat
  silently any more.
* `guard --volume-needs-upload on|off` and `--volume-mbps` on the command line.
* Both READMEs: the "Fast node" section was rewritten — it still talked about
  the fourth preset out of the old five.
* Tests: a store download is not caught, a torrent at the same volume is, a
  feeble upload does not count as a torrent, penalty speed chosen by reasons.

---

## 3.33

**The offender card gained a name, and a tap stopped copying the address.**

### The wrong thing was copyable

```
🚦 Limited · Erebor
Limited user_100000005 · 203.0.113.20 → 1 Mbit/s for 12 h
```

Tapping such a message put the address in the clipboard — and there is nowhere
to search by an address: neither the panel nor the bot knows it. What needs
copying is exactly what goes into the panel's search box: the account login.

Now:

```
🚦 Limited · Erebor

👤 Ivan · @ivan_k
🆔 Telegram: 100000003
🔑 Panel login: user_100000003 · #101

📍 Address: 203.0.113.20
🐌 Speed reduced to 1 Mbit/s for 12 h
Reason: uploaded disproportionately much in 24h
```

A tap copies the panel login and the Telegram ID. The address is plain text.
The internal number sits next to the login and is not copyable either: it is
there for the eye, not for the clipboard.

### The name

The name line used to hold the login: `user_100000005`. The panel has no field
for a name — the name, if it exists at all, is written into the account
description by a bot, usually as a line like `Bot user: Ivan @ivan_k`.

Shape now parses that description into a name and a handle. The parse is
cautious: every bot has its own format, and if it fails the card simply keeps
the login, as before. A note like `Paid: until 3 October` is left alone and
shown in full.

The name became tappable: behind it sits a `tg://user?id=…` link that opens the
chat, and it works even for people without a username.

### Node report

The label in the report and in the address-list file now carries both the name
and the login: `Ivan · user_100000003 (100000003)`. It used to carry the login
alone. The login stays even when the name is known — the report is opened
precisely in order to find the person in the panel.

### Also

* `panel who` prints the login and the handle alongside the name.
* `subject_text` removed: `offender_card` builds the whole card, and a second
  function for the same job only drifted away from the first.
* Tests: description parsing (name, handle, bot label, Cyrillic note, length),
  login in `<code>`, address not in `<code>`, the profile link.

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
🆔 Telegram: 100000003
🔑 Panel ID: 741

📍 Address: 203.0.113.20
🐌 Speed cut to 1 Mbit/s for 1.0 h
Reason: uploaded disproportionately much in 24h
```

```
🔎 Looks like a shared subscription · Erebor

👤 Bashou
🆔 Telegram: 100000003
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

The ratio signal fired on a node: `203.0.113.30` limited, present in the
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
shaperctl.py panel who 203.0.113.20
```

```
✓ address 203.0.113.20 belongs to:
    Panel ID: 741
    Name: Bashou
    Telegram: 100000003
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
Node UUID : a1b0e1f2a3b4c5d
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
⚠ the node UUID must look like a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d
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
Limited 203.0.113.20 → 1 Mbit/s for 1.0 h
uploaded disproportionately much in 24h
```

The signal worked, but who is it?

### What was wrong

The offender's label was built from three fields: name, Telegram ID and panel
number. The first two were shown, the third was not — even though it is almost
always available: the number arrives with the connections list, before Shape
asks for the user's card at all.

So with names disabled, or without the `users:read` scope, we knew `#101` and
printed a bare address.

Now such a case reads `#101 · 203.0.113.20` — the number finds the person in the
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
203.0.113.30    857 MB ↓   756 MB ↑   = 88%
203.0.113.37    1015 MB ↓   489 MB ↑   = 48%   ← the 50% threshold missed it
203.0.113.28      1.1 GB ↓   500 MB ↑   = 45%   ← and this one
203.0.113.44    1.1 GB ↓   280 MB ↑   = 25%
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
  203.0.113.30      857.2 MB ↓   756.3 MB ↑    88%
  203.0.113.37      1014.7 MB ↓   489.1 MB ↑    48%
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
203.0.113.34           10.1     0.1    140     3.1  12.4 GB  12 min  ████████████ 101%
203.0.113.22              1.4     2.7   1310     1.7  22.8 GB       —  █▊··········  14%
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
203.0.113.18   downloaded 379 MB   uploaded 916 MB   ← 2.4× more up than down
203.0.113.20    downloaded 785 MB   uploaded 461 MB   ← 59%
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

`203.0.113.18` sat sixteenth among six thousand addresses — the list is sorted
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
Address     : https://admin.example.com
Node UUID   : a1b2c3d4
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
with 61 users it was text in the chat; on Node-3 with 76 it was a file. The
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

Finding a reseller is not enough — an internal `#101` tells you nothing about
who to write to. The message now carries everything needed to sort it out, and
access to the node can be cut off on the spot.

### The card

```
🔎 Looks like a shared subscription · FRONT-3

👤 Bashou
🆔 Telegram: 100000003
🔑 Panel ID: 741

Simultaneous addresses: 437 over the last 10 min
🚫 Access to the node cut off for 60 min, addresses: 412
Connections dropped: 437
```

The Telegram ID and the panel ID are on their own lines and wrapped in `<code>`:
in Telegram that copies with a single tap. You will be searching by them anyway,
and nobody should retype nine digits off a screen.

A Telegram handle like `@petr_s` is not stored by the panel — there is no such
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
`Olga (100000008)`.

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

Nikita (100000007) — 437  ⚠
    1.2.3.4
    …
Olga (100000008) — 2
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
203.0.113.14          37.9     4.6   1280    23.4     4 s  █████████▏··  76%
203.0.113.15           13.9     0.8    150     5.1       —  ███▍········  28%
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
