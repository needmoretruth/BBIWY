# Measurements

Everything below was measured on real software, not reasoned about. Where a
result contradicts something this project previously assumed, the contradiction
is recorded rather than quietly dropped.

Test bed: Ubuntu 24.04.4, kernel 6.8.0, nftables 1.0.9, passt
`0.0~git20240220`, Mullvad Browser 15.0.20 (Firefox ESR 140.14.0).

Harnesses live in [`../tools`](../tools). Every claim here has one.

---

## 1. Profile-locked transport does not leak

A real browser, in a network namespace, with an nftables allow-list that
permits only the transport port and counts everything else.

| | |
|---|---|
| 75 seconds of real use, including startup and filter-list updates | **0 violating packets / 445 allowed** |
| Same run with the transport daemon killed | **0 violating packets** |

No silent fallback to the clear net. When the route is gone, the profile
reaches nothing.

The harness is not blind: a deliberate leak generator
([`tools/probe`](../tools/probe)) produces counted violations on demand, and a
no-proxy control leaked 6 DNS packets.

## 2. Three starting assumptions were wrong

| Assumption | Measured |
|---|---|
| `policies.json` is disabled in this build | **It works.** All prefs locked. `--disable-system-policies` only removes Windows GPO, macOS plists and `/etc/firefox` |
| uBlock Origin's `browser.dns.resolve` bypasses SOCKS | **It does not.** With a proxy configured, `nsIDNSService` refuses with `NS_ERROR_UNKNOWN_PROXY_HOST`. The bug behind this belief was fixed in Firefox 80 (2020) |
| WebRTC must be disabled | Leaving it on leaked nothing. **Turning it off was the only change that made profiles distinguishable** |

## 3. Two real defects, found and fixed

| Pref | Was | Measured |
|---|---|---|
| `network.proxy.allow_hijacking_localhost` | documented as `false` | `false` → `127.0.0.1:65001` reaches the proxy log. Must be **`true`** |
| `network.proxy.socks5_remote_dns` | assumed `socks_remote_dns` covered it | Split in Firefox 128. `false` → **6 DNS packets escaped**. Both must be locked |

## 4. Isolation needs no privilege at runtime

`pasta` attaches an unprivileged namespace to the network without touching the
host namespace, so the `CAP_NET_ADMIN` boundary is never crossed. nftables
works fully inside, counters included.

With only port 443 permitted, from an unprivileged process:

| | |
|---|---|
| TCP 443 | connects |
| TCP 80 | blocked (timeout) |
| UDP 53 | blocked (`EPERM`, immediately) |
| counters | 4 allowed / **11 blocked** |

No setuid helper, no file capabilities, no polkit, no system service. That
matters: the setuid helper is where tools in this category have historically
been broken.

## 5. But install-time root is required — for one file

On Ubuntu 24.04+, `kernel.apparmor_restrict_unprivileged_userns` defaults to
`1` and the namespace cannot be created at all.

A six-line AppArmor profile whose only rule is `userns,` restores it
completely:

| State | Result |
|---|---|
| no profile | `clone: Operation not permitted`, exit 1 |
| **profile loaded** | **namespace entered**, exit 0 |
| profile removed again | fails again |

Firefox, Chrome, Brave, Discord, VS Code, Flatpak and Podman all ship exactly
such a profile on this system. This is normal packaging, not a special ask.

> Note: the Debian/Ubuntu `passt` package ships an AppArmor profile covering
> `/usr/bin/passt{,.avx2}` only — not `pasta`, and with no `userns` rule. The
> distribution binary therefore does not work in pasta mode under the current
> default. Ship your own.

## 6. The isolation is not expensive

400 MB over HTTP, four runs each:

| | Throughput |
|---|---|
| no namespace (loopback baseline) | 685 – 715 MB/s |
| pasta namespace | 394 – 513 MB/s |
| pasta namespace + nftables allow-list | 435 – 517 MB/s |

pasta costs about a third of loopback throughput — roughly 3.5–4 Gbit/s, far
above any real connection. **The allow-list itself has no measurable cost.**

## 7. Dropping *all* privilege breaks the browser. Dropping two does not.

Before `exec`, the launcher removes capabilities so that nothing downstream can
undo the allow-list. The obvious implementation — drop everything — is wrong,
and an isolated simulation of it said otherwise.

A hand-written probe that created a user namespace and mapped its own uid, the
way Firefox's content sandbox does, succeeded under a fully emptied bounding
set. On that basis this document previously claimed the drop was safe.

**Running the real browser disproved it.** Every content process died:

```
Sandbox: writing /proc/self/uid_map: EPERM
... process 110 exited on signal 11
```

Measured properly, all three cases in one harness — does the allow-list survive
tampering, and does the browser actually run:

| capability drop | `nft flush ruleset` | browser |
|---|---|---|
| none | **succeeds — design defeated** | runs |
| `--bounding-set=-all` | denied | **every content process dies** |
| **`--bounding-set=-net_admin,-net_raw`** | **denied** | **runs normally** |

So the launcher drops exactly `CAP_NET_ADMIN` and `CAP_NET_RAW`, plus
`no_new_privs`. Removing them from the *bounding* set means they can never be
regained, by the browser or anything it spawns, while everything Firefox needs
for its own sandbox stays intact.

With that drop in place: `nft flush ruleset` denied, `ip link add` denied,
escape into a root-mapped namespace denied, and the allow-list still enforcing —
443 passes, 80 blocked.

> Three measurement traps, all of which produced wrong answers here before being
> caught. After the capability drop, `nft list ruleset` is *also* denied, so
> checking whether rules survived by listing them reports a false failure; check
> by behaviour instead. `os._exit()` does not flush stdout, so output from a
> forked child vanishes. And `timeout` cannot invoke a shell function, which
> silently turned an entire comparison into "command not found" for every case.

## 8. One installation can lock a pref differently per profile

The five-profile design needs per-profile locking from a single install.
Autoconfig is installation-wide, so this was the open question.

| | sandbox on | sandbox off |
|---|---|---|
| autoconfig runs | yes | yes |
| `getenv()` available | yes | yes |
| profile directory readable | no | **yes** |
| `privacy.resistFingerprinting` per profile | **locked true / unlocked false** | same |

Branch on the **running profile's directory**, not on an environment variable —
a user can set the variable and defeat the lock. The directory is authoritative.
This works on the shipped binary; no custom build required.

## 9. All five profiles can share one fingerprint

Five profiles, launched separately, fingerprint surface compared.

**Privacy profiles: 0 differences.** They are indistinguishable.

Then, what each "daily driver" relaxation actually costs:

| Relaxation | Fingerprint cost |
|---|---|
| logins, history, autofill persist; no clear-on-shutdown | **0 — free** |
| letterboxing off | **window size leaks exactly** |
| RFP off | real CPU count, real GPU, real screen |

Letterboxing is the **only** relaxation that breaks fingerprint uniformity:

| Window asked for | letterboxing **on** | letterboxing **off** |
|---|---|---|
| 1123 × 777 | `1000 × 600` | **`1123 × 600`** |
| 1000 × 700 | `1000 × 450` | **`1000 × 494`** |
| 1280 × 800 | `1200 × 600` | **`1280 × 623`** |

On, values land on a shared grid. Off, the exact window size goes out — and
under RFP `screen` follows the window, so that leaks too.

> An earlier version of this test reported "no difference" for letterboxing.
> That test never resized the window, which is the only situation where
> letterboxing does anything. It had no discriminating power and the result was
> meaningless.

## 10. X11 and Wayland are nearly indistinguishable

Tor Browser and Mullvad Browser ship a patch forcing X11. The stated reason is
not a known leak — it is *"we don't really have any fingerprinting insight into
the difference between wayland and non-wayland."* That is an absence of
measurement.

Same profile, same locks, headless compositor versus Xvfb:

**3 of 38 items differ, and all three are the same thing — window geometry.**

The other 35 are identical: CPU count, GPU strings, device pixel ratio,
timezone, language, font metrics, audio sample rate, plugins, MIME types, user
agent, colour gamut, **refresh-rate class**, pointer, hover, reduced-motion.

Refresh rate matters: that was the one demonstrated Wayland leak
(tor-browser#43236), and the shipped build already carries
`widget.wayland.vsync.enabled = false`.

Both geometry values land on the letterboxing grid, so the defence works
identically on both. The gap is window size, which is ours to pin.

> Limits: a headless compositor is not a real desktop. Fractional scaling,
> HiDPI and a real high-refresh monitor are untested. 38 items is not the whole
> fingerprint surface.

## 11. The launcher's own pasta command line was fail-open

pasta's forwarding options default to `auto`, and the launcher had named only
half of them. Measured with the real pasta at three versions — 2024_02_20 (the
Ubuntu 24.04 build), 2024_09_06 and 2026_09_25 — a listener on the host's
127.0.0.1 at 5432, 8080 and 9150, and a client inside the namespace:

| command line | inside the namespace |
|---|---|
| direct, before: `--tcp-ports none --udp-ports none` | **every** host loopback port reachable — 5432, 8080, 9150 — through `oifname "lo" accept`, uncounted |
| proxied, before: `--tcp-ports 9150` | pasta **exits**: `Failed to bind port 9150 (Address already in use)`. `-t` binds the *host* port, which tor already holds |
| now: `-t none -u none -T <relay> -U none --no-map-gw` | only the relay (9150 reaches the host's 9150). 5432 and 8080: refused |

The relay is now matched and counted before the loopback rule; a direct profile
gets nothing from the host at all.

## 12. `setpriv` can skip the capability drop without a word

Where `no_new_privs` is already set before the launcher runs, pasta's child
keeps three capabilities, and `CAP_SETPCAP` is not one of them. setpriv then
runs its command with the bounding set untouched:

| | CapBnd after setpriv | `nft flush ruleset` |
|---|---|---|
| `unshare -Urn` (ordinary) | NET_ADMIN, NET_RAW gone | denied |
| pasta, `no_new_privs` preset | **unchanged** | **succeeds** |

So the process that becomes the browser now reads its own capability sets first
(`__sealed`), and refuses to start unless NET_ADMIN and NET_RAW are absent from
every set and `no_new_privs` is on. `doctor` reports the cause.

## 13. The installed locks, on the shipped browser

Mullvad Browser 15.0.23, installed by `bbiwy install` (signature checked against
the pinned key; a tarball with one byte changed is refused with `BADSIG`), read
back from chrome scope in each profile directory:

- every profile gets its route's proxy prefs **locked**; tor and session SOCKS5
  with both remote-DNS prefs, i2p HTTP; direct profiles `trr.mode` 3, locked
- the address bar reads `⬤ DAILY`, `◯ HARDENED`, `◎ TOR`, `◆ I2P`, `⬡ SESSION`
  with the edge each route specifies — but only when started by the launcher;
  the same profile opened by hand is locked the same and claims no route
- a directory that is not one of BBIWY's gets the strict set and no route
- **0 of 30 fingerprint items differ** across all seven windows

`daily`, run directly under `strace`: connections to 194.242.2.2:443 (the DoH
resolver, by address) and the site. **Nothing to port 53.**

The inner half of `bbiwy run`, in a real user+network namespace, with the
allow-list loaded and the capabilities dropped: tor and i2p fetched a page
through a logging relay, **by name** (`addrtype: domain`), with **0 blocked
packets**, and `nft flush ruleset` from after the drop was denied.

> Limits: this sandbox has no `/dev/net/tun` and no AppArmor. pasta's
> forwarding was measured with the tun device faked, so pasta's own network
> setup (`--config-net`) and `sudo bbiwy apparmor` have not run here. One run on
> Ubuntu 24.04 — `bbiwy install`, `sudo bbiwy apparmor`, `bbiwy doctor`,
> `bbiwy run tor` with a real tor — is what remains before calling it verified.

---

## What has not been measured

- Building from source. Nothing here was produced by our own build yet.
- Live web browsing over each transport.
- Wayland on a real GNOME or KDE session.
- IPv6 (disabled on the test machine).
- Font enumeration deltas, media capabilities, WebGL extension lists.
