# BBIWY

**Big Brother Is Watching You** — a privacy browser where every network path
lives in its own sealed profile.

> **Status: alpha (0.1.0-alpha.1).** `daily`, `hardened`, `tor` and `i2p` install and
> run. `session` waits for an upstream SOCKS listener. Linux x86_64 only.
> See [Measurements](docs/MEASUREMENTS.md) for what has been verified, and on what.

한국어 설명은 [README.ko.md](README.ko.md) 를 보십시오.

---

## What it is

One browser, several ways out — direct, Tor, I2P, Session — and each one is
locked to a physically separate profile so state and traffic never mix.

| Profile | Route | Notes |
|---|---|---|
| `daily` | direct | logins persist, sites don't break |
| `hardened` | direct | nothing persists |
| `tor` | SOCKS5 → local tor | `.onion` |
| `i2p` | HTTP proxy → local I2P router | `.i2p` |
| `session` | Session Router | `.sesh` internal services only |

**All five share one fingerprint.** The difference between `daily` and
`hardened` is *strictness* — whether logins survive, how much breakage you
tolerate — not identity. Measurement showed that keeping logins, history and
autofill costs exactly **zero** fingerprint difference, so there is no reason
to split the anonymity set.

## How the isolation works

Two layers, and the second one does not trust the first.

**Browser layer** — one lock file (`bbiwy.cfg`, Gecko autoconfig) installed
next to the browser picks each profile's locks by the *name of its profile
directory*, never by an environment variable. Proxy, remote DNS, DNS over HTTPS
bootstrapped by address, HTTP/3 off, no speculative connections. A window whose
locks did not all load is marked **UNLOCKED** in red, and claims no route.

**OS layer** — each profile runs inside its own Linux network namespace with an
nftables allow-list. Only the port that profile is supposed to reach is
reachable. Everything else is dropped **and counted**. If the transport daemon
dies, the profile does not silently fall back to the clear net; it simply
cannot reach anything.

The launcher uses **no privilege at runtime**. No setuid helper, no file
capabilities, no polkit action, no system service. It composes three audited
tools — `pasta`, `nft`, `setpriv` — in a fixed order, and removes the two
capabilities that could undo the allow-list before the browser starts — then
checks that they are really gone. After that the browser cannot remove the
allow-list, cannot create interfaces, and cannot escape into a
root-mapped namespace — while Firefox's own content sandbox keeps working.

Root is needed exactly once, at install time, to place an AppArmor profile.
Firefox, Chrome and Brave all ship one on Ubuntu for the same reason.

## Install and use

Needs `pasta` (package `passt`), `nftables`, `util-linux`, and for installing
`curl gpg tar xz zip unzip`. On Debian/Ubuntu:
`sudo apt install passt nftables curl gpg xz-utils zip unzip`.

A static binary for Linux x86_64 is attached to each
[release](https://github.com/needmoretruth/BBIWY/releases), built from its tag
by `.github/workflows/release.yml`. Or build it:

```sh
cd launcher && cargo build --release
./target/release/bbiwy install      # latest Mullvad Browser, signature checked, locked down
sudo ~/.local/bin/bbiwy apparmor    # Ubuntu 23.10+ only, once — install tells you if needed
bbiwy doctor                        # does isolation actually hold on this machine?
bbiwy run daily                     # or hardened · tor · i2p, or from the menu
```

| Command | |
|---|---|
| `bbiwy install [--tor-port 9050] [--i2p-port N]` | download, verify against the pinned Tor Browser Developers key, lock, theme, menu entries. `--from <tar.xz>` or `--browser <dir>` instead of downloading |
| `bbiwy run <profile> [url…]` | start a profile sealed in its namespace. Refuses if the route's daemon is not listening, or the capability drop did not take |
| `bbiwy status` | running profiles, and what each allow-list let through and dropped |
| `bbiwy explain <profile>` | the exact pasta command, nft rules and preference locks that profile gets |
| `bbiwy list` · `bbiwy doctor` · `bbiwy uninstall [--purge]` | |

The tor route expects a SOCKS port on `127.0.0.1:9150` (a system tor uses
9050: `bbiwy install --tor-port 9050`); the i2p route, i2pd or Java I2P's HTTP
proxy on `127.0.0.1:4444`. When the browser updates itself it replaces the
theme; `bbiwy run` puts it back before the next window opens.

## Layout

```
launcher/          the launcher (Rust, #![forbid(unsafe_code)], no dependencies)
tools/
  isolation-lab/   build a namespace, count what tries to escape, give a verdict
  fake-transport/  a logging SOCKS5 or HTTP proxy — proves the browser hands over names,
                   not addresses, and that nothing bypasses the proxy
  leakcheck/       drive a real browser, read pref lock state, dump the
                   fingerprint surface
  probe/           deliberately leak, to prove the harness is not blind
  profiles/        profile generation and the fingerprint comparisons
docs/
```

`doctor` refuses to pass if isolation cannot be established. That is
deliberate: a privacy tool that quietly runs unprotected is worse than one that
refuses to start.

## Base

Built on [Mullvad Browser](https://mullvad.net/en/browser), which is built on
Tor Browser, which is built on Firefox ESR. Tor is one of four paths here, so a
neutral base is the right one.

BBIWY is not affiliated with Mullvad, the Tor Project, or Mozilla.

## Licence

[MPL-2.0](LICENSE).
