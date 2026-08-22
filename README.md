# BBIWY

**Big Brother Is Watching You** — a privacy browser where every network path
lives in its own sealed profile.

> **Status: pre-alpha.** There is nothing to install yet. What exists is a
> working launcher, a set of measurement harnesses, and a pile of results that
> say the core idea holds. See [Measurements](docs/MEASUREMENTS.md).

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

**Browser layer** — proxy settings are profile preferences, locked so nothing
in the profile can override them. Remote DNS on, localhost hijacking on,
PAC and extension-based proxying permanently forbidden.

**OS layer** — each profile runs inside its own Linux network namespace with an
nftables allow-list. Only the port that profile is supposed to reach is
reachable. Everything else is dropped **and counted**. If the transport daemon
dies, the profile does not silently fall back to the clear net; it simply
cannot reach anything.

The launcher uses **no privilege at runtime**. No setuid helper, no file
capabilities, no polkit action, no system service. It composes three audited
tools — `pasta`, `nft`, `setpriv` — in a fixed order, and drops every
capability before the browser starts. After that the browser cannot remove the
allow-list, cannot create interfaces, and cannot escape into a
root-mapped namespace — while Firefox's own content sandbox keeps working.

Root is needed exactly once, at install time, to place an AppArmor profile.
Firefox, Chrome and Brave all ship one on Ubuntu for the same reason.

## Layout

```
launcher/          the launcher (Rust, #![forbid(unsafe_code)], no dependencies)
tools/
  isolation-lab/   build a namespace, count what tries to escape, give a verdict
  fake-transport/  a logging SOCKS5 proxy — proves the browser hands over names,
                   not addresses, and that nothing bypasses the proxy
  leakcheck/       drive a real browser, read pref lock state, dump the
                   fingerprint surface
  probe/           deliberately leak, to prove the harness is not blind
  profiles/        profile generation and the fingerprint comparisons
docs/
```

## Building

```sh
cd launcher && cargo build --release
./target/release/bbiwy doctor     # does isolation actually hold on this machine?
./target/release/bbiwy list
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
