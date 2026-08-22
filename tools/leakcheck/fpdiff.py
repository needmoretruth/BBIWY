#!/usr/bin/env python3
"""fpdiff — compare the fingerprint surface across profiles.

The requirement is that profiles differ by nothing. Any item that does differ
is, by definition, a signal that tells them apart.

The same tool compares across browser versions. There the difference cannot be
zero, and *which* items moved becomes the regression checklist.
"""
import json, sys

def flat(d, pre=""):
    out = {}
    for k, v in (d or {}).items():
        key = pre + k
        if isinstance(v, dict):
            out.update(flat(v, key + "."))
        elif isinstance(v, list):
            out[key] = json.dumps(v, ensure_ascii=False)
        else:
            out[key] = v
    return out

# Items engineered to differ on every read. Differing is correct behaviour for
# them, so they are excluded: the base ships canvas randomisation locked on.
NOISY = {"canvas"}

def main(paths):
    got = {}
    for p in paths:
        with open(p) as f:
            d = json.load(f)
        name = p.split("/")[-1].replace("fp-", "").replace(".json", "")
        got[name] = flat(d.get("fingerprint"))

    names = list(got)
    keys = sorted(set().union(*[set(v) for v in got.values()]))
    same, diff, noisy = [], [], []
    for k in keys:
        vals = [got[n].get(k, "<absent>") for n in names]
        if k in NOISY:
            noisy.append(k)
            continue
        (same if len(set(map(str, vals))) == 1 else diff).append((k, vals))

    print("profiles: %s" % " · ".join(names))
    print("%d identical · %d differing · %d randomised (excluded: %s)\n"
          % (len(same), len(diff), len(noisy), ", ".join(noisy) or "none"))
    if not diff:
        print("no fingerprint difference between profiles.")
        return 0
    print("=== items that tell the profiles apart ===")
    for k, vals in diff:
        print("\n%s" % k)
        for n, v in zip(names, vals):
            print("  %-8s %s" % (n, str(v)[:110]))
    return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
