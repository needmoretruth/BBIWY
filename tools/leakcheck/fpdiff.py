#!/usr/bin/env python3
"""fpdiff — 프로필들의 지문 표면을 견준다.

설계 문서 §11이 요구한 것: "4개 프로필 결과 JSON diff. 프로필 간 차이 0이어야 함."
차이가 나면 그 항목이 곧 프로필을 구별하는 신호다.

판올림 사이 비교에도 같은 것을 쓴다. 그때는 차이가 0일 수 없고,
**어떤 항목이 달라졌는지**가 회귀 검토 목록이 된다.
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

# 값이 매번 달라지도록 만들어진 항목. 다르다는 사실 자체가 정상이므로 비교에서 뺀다.
# Mullvad Browser 는 privacy.resistFingerprinting.randomDataOnCanvasExtract 를 잠근 채 켠다.
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
        vals = [got[n].get(k, "«없음»") for n in names]
        if k in NOISY:
            noisy.append(k)
            continue
        (same if len(set(map(str, vals))) == 1 else diff).append((k, vals))

    print("프로필: %s" % " · ".join(names))
    print("같은 항목 %d개 · 다른 항목 %d개 · 무작위 항목 %d개(비교 제외: %s)\n"
          % (len(same), len(diff), len(noisy), ", ".join(noisy) or "없음"))
    if not diff:
        print("프로필 간 지문 차이 없음.")
        return 0
    print("=== 프로필을 구별하는 항목 ===")
    for k, vals in diff:
        print("\n%s" % k)
        for n, v in zip(names, vals):
            print("  %-8s %s" % (n, str(v)[:110]))
    return 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
