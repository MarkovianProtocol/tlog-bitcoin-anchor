#!/usr/bin/env python3
"""
Run every rootcommit/v1 vector through the verifier logic and assert the documented outcome.
Exit non-zero on any deviation. This is the executable half of the spec.

Run on Neo:  ~/neo_env/bin/python3 run_rootcommit_vectors.py
"""
import json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_rootcommit import parse_anchor, ots_commits, build_preimage, KEY_NAME

DIR = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(DIR, "vectors")


def evaluate(path):
    raw = open(path, "rb").read()
    origin, size, root = raw.split(b"\n\n", 1)[0].decode().splitlines()[:3]
    lines = [l for l in raw.split(b"\n\n", 1)[1].decode().splitlines() if l.startswith(f"— {KEY_NAME} ")]
    known = [k for k in (parse_anchor(l) for l in lines) if k]
    res = {"known_anchors": len(known)}
    if known:
        _, wallet, ots_bytes = known[0]
        binds, _ = ots_commits(build_preimage(origin, size, root, wallet), ots_bytes)
        res["binding"] = binds
        res["reject"] = not binds
    else:
        res["reject"] = False
    return res


def main():
    manifest = json.load(open(os.path.join(VDIR, "manifest.json")))
    ok = True
    for v in manifest["vectors"]:
        got = evaluate(os.path.join(VDIR, v["file"]))
        exp = v["expect"]
        passed = all(got.get(k) == val for k, val in exp.items() if k in got)
        ok = ok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {v['file']:32} {v['desc']}")
        if not passed:
            print(f"         expected {exp}\n         got      {got}")
    print("\n", "ALL VECTORS PASS" if ok else "VECTOR FAILURES", sep="")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
