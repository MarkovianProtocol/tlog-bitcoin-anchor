#!/usr/bin/env python3
"""
Run every conformance vector through the verifier logic and check it produces the documented
outcome. This is the executable half of the spec: an independent verifier in any language can be
proven correct by reproducing these results. Exit non-zero if any vector deviates.

Run on Neo:  ~/neo_env/bin/python3 run_vectors.py
"""
import json, os, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from verify_sunlight_anchor import parse_anchor, ots_check, KEY_NAME, IDENTIFIER

DIR = os.path.expanduser("~/markovian/sunlight_anchor")
VDIR = os.path.join(DIR, "vectors")


def evaluate(path):
    raw = open(path, "rb").read()
    body = raw.split(b"\n\n", 1)[0] + b"\n"
    lines = [l for l in raw.split(b"\n\n", 1)[1].decode().splitlines() if l.startswith(f"— {KEY_NAME} ")]
    known, ignored = [], 0
    for l in lines:
        p = parse_anchor(l)
        if p and p[0] == IDENTIFIER:
            known.append(p[1])
        else:
            ignored += 1
    res = {"known_anchors": len(known), "ignored": ignored}
    if known:
        binds, when = ots_check(body, known[0])
        res["binding"] = binds
        res["reject"] = not binds                       # a known anchor whose binding fails -> reject
    else:
        res["reject"] = False                           # nothing known to verify -> ignore, don't reject
    return res


def main():
    manifest = json.load(open(os.path.join(VDIR, "manifest.json")))
    ok = True
    for v in manifest["vectors"]:
        got = evaluate(os.path.join(VDIR, v["file"]))
        exp = v["expect"]
        passed = all(got.get(k) == val for k, val in exp.items() if k in got)
        ok = ok and passed
        mark = "PASS" if passed else "FAIL"
        print(f"  [{mark}] {v['file']:22} {v['desc']}")
        if not passed:
            print(f"         expected {exp}\n         got      {got}")
    print("\n", "ALL VECTORS PASS" if ok else "VECTOR FAILURES", sep="")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
