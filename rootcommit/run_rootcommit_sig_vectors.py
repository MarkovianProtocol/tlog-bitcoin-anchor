#!/usr/bin/env python3
"""
Run every rootcommit-sig/v1 vector through the verifier logic and assert the documented outcome.
Exit non-zero on any deviation.

Run on Neo:  ~/neo_env/bin/python3 run_rootcommit_sig_vectors.py
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from verify_rootcommit_sig import parse_anchor, ots_commits, sig_recovers, eqaddr, KEY_NAME
from build_rootcommit import build_preimage

DIR = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(DIR, "vectors_sig")


def evaluate(path):
    raw = open(path, "rb").read()
    origin, size, root = raw.split(b"\n\n", 1)[0].decode().splitlines()[:3]
    lines = [l for l in raw.split(b"\n\n", 1)[1].decode().splitlines() if l.startswith(f"— {KEY_NAME} ")]
    known = [k for k in (parse_anchor(l) for l in lines) if k]
    res = {"known_anchors": len(known)}
    if known:
        wallet, sig65, ots_bytes = known[0]
        preimage = build_preimage(origin, size, root, wallet)
        commitment = hashlib.sha256(preimage).hexdigest()
        binds, _ = ots_commits(preimage, ots_bytes)
        sig_ok = eqaddr(sig_recovers(commitment, sig65), wallet)
        res["binding"] = binds
        res["sig_ok"] = sig_ok
        res["reject"] = not (binds and sig_ok)
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
        print(f"  [{'PASS' if passed else 'FAIL'}] {v['file']:28} {v['desc']}")
        if not passed:
            print(f"         expected {exp}\n         got      {got}")
    print("\n", "ALL VECTORS PASS" if ok else "VECTOR FAILURES", sep="")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
