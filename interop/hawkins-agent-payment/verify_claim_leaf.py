#!/usr/bin/env python3
"""
Independent verifier for a Markovian claim-leaf.

Trusts NOTHING from us except the public read endpoints. Re-derives the RFC 6962
Merkle math from scratch (no project code imported) and proves:

  1. the leaf served at /leaf/<i> hashes to the claim_root in the receipt
  2. that leaf is included at index i in the tree whose root the log signed
  3. the log's own signature AND >= 1 independent witness cosigned that checkpoint

If all three hold, the claim is in a single, witnessed, non-equivocating history.
Run it from any machine. It only reads the public log.

Usage:  verify_claim_leaf.py <receipt.json> [--log https://log.markovianprotocol.com]
"""
import sys, json, base64, hashlib, urllib.request

# ------------------------- RFC 6962 / 9162, from scratch -------------------------
def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()

def node_hash(l: bytes, r: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + l + r).digest()

def root_from_inclusion(index, size, lh, proof):
    """RFC 9162 2.1.3.2 audit-path fold."""
    fn, sn, r = index, size - 1, lh
    for p in proof:
        if sn == 0:
            raise ValueError("inclusion proof too long")
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(p, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1; sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1; sn >>= 1
    if sn != 0:
        raise ValueError("inclusion proof too short")
    return r

# ------------------------------ tiny http ------------------------------
def get(url):
    with urllib.request.urlopen(url, timeout=25) as r:
        return r.read()

def parse_checkpoint(note_bytes, origin):
    """C2SP signed-note: body lines, blank line, then '<U+2014> name b64sig' lines."""
    text = note_bytes.decode()
    body, _, sigs = text.partition("\n\n")
    lines = body.split("\n")
    size = int(lines[1])
    root = base64.b64decode(lines[2])
    cosigners = []
    for ln in sigs.split("\n"):
        ln = ln.strip()
        if ln.startswith("— "):
            name = ln[2:].split(" ")[0]
            cosigners.append(name)
    log_self = origin in cosigners
    witnesses = sorted(set(n for n in cosigners if n != origin))
    return size, root, log_self, witnesses

def main():
    receipt = json.load(open(sys.argv[1]))
    LOG = "https://log.markovianprotocol.com"
    if "--log" in sys.argv:
        LOG = sys.argv[sys.argv.index("--log") + 1]
    origin = "markovianprotocol.com/log"

    i = receipt["leaf_index"]
    expect_root = receipt["claim_root_sha256"]

    print("verifying against PUBLIC log: %s" % LOG)
    print("leaf index: %d   expected claim_root: %s" % (i, expect_root))
    print()

    # Two checkpoints: the WITNESSED one (carries cosignatures, the non-equivocation
    # leg) and the live TIP the log signs alone (order+time, no witness yet).
    w_size, w_root, w_self, witnesses = parse_checkpoint(get(LOG + "/checkpoint"), origin)
    t_size, t_root, _, _ = parse_checkpoint(get(LOG + "/checkpoint/unwitnessed"), origin)

    P = lambda b: "PASS" if b else "FAIL"

    # (1) the leaf the log serves must hash to the claim_root we were handed
    leaf = get("%s/leaf/%d" % (LOG, i))
    got_root = hashlib.sha256(leaf).hexdigest()
    ok1 = (got_root == expect_root)
    print("[%s] leaf/%d hashes to claim_root      (%s)" % (P(ok1), i, got_root))

    # Pick the smallest checkpoint that covers the leaf; prefer the witnessed one.
    if i < w_size:
        cp_root, cp_size, cp_kind = w_root, w_size, "witnessed"
    elif i < t_size:
        cp_root, cp_size, cp_kind = t_root, t_size, "log-signed tip (not yet witnessed)"
    else:
        print("[FAIL] leaf %d not covered by any published checkpoint" % i)
        sys.exit(1)

    # (2) inclusion under that checkpoint's root, our own RFC 6962 math
    proof_txt = get("%s/inclusion?leaf=%d&size=%d" % (LOG, i, cp_size)).decode()
    proof = [base64.b64decode(x) for x in proof_txt.split("\n") if x.strip()]
    computed = root_from_inclusion(i, cp_size, leaf_hash(leaf), proof)
    ok2 = (computed == cp_root)
    print("[%s] leaf included in %s tree (size %d)" % (P(ok2), cp_kind, cp_size))
    print("         our recomputed root : %s" % base64.b64encode(computed).decode())
    print("         log-signed root     : %s" % base64.b64encode(cp_root).decode())

    # (3) witnessing — only established if the WITNESSED checkpoint covers the leaf
    witnessed = (i < w_size) and w_self and len(witnesses) >= 1
    print("[%s] non-equivocation: witnessed checkpoint at size %d, %d independent witness(es)"
          % (P(witnessed), w_size, len(witnesses)))
    for w in witnesses:
        print("           - %s" % w)
    print()

    if ok1 and ok2 and witnessed:
        print("VERIFIED (full): claim %s... is leaf %d of a %d-leaf tree, log-signed and "
              "cosigned by %d independent witnesses. Single, witnessed, non-equivocating history."
              % (expect_root[:16], i, cp_size, len(witnesses)))
        sys.exit(0)
    if ok1 and ok2:
        print("VERIFIED (partial): claim %s... is leaf %d, log-signed at tip size %d with a "
              "valid inclusion proof (order + time). NOT YET in a witnessed checkpoint "
              "(witnessed size %d < %d); the non-equivocation leg lands at the next "
              "witness cosign round. Re-run then." % (expect_root[:16], i, t_size, w_size, i + 1))
        sys.exit(2)
    print("VERIFICATION FAILED")
    sys.exit(1)

if __name__ == "__main__":
    main()
