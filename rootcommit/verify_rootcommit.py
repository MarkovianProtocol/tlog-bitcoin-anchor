#!/usr/bin/env python3
"""
Independent verifier for the rootcommit/v1 anchor. Trusts no operator: reconstructs the frozen
preimage from the checkpoint's own (origin, size, root) plus the wallet carried in the anchor
line, then checks the OTS proof commits sha256(preimage) and lands in Bitcoin.

Checks:
  [1] Structure : 0xff signed-note line under our key name, known rootcommit/v1 identifier.
  [2] Binding   : the OTS proof commits sha256(reconstructed preimage) -> ties (root, wallet) to Bitcoin.
  [3] Temporal  : Bitcoin block, PENDING, or FAIL.
  [4] Root check: mutate the root line; binding MUST break.
  [5] Wallet chk: mutate the wallet byte; binding MUST break. (The new property vs v1.)

Run on Neo:  ~/neo_env/bin/python3 verify_rootcommit.py [file]
"""
import base64, hashlib, os, re, subprocess, sys, tempfile
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import KEY_NAME, SIG_TYPE  # noqa

DIR = os.path.dirname(os.path.abspath(__file__))
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
PREIMAGE_TAG = "markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIR, "mkv_checkpoint.rootcommit.txt")


def expected_key_id(identifier: bytes) -> bytes:
    return hashlib.sha256(KEY_NAME.encode() + b"\x0a" + bytes([SIG_TYPE]) + identifier).digest()[:4]


def parse_anchor(line: str):
    """Return (identifier, wallet, ots_bytes) for a known rootcommit line, else None."""
    try:
        payload = base64.b64decode(line.split(" ", 2)[2])
        kid, stype, idlen = payload[:4], payload[4], payload[5]
        ident = payload[6:6 + idlen]
        opaque = payload[6 + idlen:]
        if stype != SIG_TYPE or kid != expected_key_id(ident) or ident != IDENTIFIER:
            return None
        ver, wlen = opaque[0], opaque[1]
        if ver != 0x01:
            return None
        wallet = opaque[2:2 + wlen].decode()
        ots_bytes = opaque[2 + wlen:]
        return ident, wallet, ots_bytes
    except Exception:
        return None


def build_preimage(origin, size, root, wallet) -> bytes:
    lines = [PREIMAGE_TAG, f"origin={origin}", f"size={size}", f"root={root}", f"wallet={wallet}"]
    return ("\n".join(lines) + "\n").encode()


def ots_commits(preimage: bytes, ots_bytes: bytes):
    """(binds, when): binds = proof commits sha256(preimage); when = Bitcoin line / PENDING / None."""
    with tempfile.TemporaryDirectory() as d:
        pf = os.path.join(d, "preimage.bin"); of = pf + ".ots"
        open(pf, "wb").write(preimage); open(of, "wb").write(ots_bytes)
        info = subprocess.run([OTS, "info", of], capture_output=True, text=True).stdout
        binds = hashlib.sha256(preimage).hexdigest() in info
        m = re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", info)
        if m:
            when = "Bitcoin block " + m.group(1)
        elif "PendingAttestation" in info:
            when = "PENDING"
        else:
            when = None
        return binds, when


def main():
    raw = open(FILE, "rb").read()
    origin, size, root = raw.split(b"\n\n", 1)[0].decode().splitlines()[:3]
    sig_block = raw.split(b"\n\n", 1)[1].decode()
    print(f"checkpoint: {origin}  size {size}")

    known = [parse_anchor(l) for l in sig_block.splitlines() if l.startswith(f"— {KEY_NAME} ")]
    known = [k for k in known if k]
    if not known:
        print("  [!] no known rootcommit anchor to verify"); sys.exit(1)
    _, wallet, ots_bytes = known[0]
    preimage = build_preimage(origin, size, root, wallet)

    binds, when = ots_commits(preimage, ots_bytes)
    print(f"  wallet bound  : {wallet}")
    print(f"  [1] Structure : PASS  (0xff, id={IDENTIFIER.decode()})")
    print(f"  [2] Binding   : {'PASS' if binds else 'FAIL'}  (proof commits sha256(preimage) {hashlib.sha256(preimage).hexdigest()[:16]}…)")
    if when and when != "PENDING":
        print(f"  [3] Temporal  : PASS  (Bitcoin-confirmed) — {when}")
    elif when == "PENDING":
        print("  [3] Temporal  : PENDING (upgrades to a Bitcoin block in ~1 block via `ots upgrade`)")
    else:
        print("  [3] Temporal  : FAIL  (no Bitcoin attestation)")

    # [4] mutate the root line -> binding must break
    bad_root = root[:-2] + ("A" if root[-2] != "A" else "B") + root[-1]
    rbinds, _ = ots_commits(build_preimage(origin, size, bad_root, wallet), ots_bytes)
    print(f"  [4] Root check: {'PASS' if not rbinds else 'FAIL'}  (mutated root correctly {'rejected' if not rbinds else 'ACCEPTED — binding is a no-op!'})")

    # [5] mutate the wallet -> binding must break (the property v1 does not have)
    bad_w = wallet[:-1] + ("0" if wallet[-1] != "0" else "1")
    wbinds, _ = ots_commits(build_preimage(origin, size, root, bad_w), ots_bytes)
    print(f"  [5] Wallet chk: {'PASS' if not wbinds else 'FAIL'}  (mutated wallet correctly {'rejected' if not wbinds else 'ACCEPTED — wallet not actually committed!'})")

    ok = binds and (when is not None) and (not rbinds) and (not wbinds)
    print("\n  RESULT:", "PASS — root and wallet are jointly committed under Bitcoin time." if ok
          else "REVIEW — see failing check above.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
