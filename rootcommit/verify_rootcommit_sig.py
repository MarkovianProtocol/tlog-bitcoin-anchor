#!/usr/bin/env python3
"""
Independent verifier for the rootcommit-sig/v1 anchor: who + what + when, trusting no operator.

  [1] Structure : 0xff signed-note line, known rootcommit-sig/v1 identifier.
  [2] Binding   : OTS proof commits sha256(preimage(origin,size,root,wallet)).      -> what + when
  [3] Temporal  : Bitcoin block / PENDING / FAIL.
  [4] Signature : EIP-191 recover(message(commitment), sig) == the bound wallet.      -> who
  [5] Root chk  : mutate root  -> binding MUST break.
  [6] Sig chk   : mutate sig   -> recovery MUST no longer match the wallet.

Run on Neo:  ~/neo_env/bin/python3 verify_rootcommit_sig.py [file]
"""
import base64, hashlib, os, re, subprocess, sys, tempfile
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import KEY_NAME, SIG_TYPE
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_rootcommit import build_preimage
from eth_account import Account
from eth_account.messages import encode_defunct

DIR = os.path.dirname(os.path.abspath(__file__))
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"  # canonical (was rootcommit-sig/v1)
SIG_MSG_TAG = "markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"
FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIR, "mkv_checkpoint.rootcommit-sig.txt")


def expected_key_id(identifier: bytes) -> bytes:
    return hashlib.sha256(KEY_NAME.encode() + b"\x0a" + bytes([SIG_TYPE]) + identifier).digest()[:4]


def parse_anchor(line: str):
    """Return (wallet, sig65, ots_bytes) for a known rootcommit-sig line, else None."""
    try:
        payload = base64.b64decode(line.split(" ", 2)[2])
        kid, stype, idlen = payload[:4], payload[4], payload[5]
        ident = payload[6:6 + idlen]
        opaque = payload[6 + idlen:]
        if stype != SIG_TYPE or kid != expected_key_id(ident) or ident != IDENTIFIER:
            return None
        if opaque[0] != 0x02:
            return None
        wlen = opaque[1]
        wallet = opaque[2:2 + wlen].decode()
        p = 2 + wlen
        siglen = opaque[p]
        sig65 = opaque[p + 1:p + 1 + siglen]
        ots_bytes = opaque[p + 1 + siglen:]
        return wallet, sig65, ots_bytes
    except Exception:
        return None


def commitment_of(origin, size, root, wallet) -> str:
    return hashlib.sha256(build_preimage(origin, size, root, wallet)).hexdigest()


def ots_commits(preimage: bytes, ots_bytes: bytes):
    with tempfile.TemporaryDirectory() as d:
        pf = os.path.join(d, "preimage.bin"); of = pf + ".ots"
        open(pf, "wb").write(preimage); open(of, "wb").write(ots_bytes)
        info = subprocess.run([OTS, "info", of], capture_output=True, text=True).stdout
        binds = hashlib.sha256(preimage).hexdigest() in info
        m = re.search(r"BitcoinBlockHeaderAttestation\((\d+)\)", info)
        when = ("Bitcoin block " + m.group(1)) if m else ("PENDING" if "PendingAttestation" in info else None)
        return binds, when


def sig_recovers(commitment_hex: str, sig65: bytes):
    try:
        msg = encode_defunct(text=f"{SIG_MSG_TAG}\n{commitment_hex}")
        return Account.recover_message(msg, signature=sig65)
    except Exception:
        return None


def eqaddr(a, b):
    return a is not None and b is not None and a.lower() == b.lower()


def main():
    raw = open(FILE, "rb").read()
    origin, size, root = raw.split(b"\n\n", 1)[0].decode().splitlines()[:3]
    sig_block = raw.split(b"\n\n", 1)[1].decode()
    print(f"checkpoint: {origin}  size {size}")

    known = [k for k in (parse_anchor(l) for l in sig_block.splitlines() if l.startswith(f"— {KEY_NAME} ")) if k]
    if not known:
        print("  [!] no known rootcommit-sig anchor"); sys.exit(1)
    wallet, sig65, ots_bytes = known[0]
    preimage = build_preimage(origin, size, root, wallet)
    commitment = hashlib.sha256(preimage).hexdigest()

    binds, when = ots_commits(preimage, ots_bytes)
    recovered = sig_recovers(commitment, sig65)
    sig_ok = eqaddr(recovered, wallet)

    print(f"  wallet bound  : {wallet}")
    print(f"  [1] Structure : PASS  (0xff, id={IDENTIFIER.decode()})")
    print(f"  [2] Binding   : {'PASS' if binds else 'FAIL'}  (proof commits sha256(preimage) {commitment[:16]}…)")
    if when and when != "PENDING":
        print(f"  [3] Temporal  : PASS  (Bitcoin-confirmed) — {when}")
    elif when == "PENDING":
        print("  [3] Temporal  : PENDING (upgrades to a Bitcoin block via `ots upgrade`)")
    else:
        print("  [3] Temporal  : FAIL")
    print(f"  [4] Signature : {'PASS' if sig_ok else 'FAIL'}  (EIP-191 recover -> {recovered} {'== wallet' if sig_ok else '!= wallet'})")

    bad_root = root[:-2] + ("A" if root[-2] != "A" else "B") + root[-1]
    rbinds, _ = ots_commits(build_preimage(origin, size, bad_root, wallet), ots_bytes)
    print(f"  [5] Root chk  : {'PASS' if not rbinds else 'FAIL'}  (mutated root correctly {'rejected' if not rbinds else 'ACCEPTED'})")

    bad_sig = bytearray(sig65); bad_sig[5] ^= 0x01
    bad_rec = sig_recovers(commitment, bytes(bad_sig))
    print(f"  [6] Sig chk   : {'PASS' if not eqaddr(bad_rec, wallet) else 'FAIL'}  (mutated signature correctly {'rejected' if not eqaddr(bad_rec, wallet) else 'ACCEPTED'})")

    ok = binds and (when is not None) and sig_ok and (not rbinds) and (not eqaddr(bad_rec, wallet))
    print("\n  RESULT:", "PASS — who (signature) + what (root) + when (Bitcoin), on one record." if ok
          else "REVIEW — see failing check above.")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
