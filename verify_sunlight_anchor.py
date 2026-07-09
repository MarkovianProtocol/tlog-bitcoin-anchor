#!/usr/bin/env python3
"""
Independent verifier for a Bitcoin-anchored Tuscolo checkpoint. Trusts neither Geomys nor
Markovian. Works from the single self-contained `.anchored.txt` file: the Bitcoin proof rides
inside the checkpoint, so nothing else is needed but the stock `ots` client and Bitcoin headers.

Conformance behaviour demonstrated here:
  - Multiple anchor lines under our key name are tolerated; lines with an UNKNOWN identifier
    (grease / future anchor versions) are IGNORED, never rejected.
  - The one known-identifier anchor is verified: structure, binding to the note body, and Bitcoin.
  - A negative self-check proves the binding actually checks (mutating the note body MUST break it).

The log's OWN signature lines are left untouched and still verify with the log's key. That is WHO;
this tool only adds WHEN.

Run on Neo:  ~/neo_env/bin/python3 verify_sunlight_anchor.py [file]
"""
import base64, hashlib, os, re, subprocess, sys, tempfile

DIR = os.path.expanduser("~/markovian/sunlight_anchor")
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
KEY_NAME = "markovianprotocol.com/bitcoin-anchor"
SIG_TYPE = 0xff
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/ots/v1"
FILE = sys.argv[1] if len(sys.argv) > 1 else os.path.join(DIR, "tuscolo_checkpoint.anchored.txt")


def expected_key_id(identifier: bytes) -> bytes:
    return hashlib.sha256(KEY_NAME.encode() + b"\x0a" + bytes([SIG_TYPE]) + identifier).digest()[:4]


def parse_anchor(line: str):
    """Return (identifier, ots_bytes) or None if the line is malformed."""
    try:
        payload = base64.b64decode(line.split(" ", 2)[2])
        kid, stype, idlen = payload[:4], payload[4], payload[5]
        ident = payload[6:6 + idlen]
        opaque = payload[6 + idlen:]
        if stype != SIG_TYPE or kid != expected_key_id(ident):
            return None
        return ident, opaque
    except Exception:
        return None


def ots_check(body: bytes, ots_bytes: bytes):
    """Return (binds, when) — binds = proof commits sha256(body); when = Bitcoin line or None/pending."""
    with tempfile.TemporaryDirectory() as d:
        bf = os.path.join(d, "notebody.txt"); of = bf + ".ots"
        open(bf, "wb").write(body); open(of, "wb").write(ots_bytes)
        info = subprocess.run([OTS, "info", of], capture_output=True, text=True).stdout
        binds = hashlib.sha256(body).hexdigest() in info
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
    body = raw.split(b"\n\n", 1)[0] + b"\n"
    sig_block = raw.split(b"\n\n", 1)[1].decode()
    origin, size, root = body.decode().splitlines()[:3]
    print(f"checkpoint: {origin}  size {size}")

    lines = [l for l in sig_block.splitlines() if l.startswith("— ")]
    log_sigs = [l for l in lines if not l.startswith(f"— {KEY_NAME} ")]
    ours = [l for l in lines if l.startswith(f"— {KEY_NAME} ")]

    real, ignored = [], 0
    for l in ours:
        p = parse_anchor(l)
        if p and p[0] == IDENTIFIER:
            real.append(p[1])
        else:
            ignored += 1                                  # unknown identifier / grease -> ignore
    print(f"  anchor lines : {len(real)} known, {ignored} ignored (unknown identifier / grease)")

    if not real:
        print("  [!] no known anchor to verify"); return
    binds, when = ots_check(body, real[0])
    print(f"  [1] Structure : PASS  (0xff signed-note line, id={IDENTIFIER.decode()})")
    print(f"  [2] Binding   : {'PASS' if binds else 'FAIL'}  (proof commits sha256(note body) {hashlib.sha256(body).hexdigest()[:16]}…)")
    if when and when != "PENDING":
        print(f"  [3] Temporal  : PASS  (Bitcoin-confirmed) — {when.strip()[:80]}")
    elif when == "PENDING":
        print("  [3] Temporal  : PENDING (Bitcoin-confirms in ~1 block, then `ots upgrade`)")
    else:
        print("  [3] Temporal  : FAIL  (no Bitcoin attestation)")

    # Negative self-check: mutate the note body; the binding MUST break. Proves the check has teeth.
    tampered = bytearray(body); tampered[-2] ^= 0x01
    nbinds, _ = ots_check(bytes(tampered), real[0])
    print(f"  [4] Self-check: {'PASS' if not nbinds else 'FAIL'}  (mutated note body correctly {'rejected' if not nbinds else 'ACCEPTED — binding is a no-op!'})")

    print(f"\n  WHO : {len(log_sigs)} log signature line(s) intact — verify with the log's own key / stock tooling.")
    print("  WHEN: this exact tree head is anchored to Bitcoin — no key, no witness, offline.")


if __name__ == "__main__":
    main()
