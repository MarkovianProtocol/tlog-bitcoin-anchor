#!/usr/bin/env python3
"""verify_preimage.py — check the ForeSeal anchor preimages in this directory, offline.

Standard library only. No network, no node, no calendar, nothing of either party's to contact.

It asserts three things per tier:

  1. the committed .bin parses as `payperbyte.io/x402-anchor/receipt/v2-sig` — exactly four
     LF-terminated lines (tag / tier= / digest= / signer=), no blanks, no trailing content, and
     no signature line: v2-sig commits the SIGNER, the signature travels alongside;
  2. SHA-256 over those exact file bytes equals the commitment in manifest.json — this is the
     value `ots stamp` commits to, and the value `ots info <file>.ots` prints back;
  3. the tier, digest and signer lines are well-formed and agree with the manifest.

It does NOT validate the signer's EIP-55 checksum — keccak256 is not in the standard library. A
preimage emitted with a non-checksummed signer would pass here, because the commitment is computed
from the file and so always agrees with a consistently-emitted file. The hash check catches
tampering AFTER emission; it cannot catch a preimage that was spec-violating at emission. Signer
recovery in the source repo is what catches that.

It also does not verify the signature in manifest.json — it checks that one is present and
structurally sound: 65 bytes, recovery id 27 or 28, and r/s inside the secp256k1 group order with s
in the lower half (EIP-2). Those are integer comparisons, so they need no curve library, and they
reject the overwhelming majority of hex that is merely the right LENGTH. What they cannot do is tie
the signature to the digest — recovering it to `signer` needs secp256k1, which is not stdlib. Treat
a green signature line as "this is shaped like a real Ethereum signature", never as "this signature
is valid for this receipt".

What it deliberately does NOT do: recover the EIP-712 signer. That needs secp256k1, and the
point of this directory is that the anchoring side can check the binding with the standard
library alone. Signer recovery lives in the source repo (`npm run vector`, cross-checked in
TypeScript and Python) and is a separate, stronger claim.

Scope, so a green run is not over-read: this proves the stamped bytes are the ones **manifest.json**
names, and that the manifest's commitments are the SHA-256 of those exact bytes. manifest.json is
not signed. Binding it to the actual receipt means fetching `fixtures/live-receipt.json` from the
source repo and recovering the EIP-712 signers — a separate, stronger check that lives there. A
green run here also says nothing about whether the data in the receipt is correct, and nothing
about existence-in-time until an anchor proof is attached.

    python3 verify_preimage.py          # exit 0 iff every tier checks out
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TAG = "payperbyte.io/x402-anchor/receipt/v2-sig"
_TIER = re.compile(r"^tier=(delivery|provenance)$")
_DIGEST = re.compile(r"^digest=0x[0-9a-f]{64}$")
_SIGNER = re.compile(r"^signer=0x[0-9a-fA-F]{40}$")

# Order of the secp256k1 group. Used only for integer range checks on (r, s) — no curve arithmetic,
# so this stays standard-library-only.
_SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141


def check_signature(tier: str, sig: object) -> list[str]:
    """Structural checks on the accompanying signature. Cheap, stdlib-only, and fail-closed.

    A length-only check accepts any 130 hex characters, which means a corrupted or placeholder
    signature rides along looking fine. Splitting it into (r, s, v) and range-checking costs
    nothing and rejects almost all of that: r and s must be non-zero and below the group order,
    s must be in the lower half (EIP-2 — Ethereum rejects malleable high-s signatures outright),
    and v must be 27 or 28.

    This still does NOT prove the signature belongs to this digest or this signer. That is
    recovery, it needs secp256k1, and it lives in the source repo.
    """
    if not isinstance(sig, str) or not re.fullmatch(r"0x[0-9a-fA-F]{130}", sig):
        return [f"{tier}: manifest signature missing or not 0x + 130 hex (present: {sig!r})"]

    body = sig[2:]
    r = int(body[0:64], 16)
    s = int(body[64:128], 16)
    v = int(body[128:130], 16)

    errs = []
    if not 0 < r < _SECP256K1_N:
        errs.append(f"{tier}: signature r is not in [1, n-1] — not a secp256k1 signature")
    if not 0 < s < _SECP256K1_N:
        errs.append(f"{tier}: signature s is not in [1, n-1] — not a secp256k1 signature")
    elif s > _SECP256K1_N // 2:
        errs.append(f"{tier}: signature has high s — EIP-2 requires the lower half (malleable)")
    if v not in (27, 28):
        errs.append(f"{tier}: signature recovery id is {v}, expected 27 or 28")
    return errs


def check(tier: str, spec: dict) -> list[str]:
    errs = []
    path = HERE / spec["preimage_file"]
    if not path.exists():
        return [f"{tier}: missing {spec['preimage_file']}"]
    raw = path.read_bytes()

    if len(raw) != spec["preimage_bytes"]:
        errs.append(f"{tier}: {len(raw)} bytes on disk, manifest says {spec['preimage_bytes']}")
    if not raw.endswith(b"\n"):
        errs.append(f"{tier}: preimage does not end with LF")
    if b"\n\n" in raw:
        errs.append(f"{tier}: preimage contains a blank line (v2-sig is exactly four lines)")

    lines = raw.decode("utf-8").split("\n")
    if len(lines) != 5 or lines[4] != "":
        errs.append(f"{tier}: expected exactly 4 LF-terminated lines, got {len(lines) - 1}")
    else:
        if lines[0] != TAG:
            errs.append(f"{tier}: line 1 is {lines[0]!r}, expected {TAG!r}")
        if not _TIER.match(lines[1]):
            errs.append(f"{tier}: line 2 is not tier=<delivery|provenance>: {lines[1]!r}")
        elif lines[1] != f"tier={tier}":
            errs.append(f"{tier}: line 2 says {lines[1]!r} but is filed under tier {tier!r}")
        if not _DIGEST.match(lines[2]):
            errs.append(f"{tier}: line 3 is not digest=0x<64 hex>")
        elif lines[2] != f"digest={spec['eip712_digest']}":
            errs.append(f"{tier}: digest line disagrees with manifest")
        if not _SIGNER.match(lines[3]):
            errs.append(f"{tier}: line 4 is not signer=0x<40 hex>")
        elif lines[3] != f"signer={spec['signer']}":
            errs.append(f"{tier}: signer line disagrees with manifest")
        if "sig=" in raw.decode("utf-8"):
            errs.append(f"{tier}: preimage carries a signature line — v2-sig commits the SIGNER, "
                        f"the signature travels alongside")

    # The signature is not in the preimage, but the manifest must still carry a well-formed one —
    # it is the "who" layer, and shipping a tier without it would be a silently incomplete record.
    errs += check_signature(tier, spec.get("signature"))

    got = "0x" + hashlib.sha256(raw).hexdigest()
    if got != spec["commitment"]:
        errs.append(f"{tier}: commitment mismatch — computed {got}, manifest says {spec['commitment']}")
    else:
        print(f"[OK] {tier:11s} {len(raw)} B  sha256 {got}")
    return errs


def main() -> int:
    try:
        manifest = json.loads((HERE / "manifest.json").read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"[FAIL] manifest.json is not readable valid JSON: {e}")
        return 1
    if manifest.get("format") != TAG:
        print(f"[FAIL] manifest format is {manifest.get('format')!r}, expected {TAG!r}")
        return 1

    tiers = manifest.get("tiers") or {}
    if not tiers:
        print("[FAIL] manifest declares no tiers — nothing to check (a green run here would be vacuous)")
        return 1

    errs = []
    for tier, spec in tiers.items():
        errs += check(tier, spec)

    # Every preimage file present must be declared. An undeclared .bin sitting in the directory
    # would otherwise ride along unchecked and look blessed by a green run.
    # Two tiers pointing at the same file, or carrying the same digest, would let one preimage
    # masquerade as coverage of both.
    files = [s.get("preimage_file") for s in tiers.values()]
    digs = [s.get("eip712_digest") for s in tiers.values()]
    if len(set(files)) != len(files):
        errs.append("two tiers declare the same preimage_file — each tier must name its own")
    if len(set(digs)) != len(digs):
        errs.append("two tiers declare the same eip712_digest — tiers must be distinct receipts")

    sigs = [s.get("signature") for s in tiers.values()]
    if len(set(sigs)) != len(sigs):
        errs.append("two tiers declare the same signature — tiers must be distinct receipts")

    declared = {s.get("preimage_file") for s in tiers.values()}
    for stray in sorted(p.name for p in HERE.glob("*.preimage.bin")):
        if stray not in declared:
            errs.append(f"{stray} is present but not declared in manifest.tiers — unchecked")

    for e in errs:
        print(f"[FAIL] {e}")
    print("\n" + (f"all {len(tiers)} declared preimage(s) check out" if not errs
                  else f"{len(errs)} problem(s)"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
