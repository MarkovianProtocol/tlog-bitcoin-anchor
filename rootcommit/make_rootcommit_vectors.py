#!/usr/bin/env python3
"""
Generate the rootcommit/v1 conformance vectors. Deterministic and reviewable in diffs. Every
independent verifier must reproduce the documented outcome -- that is what makes the wallet
binding independently checkable.

Cases:
  rootcommit-01-valid          real anchor, preimage commits (root, wallet)   -> binding ok, no reject
  rootcommit-02-tampered-root  root line altered in note body                 -> binding MUST fail, reject
  rootcommit-03-tampered-wallet wallet byte altered inside the opaque         -> binding MUST fail, reject  (NEW property vs v1)
  rootcommit-04-tampered-proof OTS proof bytes corrupted                      -> binding MUST fail, reject

Run on Neo (after build_rootcommit.py):  ~/neo_env/bin/python3 make_rootcommit_vectors.py
"""
import hashlib, json, os, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import anchor_line
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_rootcommit import build_opaque, build_preimage, IDENTIFIER, note_lines, checksum, WALLET

DIR = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(DIR, "vectors")
CHECKPOINT = os.path.join(DIR, "mkv_checkpoint.txt")
OTS_PROOF = os.path.join(DIR, "rootcommit_preimage.bin.ots")


def write(name, data): open(os.path.join(VDIR, name), "wb").write(data)


def main():
    os.makedirs(VDIR, exist_ok=True)
    wallet = checksum(WALLET)
    raw = open(CHECKPOINT, "rb").read()
    origin, size, root = note_lines(raw)
    ots = open(OTS_PROOF, "rb").read()
    head = raw if raw.endswith(b"\n") else raw + b"\n"

    # committed preimage sha256, for the manifest
    committed = hashlib.sha256(build_preimage(origin, size, root, wallet)).hexdigest()

    # 01 valid
    real = anchor_line(IDENTIFIER, build_opaque(wallet, ots))
    write("rootcommit-01-valid.txt", head + (real + "\n").encode())

    # 02 tampered root: flip a byte in the root (3rd) line; opaque unchanged
    tam = bytearray(raw)
    root_line = raw.split(b"\n")[2]
    i = raw.index(root_line) + 4
    tam[i] ^= 0x01
    tam_head = bytes(tam)
    tam_head = tam_head if tam_head.endswith(b"\n") else tam_head + b"\n"
    # ensure note body still parses (byte flip may hit base64 alphabet; keep it printable)
    write("rootcommit-02-tampered-root.txt", tam_head + (real + "\n").encode())

    # 03 tampered wallet: opaque carries a mutated wallet, but the OTS still commits the ORIGINAL
    # preimage. Verifier reconstructs preimage(root, mutated_wallet) -> mismatch. NEW property.
    bad_wallet = wallet[:-1] + ("0" if wallet[-1] != "0" else "1")
    bad_line = anchor_line(IDENTIFIER, build_opaque(bad_wallet, ots))
    write("rootcommit-03-tampered-wallet.txt", head + (bad_line + "\n").encode())

    # 04 tampered proof: corrupt the committed digest inside the OTS proof
    digest = hashlib.sha256(build_preimage(origin, size, root, wallet)).digest()
    bad = bytearray(ots)
    j = bad.find(digest)
    j = j if j >= 0 else 8
    bad[j + 5] ^= 0x01
    bad_proof_line = anchor_line(IDENTIFIER, build_opaque(wallet, bytes(bad)))
    write("rootcommit-04-tampered-proof.txt", head + (bad_proof_line + "\n").encode())

    manifest = {
        "format": "tlog-bitcoin-anchor rootcommit/v1 conformance vectors",
        "identifier": IDENTIFIER.decode(),
        "committed_preimage_sha256": committed,
        "wallet": wallet,
        "preimage_layout": "5 LF-terminated ASCII lines: tag, origin=, size=, root= (verbatim base64), wallet= (EIP-55)",
        "opaque_layout": "version(1)=0x01 || wlen(1) || wallet_ascii || ots_proof_bytes",
        "scope": ("Binds wallet address bytes to the root under Bitcoin time; provenance chosen by "
                  "the anchorer, not a signature by the wallet's key."),
        "vectors": [
            {"file": "rootcommit-01-valid.txt", "desc": "real anchor; preimage commits (root, wallet)",
             "expect": {"known_anchors": 1, "binding": True, "reject": False}},
            {"file": "rootcommit-02-tampered-root.txt", "desc": "root line altered; preimage no longer matches proof",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
            {"file": "rootcommit-03-tampered-wallet.txt", "desc": "wallet altered in opaque; preimage no longer matches proof",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
            {"file": "rootcommit-04-tampered-proof.txt", "desc": "OTS proof corrupted",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
        ],
    }
    open(os.path.join(VDIR, "manifest.json"), "w").write(json.dumps(manifest, indent=2))
    print("wrote", len(manifest["vectors"]), "vectors + manifest.json to", VDIR)
    print("committed preimage sha256:", committed)


if __name__ == "__main__":
    main()
