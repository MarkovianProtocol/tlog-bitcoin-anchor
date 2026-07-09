#!/usr/bin/env python3
"""
Generate the tlog-bitcoin-anchor conformance test-vector corpus. Deterministic (fixed grease seed),
so the golden files are stable and reviewable in diffs. Any independent verifier can run these and
must produce the documented outcome -- that is what makes the format independently implementable.

Cases:
  01-valid            real anchor (+ grease), the demo output          -> known=1, binding ok, temporal pending/confirmed
  02-unknown-id       ONLY an unknown-identifier anchor line           -> known=0, ignored=1, MUST NOT reject (forward-compat)
  03-tampered-body    root hash altered, proof unchanged               -> binding MUST fail, MUST reject
  04-tampered-proof   OTS proof bytes corrupted                        -> MUST reject

Run on Neo:  ~/neo_env/bin/python3 make_vectors.py
"""
import base64, hashlib, json, os, random, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import anchor_line, grease_line, note_body, KEY_NAME, IDENTIFIER

DIR = os.path.expanduser("~/markovian/sunlight_anchor")
VDIR = os.path.join(DIR, "vectors")
CHECKPOINT = os.path.join(DIR, "tuscolo_checkpoint.txt")
OTS_PROOF = os.path.join(DIR, "tuscolo_notebody.txt.ots")


def write(name, checkpoint_bytes):
    open(os.path.join(VDIR, name), "wb").write(checkpoint_bytes)


def main():
    os.makedirs(VDIR, exist_ok=True)
    raw = open(CHECKPOINT, "rb").read()
    body = note_body(raw)
    ots = open(OTS_PROOF, "rb").read()
    head = raw if raw.endswith(b"\n") else raw + b"\n"

    real = anchor_line(IDENTIFIER, ots)
    grease = grease_line(seed=1)                                   # deterministic grease

    # 01 valid: real + grease, shuffled deterministically
    lines = [real, grease]; random.Random(1).shuffle(lines)
    write("01-valid.txt", head + "".join(l + "\n" for l in lines).encode())

    # 02 unknown-id only: no known anchor at all, just an unknown identifier -> must be ignored
    write("02-unknown-id.txt", head + (grease + "\n").encode())

    # 03 tampered note body: flip a byte in the root hash line; proof still commits the original body
    tam = bytearray(raw)
    rh = raw.split(b"\n")[2]                                       # root hash line
    i = raw.index(rh) + 5
    tam[i] ^= 0x01
    tam_head = bytes(tam).split(b"\n\n", 1)[0] + b"\n\n"
    write("03-tampered-body.txt", tam_head + (real + "\n").encode())

    # 04 tampered proof: corrupt the committed digest inside the proof so it no longer commits this
    # note body. Binding MUST fail regardless of Bitcoin confirmation status.
    digest = hashlib.sha256(body).digest()
    bad = bytearray(ots)
    j = bad.find(digest)                                          # the 32-byte committed digest
    if j < 0:
        j = 8                                                     # fallback: an early proof byte
    bad[j + 5] ^= 0x01
    write("04-tampered-proof.txt", head + (anchor_line(IDENTIFIER, bytes(bad)) + "\n").encode())

    manifest = {
        "format": "tlog-bitcoin-anchor conformance vectors",
        "note": "committed note body sha256 = " + hashlib.sha256(body).hexdigest(),
        "vectors": [
            {"file": "01-valid.txt", "desc": "real anchor + grease line, shuffled",
             "expect": {"known_anchors": 1, "ignored": 1, "binding": True, "reject": False}},
            {"file": "02-unknown-id.txt", "desc": "only an unknown-identifier anchor; forward-compat",
             "expect": {"known_anchors": 0, "ignored": 1, "reject": False}},
            {"file": "03-tampered-body.txt", "desc": "root hash altered; note body no longer matches proof",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
            {"file": "04-tampered-proof.txt", "desc": "OTS proof corrupted",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
        ],
    }
    open(os.path.join(VDIR, "manifest.json"), "w").write(json.dumps(manifest, indent=2))
    print("wrote", len(manifest["vectors"]), "vectors + manifest.json to", VDIR)


if __name__ == "__main__":
    main()
