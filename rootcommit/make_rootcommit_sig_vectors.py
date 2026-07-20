#!/usr/bin/env python3
"""
Generate rootcommit-sig/v1 conformance vectors. Deterministic, reviewable in diffs.

  v2sig-01-valid          real anchor + valid wallet signature        -> binding ok, sig ok, no reject
  v2sig-02-tampered-root  root line altered                           -> binding fails, reject
  v2sig-03-tampered-wallet wallet altered in opaque                   -> binding fails, reject
  v2sig-04-tampered-sig   signature bytes corrupted                   -> sig fails, reject   (NEW vs v2)
  v2sig-05-tampered-proof OTS proof corrupted                         -> binding fails, reject

Run on Neo (after build_rootcommit_sig.py):  ~/neo_env/bin/python3 make_rootcommit_sig_vectors.py
"""
import base64, hashlib, json, os, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import anchor_line
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_rootcommit import build_preimage, note_lines, checksum, WALLET
from build_rootcommit_sig import build_opaque, sig_message, IDENTIFIER
from eth_account import Account
from eth_account.messages import encode_defunct

DIR = os.path.dirname(os.path.abspath(__file__))
VDIR = os.path.join(DIR, "vectors_sig")
CHECKPOINT = os.path.join(DIR, "mkv_checkpoint.txt")
OTS_PROOF = os.path.join(DIR, "rootcommit_preimage.bin.ots")
WALLET_FILE = os.path.expanduser("~/.secrets/agent3_evm_wallet.json")


def write(name, data): open(os.path.join(VDIR, name), "wb").write(data)


def main():
    os.makedirs(VDIR, exist_ok=True)
    wallet = checksum(WALLET)
    raw = open(CHECKPOINT, "rb").read()
    origin, size, root = note_lines(raw)
    ots = open(OTS_PROOF, "rb").read()
    head = raw if raw.endswith(b"\n") else raw + b"\n"

    commitment = hashlib.sha256(build_preimage(origin, size, root, wallet)).hexdigest()
    acct = Account.from_key(json.load(open(WALLET_FILE))["private_key"])   # never printed
    sig65 = bytes(acct.sign_message(encode_defunct(text=sig_message(commitment))).signature)

    # 01 valid
    real = anchor_line(IDENTIFIER, build_opaque(wallet, sig65, ots))
    write("v2sig-01-valid.txt", head + (real + "\n").encode())

    # 02 tampered root
    tam = bytearray(raw)
    root_line = raw.split(b"\n")[2]
    tam[raw.index(root_line) + 4] ^= 0x01
    th = bytes(tam); th = th if th.endswith(b"\n") else th + b"\n"
    write("v2sig-02-tampered-root.txt", th + (real + "\n").encode())

    # 03 tampered wallet (opaque carries a different wallet; sig + ots still over the original)
    bad_wallet = wallet[:-1] + ("0" if wallet[-1] != "0" else "1")
    write("v2sig-03-tampered-wallet.txt", head + (anchor_line(IDENTIFIER, build_opaque(bad_wallet, sig65, ots)) + "\n").encode())

    # 04 tampered signature
    bad_sig = bytearray(sig65); bad_sig[5] ^= 0x01
    write("v2sig-04-tampered-sig.txt", head + (anchor_line(IDENTIFIER, build_opaque(wallet, bytes(bad_sig), ots)) + "\n").encode())

    # 05 tampered proof
    digest = hashlib.sha256(build_preimage(origin, size, root, wallet)).digest()
    bad = bytearray(ots); j = bad.find(digest); j = j if j >= 0 else 8; bad[j + 5] ^= 0x01
    write("v2sig-05-tampered-proof.txt", head + (anchor_line(IDENTIFIER, build_opaque(wallet, sig65, bytes(bad))) + "\n").encode())

    manifest = {
        "format": "tlog-bitcoin-anchor rootcommit-sig/v1 conformance vectors",
        "identifier": IDENTIFIER.decode(),
        "commitment_sha256": commitment,
        "wallet": wallet,
        "signature_scheme": "EIP-191 personal_sign (secp256k1); message = tag + '\\n' + commitment_hex",
        "opaque_layout": "version(1)=0x02 || wlen(1) || wallet_ascii || 0x41 || sig(65) || ots_bytes",
        "vectors": [
            {"file": "v2sig-01-valid.txt", "desc": "real anchor + valid wallet signature",
             "expect": {"known_anchors": 1, "binding": True, "sig_ok": True, "reject": False}},
            {"file": "v2sig-02-tampered-root.txt", "desc": "root altered",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
            {"file": "v2sig-03-tampered-wallet.txt", "desc": "wallet altered in opaque",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
            {"file": "v2sig-04-tampered-sig.txt", "desc": "signature bytes corrupted",
             "expect": {"known_anchors": 1, "sig_ok": False, "reject": True}},
            {"file": "v2sig-05-tampered-proof.txt", "desc": "OTS proof corrupted",
             "expect": {"known_anchors": 1, "binding": False, "reject": True}},
        ],
    }
    open(os.path.join(VDIR, "manifest.json"), "w").write(json.dumps(manifest, indent=2))
    print("wrote", len(manifest["vectors"]), "vectors + manifest.json to", VDIR)
    print("commitment sha256:", commitment)


if __name__ == "__main__":
    main()
