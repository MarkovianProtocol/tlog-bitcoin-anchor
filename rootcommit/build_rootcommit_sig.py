#!/usr/bin/env python3
"""
rootcommit v2-sig: add the wallet's own ECDSA (EIP-191) signature over the rootcommit commitment.

Layering is explicit and deliberate: the committed preimage and its Bitcoin anchor are byte-for-byte
IDENTICAL to rootcommit/v1 (the v2 fixture). v2-sig only ADDS W's signature over that same
commitment, turning "the address was committed" (anchorer's choice) into "W's key attested to this
root, and Bitcoin timestamps the attestation." That is who (signature) + what (root) + when (Bitcoin).

Signs an EIP-191 personal-sign message. No transaction, no funds move. The private key is loaded,
used, and never printed.

Run on Neo:  ~/neo_env/bin/python3 build_rootcommit_sig.py
"""
import base64, datetime, hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import anchor_line, KEY_NAME
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from build_rootcommit import build_preimage, note_lines, checksum, WALLET
from eth_account import Account
from eth_account.messages import encode_defunct

DIR = os.path.dirname(os.path.abspath(__file__))
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
CHECKPOINT = os.path.join(DIR, "mkv_checkpoint.txt")
OTS_PROOF = os.path.join(DIR, "rootcommit_preimage.bin.ots")          # same commitment as v2
WALLET_FILE = os.path.expanduser("~/.secrets/agent3_evm_wallet.json")
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"  # canonical: matches the message tag + the rootcommit/vN family
SIG_MSG_TAG = "markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"
OPAQUE_VERSION = 0x02


def sig_message(commitment_hex: str) -> str:
    """The exact EIP-191 message the wallet signs. Frozen: tag line, then the commitment hex."""
    return f"{SIG_MSG_TAG}\n{commitment_hex}"


def build_opaque(wallet: str, sig65: bytes, ots_bytes: bytes) -> bytes:
    """opaque = version(1)=0x02 || wlen(1) || wallet_ascii || 0x41 || sig(65) || ots_proof_bytes."""
    w = wallet.encode()
    assert len(w) < 256 and len(sig65) == 65
    return bytes([OPAQUE_VERSION, len(w)]) + w + bytes([65]) + sig65 + ots_bytes


def main():
    wallet = checksum(WALLET)
    raw = open(CHECKPOINT, "rb").read()
    origin, size, root = note_lines(raw)
    preimage = build_preimage(origin, size, root, wallet)
    commitment = hashlib.sha256(preimage).hexdigest()

    wj = json.load(open(WALLET_FILE))
    assert checksum(wj["address"]) == wallet, "wallet file address != bound wallet"
    acct = Account.from_key(wj["private_key"])                 # key used here, never printed
    msg = sig_message(commitment)
    signed = acct.sign_message(encode_defunct(text=msg))
    sig65 = bytes(signed.signature)
    recovered = Account.recover_message(encode_defunct(text=msg), signature=sig65)
    assert checksum(recovered) == wallet, "self-recover != wallet"

    ots_bytes = open(OTS_PROOF, "rb").read()
    info = subprocess.run([OTS, "info", OTS_PROOF], capture_output=True, text=True).stdout
    assert commitment in info, "shared OTS proof does not commit this preimage"
    confirmed = "bitcoin block" in info.lower()

    line = anchor_line(IDENTIFIER, build_opaque(wallet, sig65, ots_bytes))
    augmented = raw if raw.endswith(b"\n") else raw + b"\n"
    augmented += (line + "\n").encode()
    open(os.path.join(DIR, "mkv_checkpoint.rootcommit-sig.txt"), "wb").write(augmented)

    artifact = {
        "_what": "A Markovian log checkpoint, Bitcoin-anchored over (root + wallet), AND signed by "
                 "that wallet's key over the same commitment.",
        "layering": "commitment and Bitcoin anchor are identical to rootcommit/v1; v2-sig adds W's "
                    "signature over that commitment.",
        "checkpoint": {"origin": origin, "tree_size": int(size), "root_line_verbatim": root},
        "commitment_sha256": commitment,
        "wallet": wallet,
        "signature": {
            "scheme": "EIP-191 personal_sign (secp256k1), recover -> address",
            "message": msg,
            "sig_b64": base64.b64encode(sig65).decode(),
            "recovers_to": recovered,
        },
        "anchor": {
            "type": "opentimestamps",
            "identifier": IDENTIFIER.decode(),
            "opaque_layout": "version(1)=0x02 || wlen(1) || wallet_ascii || 0x41 || sig(65) || ots_bytes",
            "anchor_line": line,
            "status": "bitcoin-confirmed" if confirmed else "pending",
            "anchoredAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "proves": "who (W's signature) + what (root) + when (Bitcoin). The record was never rewritten.",
        "does_not_prove": "that the root is a correct tree head of anything real, or that any figure "
                          "behind it is true. Provenance and attestation, not audit.",
    }
    open(os.path.join(DIR, "mkv_rootcommit-sig.json"), "w").write(json.dumps(artifact, indent=2))

    print("checkpoint       :", origin, "size", size)
    print("commitment sha256:", commitment)
    print("wallet (EIP-55)  :", wallet)
    print("signature        : EIP-191 personal_sign, recovers ->", recovered, "MATCH" if checksum(recovered) == wallet else "MISMATCH")
    print("anchor status    :", artifact["anchor"]["status"])
    print("wrote            : mkv_checkpoint.rootcommit-sig.txt, mkv_rootcommit-sig.json")


if __name__ == "__main__":
    main()
