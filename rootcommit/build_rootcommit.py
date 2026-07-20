#!/usr/bin/env python3
"""
Stronger Bitcoin-anchor variant for tlog-bitcoin-anchor: OTS over a domain-separated
preimage that binds the checkpoint's Merkle ROOT together with an operator WALLET address.

v1 (ots/v1) timestamps the checkpoint note body; the operator identity lives only in the
signed-note key name, which Bitcoin never sees. v2 (rootcommit/v1) folds the wallet INTO the
timestamped preimage, so the Bitcoin attestation commits to (root, wallet) jointly. Mutating
either the root or the wallet breaks the binding -- that is the property this fixture proves,
and the new tamper-wallet vector is what makes "wallet is bound" a check rather than a claim.

Honest scope: this binds the wallet ADDRESS BYTES to the root under a Bitcoin-confirmed time.
It is provenance chosen by the anchorer, not by itself a signature by that wallet's key. A
wallet ECDSA attestation over the same commitment is the offered next increment (rootcommit/v2-sig).

Run on Neo:  ~/neo_env/bin/python3 build_rootcommit.py
"""
import base64, datetime, hashlib, json, os, subprocess, sys
sys.path.insert(0, os.path.expanduser("~/markovian/sunlight_anchor"))
from build_sunlight_anchor import anchor_line, KEY_NAME  # reuse v1 signed-note framing

DIR = os.path.dirname(os.path.abspath(__file__))
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
CHECKPOINT = os.path.join(DIR, "mkv_checkpoint.txt")
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
PREIMAGE_TAG = "markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
OPAQUE_VERSION = 0x01
WALLET = os.environ.get("WALLET", "0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273")  # Agent 3, ours


def note_lines(raw: bytes):
    body = raw.split(b"\n\n", 1)[0]
    origin, size, root = body.decode().splitlines()[:3]
    return origin, size, root


def build_preimage(origin: str, size: str, root: str, wallet: str) -> bytes:
    """Frozen byte layout -- any implementation MUST reproduce these exact bytes.
    Five LF-terminated ASCII lines: domain tag first, then key=value lines. `root` is the
    checkpoint's third line verbatim (base64, no re-encoding); `wallet` is EIP-55 checksummed."""
    lines = [PREIMAGE_TAG,
             f"origin={origin}",
             f"size={size}",
             f"root={root}",
             f"wallet={wallet}"]
    return ("\n".join(lines) + "\n").encode()


def build_opaque(wallet: str, ots_bytes: bytes) -> bytes:
    """opaque = version(1) || wlen(1) || wallet_ascii[wlen] || ots_proof_bytes -- self-contained."""
    w = wallet.encode()
    assert len(w) < 256
    return bytes([OPAQUE_VERSION, len(w)]) + w + ots_bytes


def checksum(wallet: str) -> str:
    try:
        from web3 import Web3
        return Web3.to_checksum_address(wallet)
    except Exception:
        return wallet  # if web3 absent, trust the caller-supplied EIP-55 form


def main():
    wallet = checksum(WALLET)
    raw = open(CHECKPOINT, "rb").read()
    origin, size, root = note_lines(raw)
    preimage = build_preimage(origin, size, root, wallet)
    commitment = hashlib.sha256(preimage).hexdigest()

    pre_path = os.path.join(DIR, "rootcommit_preimage.bin")
    open(pre_path, "wb").write(preimage)
    ots_path = pre_path + ".ots"
    if not os.path.exists(ots_path):
        subprocess.run([OTS, "stamp", pre_path], check=True)
    ots_bytes = open(ots_path, "rb").read()

    info = subprocess.run([OTS, "info", ots_path], capture_output=True, text=True).stdout
    assert commitment in info, f"OTS proof does not commit the preimage sha256\n{info}"
    confirmed = "bitcoin block" in info.lower()

    line = anchor_line(IDENTIFIER, build_opaque(wallet, ots_bytes))
    augmented = raw if raw.endswith(b"\n") else raw + b"\n"
    augmented += (line + "\n").encode()
    open(os.path.join(DIR, "mkv_checkpoint.rootcommit.txt"), "wb").write(augmented)

    artifact = {
        "_what": "A Markovian log checkpoint, Bitcoin-anchored with the Merkle root AND operator "
                 "wallet folded into the timestamped preimage.",
        "_why": ("v1 timestamps the note body; the operator identity is outside the Bitcoin "
                 "commitment. Here the wallet is inside it, so the Bitcoin attestation commits to "
                 "(root, wallet) jointly. Mutating the root OR the wallet breaks the binding."),
        "checkpoint": {"origin": origin, "tree_size": int(size), "root_line_verbatim": root},
        "preimage": {
            "tag": PREIMAGE_TAG,
            "layout": "5 LF-terminated ASCII lines: tag, origin=, size=, root=, wallet=",
            "wallet": wallet,
            "sha256": commitment,
            "note": "root= is the checkpoint's 3rd line verbatim (base64); wallet= is EIP-55.",
        },
        "anchor": {
            "type": "opentimestamps",
            "signed_note_key_name": KEY_NAME,
            "signed_note_sig_type": "0xff",
            "identifier": IDENTIFIER.decode(),
            "opaque_layout": "version(1)=0x01 || wlen(1) || wallet_ascii || ots_proof_bytes",
            "anchor_line": line,
            "proof_ots_b64": base64.b64encode(ots_bytes).decode(),
            "status": "bitcoin-confirmed" if confirmed else "pending",
            "anchoredAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        },
        "scope": ("Binds the wallet ADDRESS BYTES to the root under a Bitcoin-confirmed time. "
                  "This is provenance chosen by the anchorer, not a signature by the wallet's key. "
                  "It proves what (root), when (Bitcoin), and that a named wallet was committed "
                  "alongside; it does not prove the wallet owner endorsed the root, nor that the "
                  "root is a correct tree head of anything. A wallet ECDSA attestation over this "
                  "same commitment (rootcommit/v2-sig) is the offered next increment."),
    }
    open(os.path.join(DIR, "mkv_rootcommit.json"), "w").write(json.dumps(artifact, indent=2))

    print("checkpoint       :", origin, "size", size)
    print("wallet (EIP-55)  :", wallet)
    print("preimage sha256  :", commitment)
    print("anchor status    :", artifact["anchor"]["status"])
    print("wrote            : mkv_checkpoint.rootcommit.txt, mkv_rootcommit.json, rootcommit_preimage.bin(.ots)")


if __name__ == "__main__":
    main()
