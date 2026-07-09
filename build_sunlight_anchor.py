#!/usr/bin/env python3
"""
Bitcoin-anchor a real Certificate Transparency checkpoint from Geomys' own Tuscolo log.

Takes a live c2sp.org/tlog-checkpoint (fetched from tuscolo2026h2.skylight.geomys.org),
and attaches an OpenTimestamps Bitcoin anchor as an additional c2sp.org/signed-note
signature line under the 0xff "unassigned signature type" escape hatch. The result is
still a valid signed note: the log's own signatures verify unchanged, and the anchor line
is ignored by any client that doesn't know it (exactly as tlog-checkpoint mandates:
"clients MUST ignore unknown signatures").

What the anchor commits: the checkpoint's note body (origin, tree size, root hash) -- the
identical bytes the log signs. So the anchor proves that THIS tree head existed on Bitcoin
at a block-confirmed time, un-backdatable, verifiable offline with the stock `ots` client
against a Bitcoin block header, trusting neither the log operator nor us.

Run on Neo (where ots lives):  ~/neo_env/bin/python3 build_sunlight_anchor.py
"""
import base64, datetime, hashlib, json, os, random, subprocess

DIR = os.path.expanduser("~/markovian/sunlight_anchor")
OTS = os.environ.get("OTS", os.path.expanduser("~/neo_env/bin/ots"))
CHECKPOINT = os.path.join(DIR, "tuscolo_checkpoint.txt")   # pinned full checkpoint
OTS_PROOF  = os.path.join(DIR, "tuscolo_notebody.txt.ots") # OTS proof over the note body

KEY_NAME = "markovianprotocol.com/bitcoin-anchor"
SIG_TYPE = 0xff                                            # "unassigned signature type" per signed-note
IDENTIFIER = b"markovianprotocol.com/bitcoin-anchor/ots/v1"  # collision-resistant long id after 0xff

SRC = "https://tuscolo2026h2.skylight.geomys.org/checkpoint"


def note_body(raw: bytes) -> bytes:
    """The signed note text: everything up to the last blank line, plus its final newline."""
    return raw.split(b"\n\n", 1)[0] + b"\n"


def key_id(identifier: bytes) -> bytes:
    """Keyless variant of the signed-note key ID: SHA-256(name || 0x0A || 0xff || identifier)[:4].
    There is no public key -- verification is against Bitcoin, not a configured key -- so the
    identifier stands in for the key material. This is the crux the spec must bless."""
    h = hashlib.sha256(KEY_NAME.encode() + b"\x0a" + bytes([SIG_TYPE]) + identifier).digest()
    return h[:4]


def anchor_line(identifier: bytes, opaque: bytes) -> str:
    """A signed-note line under our key name: base64(keyID || 0xff || len(id) || id || opaque)."""
    payload = key_id(identifier) + bytes([SIG_TYPE, len(identifier)]) + identifier + opaque
    return f"— {KEY_NAME} {base64.b64encode(payload).decode()}"


def grease_line(seed=None) -> str:
    """GREASE: a well-formed anchor line under our key name but with an UNKNOWN, future identifier
    and random opaque bytes. It commits nothing and verifies to nothing. Its only job is to force
    every verifier of our format to *ignore* anchor identifiers it doesn't implement -- keeping the
    forward-compatibility path warm for future anchor versions and chains, exactly as Sunlight's
    grease.invalid line does for signed-note. A conformant Markovian verifier MUST skip this line,
    not reject the checkpoint."""
    r = random.Random(seed) if seed is not None else random.SystemRandom()
    ident = ("markovianprotocol.com/bitcoin-anchor/GREASE/" +
             "".join(r.choice("0123456789abcdef") for _ in range(16))).encode()
    opaque = bytes(r.randrange(256) for _ in range(r.randrange(16, 80)))
    return anchor_line(ident, opaque)


def main():
    raw = open(CHECKPOINT, "rb").read()
    body = note_body(raw)
    body_hash = hashlib.sha256(body).hexdigest()
    ots_bytes = open(OTS_PROOF, "rb").read()

    # Sanity: the OTS proof must commit exactly this note body's sha256.
    info = subprocess.run([OTS, "info", OTS_PROOF], capture_output=True, text=True).stdout
    assert body_hash in info, f"OTS proof does not commit this checkpoint's note body\n{info}"
    confirmed = "bitcoin block" in info.lower()

    # The real anchor line: keyID(4) || 0xff || len(id) || id || OTS proof, self-contained.
    real_line = anchor_line(IDENTIFIER, ots_bytes)

    # GREASE our own namespace: emit a second anchor line with an unknown future identifier, and
    # shuffle the appended lines so nothing downstream can depend on order (per Sunlight's practice).
    seed = int(os.environ.get("GREASE_SEED", "0")) or None   # fixed seed for reproducible vectors
    appended = [real_line, grease_line(seed)]
    (random.Random(seed) if seed is not None else random.SystemRandom()).shuffle(appended)

    # Augmented checkpoint = the original, unchanged, with our lines appended after the log's sigs.
    augmented = raw if raw.endswith(b"\n") else raw + b"\n"
    augmented += ("".join(l + "\n" for l in appended)).encode()
    open(os.path.join(DIR, "tuscolo_checkpoint.anchored.txt"), "wb").write(augmented)

    origin, size, root = body.decode().splitlines()[:3]
    artifact = {
        "_what": "A live Geomys Tuscolo CT checkpoint, Bitcoin-anchored by Markovian",
        "_why": ("The log's signatures prove WHO issued this tree head and that it is consistent. "
                 "The anchor proves WHEN it existed, on Bitcoin, a clock the log operator does not "
                 "control. The anchor rides as an ordinary signed-note signature line under the 0xff "
                 "unassigned type, so the checkpoint still verifies in stock tooling (unknown "
                 "signatures MUST be ignored) while gaining offline, permissionless existence proof."),
        "source_checkpoint_url": SRC,
        "checkpoint": {"origin": origin, "tree_size": int(size), "root_hash": root},
        "committed": {"over": "checkpoint note body (origin, size, root hash)",
                      "hash_alg": "sha256", "value_hex": body_hash,
                      "note": "identical bytes the log's own signature signs; no re-serialization"},
        "anchor": {
            "type": "opentimestamps",
            "signed_note_key_name": KEY_NAME,
            "signed_note_sig_type": "0xff",
            "identifier": IDENTIFIER.decode(),
            "anchor_line": real_line,
            "grease": "a second anchor line with an unknown identifier is appended; verifiers MUST ignore it",
            "proof_ots_b64": base64.b64encode(ots_bytes).decode(),
            "status": "bitcoin-confirmed" if confirmed else "pending",
            "anchoredAt": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
            "note": ("Verify offline with stock `ots`. Pending upgrades to Bitcoin-confirmed in ~1 "
                     "block via `ots upgrade`."),
        },
    }
    open(os.path.join(DIR, "tuscolo_anchored.json"), "w").write(json.dumps(artifact, indent=2))

    print("checkpoint :", origin, "size", size)
    print("note body sha256 :", body_hash)
    print("anchor status    :", artifact["anchor"]["status"])
    print("wrote            : tuscolo_checkpoint.anchored.txt  (his checkpoint + our stamp line)")
    print("wrote            : tuscolo_anchored.json            (full artifact)")
    print("appended lines   : 1 real anchor + 1 grease (unknown id), shuffled")
    print("\n--- the stamp line (rides next to his 'grease.invalid' line) ---")
    print(real_line[:120] + " ...")


if __name__ == "__main__":
    main()
