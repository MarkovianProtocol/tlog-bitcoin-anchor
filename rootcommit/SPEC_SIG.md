# rootcommit/v2-sig — wallet ECDSA attestation over the anchored commitment

The signed layer on top of `rootcommit/v1`. Same committed preimage, same Bitcoin anchor; this adds
the **wallet's own signature** over that commitment, so the record carries all three of:

- **who** — the wallet's EIP-191 signature, recoverable to its address
- **what** — the Merkle root, inside the timestamped preimage
- **when** — the OpenTimestamps Bitcoin attestation over that same commitment

## Layering (deliberate)

The commitment and its OTS proof are **byte-identical** to `rootcommit/v1`:

```
commitment = SHA-256(preimage)      # preimage = tag / origin= / size= / root= / wallet=
```

`rootcommit/v1` binds the wallet's *address bytes* (anchorer's choice). `rootcommit/v2-sig` adds a
signature by that wallet's key over `commitment`, upgrading "the address was committed" to "the
wallet's key attested." The two share one Bitcoin anchor — v2-sig is strictly v2 plus a signature.

## The signature

EIP-191 `personal_sign` (secp256k1), over a frozen message:

```
message = "markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig" + "\n" + commitment_hex
```

Verify by `ecrecover(message, sig) == wallet`. 65-byte `r||s||v`. No transaction; nothing on-chain
is spent or changed — this is an off-chain attestation the address makes about a log root.

## Anchor line opaque

```
id     = "markovianprotocol.com/bitcoin-anchor/rootcommit/v2-sig"
opaque = version(1)=0x02 || wlen(1) || wallet_ascii || 0x41 || sig(65) || ots_proof_bytes
```

Self-contained: a verifier reads `wallet`, `sig`, and the OTS proof from the line, reconstructs the
preimage from the checkpoint's own `(origin, size, root)`, and checks binding, Bitcoin, and signature.

## Verify (any implementation)

1. Parse; confirm id and `0x02` opaque version. Unknown → ignore.
2. Rebuild preimage from `(origin, size, root, wallet)`; `commitment = SHA-256(preimage)`.
3. Binding: OTS proof commits `commitment` (`ots info`).
4. Temporal: OTS lands in a Bitcoin block (or PENDING).
5. Signature: `ecrecover(message(commitment), sig) == wallet`.
6. Negatives: mutate root → binding breaks; mutate signature → recovery no longer matches wallet.

## Vectors (`vectors_sig/`, `manifest.json`)

| File | Expect |
|---|---|
| `v2sig-01-valid.txt` | binding ok, sig ok, no reject |
| `v2sig-02-tampered-root.txt` | binding fails, reject |
| `v2sig-03-tampered-wallet.txt` | binding fails, reject |
| `v2sig-04-tampered-sig.txt` | sig fails, reject *(property v2 does not have)* |
| `v2sig-05-tampered-proof.txt` | binding fails, reject |

## Scope

Proves *who* committed, to *what* root, at a Bitcoin-set *when*, on a record no operator can rewrite.
It does **not** prove the root is a correct tree head of anything real, nor that any figure behind it
is true. Attestation and provenance, not audit.

## Reference run (Neo, this build)

```
checkpoint : markovianprotocol.com/log  size 1387
wallet     : 0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273   (Agent 3, ERC-8004 agentId 59327, operated by Markovian)
commitment : 4d1cc236c3872701bb27f9e27fad315e153eeb43a767a2cae958a3bb4014e771
[2] Binding: PASS   [4] Signature: PASS (recover == wallet)   [5] Root chk: PASS   [6] Sig chk: PASS
[3] Temporal: PENDING → `ots upgrade` freezes the Bitcoin block height.
```
