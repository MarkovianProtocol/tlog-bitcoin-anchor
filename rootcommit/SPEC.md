# rootcommit/v1 — Bitcoin anchor over (Merkle root + operator wallet)

A stronger variant of the `tlog-bitcoin-anchor` `ots/v1` fixture. Where `ots/v1` timestamps the
checkpoint **note body**, `rootcommit/v1` timestamps a **domain-separated preimage** that folds the
checkpoint's Merkle root together with an operator **wallet address**, so the Bitcoin attestation
commits to `(root, wallet)` jointly. Mutating either the root or the wallet breaks the binding.

## What it proves, and what it does not

- **Proves:** *what* (the exact tree head / root), *when* (Bitcoin block time, un-backdatable),
  and that a **named wallet was committed alongside that root** at that time. Verifiable offline
  with the stock `ots` client + SHA-256, trusting no operator.
- **Does not prove:** that the wallet *owner endorsed* the root. Putting an address in a preimage
  is provenance chosen by the anchorer, not a key signature. It also does not prove the root is a
  correct tree head of anything real.
- **Offered next increment (`rootcommit/v2-sig`):** the wallet's ECDSA signature over this same
  commitment, recoverable to the address — which upgrades "the address was committed" to "the
  wallet's key attested to this root at this time."

## Preimage — frozen byte layout

Five LF-terminated (`\n`) ASCII lines, in this exact order, with a trailing `\n`:

```
markovianprotocol.com/bitcoin-anchor/rootcommit/v1
origin=<checkpoint origin line, verbatim>
size=<checkpoint tree size, decimal>
root=<checkpoint 3rd line, verbatim base64 — NOT decoded/re-encoded>
wallet=<EIP-55 checksummed 0x-address>
```

`commitment = SHA-256(preimage_bytes)`. The OpenTimestamps proof commits `commitment`.
`root=` is copied byte-for-byte from the checkpoint's third line (no base64 round-trip, so there is
one and only one input byte form). `wallet=` is the EIP-55 mixed-case checksum form.

## Anchor line — self-contained on the checkpoint

Rides as an ordinary `c2sp.org/signed-note` line under the `0xff` unassigned signature type, so a
checkpoint carrying it still verifies in stock tooling (unknown signatures MUST be ignored):

```
— markovianprotocol.com/bitcoin-anchor  base64( keyID(4) || 0xff || len(id) || id || opaque )
keyID  = SHA-256( "markovianprotocol.com/bitcoin-anchor" || 0x0A || 0xff || id )[:4]
id     = "markovianprotocol.com/bitcoin-anchor/rootcommit/v1"
opaque = version(1)=0x01 || wlen(1) || wallet_ascii[wlen] || ots_proof_bytes
```

The wallet is carried in the opaque, so a verifier reconstructs the preimage from the checkpoint's
own `(origin, size, root)` plus this `wallet`, with nothing external.

## Verify (any implementation)

1. Parse the anchor line; confirm `keyID`, `0xff`, and the `rootcommit/v1` id. Unknown ids → ignore.
2. Read `wallet` and `ots_proof_bytes` from the opaque.
3. Rebuild `preimage` from `(origin, size, root, wallet)`; check the OTS proof commits
   `SHA-256(preimage)` (`ots info`).
4. Check the OTS proof lands in a Bitcoin block (or PENDING).
5. Negative: mutate the root → binding must fail. Mutate the wallet → binding must fail.

## Conformance vectors (`vectors/`, `manifest.json`)

| File | Expect |
|---|---|
| `rootcommit-01-valid.txt` | known=1, binding ok, no reject |
| `rootcommit-02-tampered-root.txt` | binding fails, reject |
| `rootcommit-03-tampered-wallet.txt` | binding fails, reject *(the property `ots/v1` does not have)* |
| `rootcommit-04-tampered-proof.txt` | binding fails, reject |

`run_rootcommit_vectors.py` asserts each outcome (exit non-zero on any deviation).

## Reference run (Neo, this build)

```
checkpoint : markovianprotocol.com/log  size 1387
wallet     : 0xdaE76a3C848CafD453dB5EBF8cEb0DbBA7610273   (Agent 3, operated by Markovian)
preimage sha256 : 4d1cc236c3872701bb27f9e27fad315e153eeb43a767a2cae958a3bb4014e771
[2] Binding : PASS    [4] Root check: PASS    [5] Wallet check: PASS
[3] Temporal: PENDING → upgrades to a Bitcoin block; `ots upgrade` freezes the height.
```
