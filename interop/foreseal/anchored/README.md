# Anchored instance — leaves 7511 and 7512

The parent directory defines the `payperbyte.io/x402-anchor/receipt/v2-sig` format and ships an
example receipt's preimages. This directory ships the first **anchored** instance: the same format,
minted from the live rail with a ~10-year deadline on both tiers, whose commitments are in this
repository's own log with Bitcoin coverage.

- `sha256(delivery.preimage.bin)` = leaf **7511** of `markovianprotocol.com/log`
- `sha256(provenance.preimage.bin)` = leaf **7512**
- Both covered by the witnessed checkpoint at tree size **7513**, whose exact bytes carry the
  OpenTimestamps proof `/anchor/7513.ots`, upgraded to Bitcoin blocks 963257 / 963258 / 963260.

`manifest.json` here uses the same schema as the parent, plus an `anchoring` section recording
what was verified and what was not. Everything below is checkable without either party's
infrastructure.

## Verify

```sh
# 1. Commitments are the file bytes (compare to the sha256 inside each leaf statement)
sha256sum delivery.preimage.bin provenance.preimage.bin
curl -s https://log.markovianprotocol.com/leaf/7511 ; echo
curl -s https://log.markovianprotocol.com/leaf/7512 ; echo

# 2. Format + manifest binding (same checker as the parent directory)
cp ../verify_preimage.py . && python3 verify_preimage.py

# 3. Inclusion to the checkpoint at size 7513: c2sp.org/tlog-proof bundles
curl -s "https://log.markovianprotocol.com/proof/7511" -o proof-7511.bundle
curl -s "https://log.markovianprotocol.com/proof/7512" -o proof-7512.bundle

# 4. The stamped bytes are the checkpoint, and the stamp reaches Bitcoin
curl -s https://log.markovianprotocol.com/anchor/7513.checkpoint -o 7513.checkpoint
sha256sum 7513.checkpoint          # equals the file hash inside the .ots
curl -s https://log.markovianprotocol.com/anchor/7513.ots -o 7513.ots
ots info 7513.ots                  # BitcoinBlockHeaderAttestation(963257 / 963258 / 963260)
```

The EIP-712 leg is unchanged from the parent README: recover each tier's `signature` over its
`digest` and compare to `signer`. The delivery signer is the **current** gateway attester —
this receipt postdates the 2026-08-19 key rotation disclosed at
`x402.payperbyte.io/.well-known/agent.json → receipt.retiredAttesters`; the parent directory's
delivery preimage predates it and recovers to the retired key. Both are genuine, on opposite
sides of a published boundary — which is itself the point of pairing rotation disclosure with
existence-in-time.

Scope, unchanged: the anchor shows the signed receipt existed before a point in time; the
signature shows which key signed which bytes; neither says the underlying data is correct.
