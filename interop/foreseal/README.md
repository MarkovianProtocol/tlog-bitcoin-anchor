# ForeSeal ⇄ tlog-bitcoin-anchor interop

*Contributed by BYTEDev, Inc. (PayPerByte / ForeSeal) under this repository's MIT licence. The
linked source repo is separately Apache-2.0 with an AGPL-3.0 carve-out for one vendored upstream
checker; that licensing applies there, not to these files. Assembled with AI assistance under
human review.*

What an x402 data receipt looks like when it reaches this repo's anchoring path, and the exact
bytes to stamp.

The two sides compose without either trusting the other:

- **ForeSeal side** — an EIP-712 attestation over the exact bytes a paid endpoint served.
  Verifiable offline: recompute keccak256 over the wire bytes, recover the signer, compare to the
  address the receipt names. No call back to the server.
- **This repo's side** — existence-in-time for that signed instance. Verifiable offline against
  Bitcoin headers, with no live party.

Neither says the underlying data is *correct*. That is a separate primitive and out of scope for
both.

## `payperbyte.io/x402-anchor/receipt/v2-sig`

The stamped preimage is a defined file format rather than a bare digest, because `ots stamp` takes
files: hand a stamper a hex value and the natural move is to write that hex into a file and stamp
it, which commits `SHA-256(the ASCII hex)` instead of the value you meant. A format removes the
ambiguity — the stamp commits to the format, not to an ASCII accident.

Exactly four LF-terminated lines, no blank lines, no trailing content:

```
payperbyte.io/x402-anchor/receipt/v2-sig
tier=<delivery|provenance>
digest=0x<eip712_digest, 32 bytes hex>
signer=0x<EIP-55 address the receipt recovers to>
```

**The signature is not in the preimage.** That is the point, and it mirrors this repo's
`rootcommit/v2-sig`: commit the *signer*, carry the *signature* alongside. Splitting them means a
third party can check existence-in-time without trusting our key, and check our key without
re-deriving the anchor. An earlier draft of ours fused `SHA-256(digest ‖ sig)`; separating them is
the better property. This follows `rootcommit/SPEC_SIG.md` in this repository. The tag is ours, on
a domain we control, per the `domain/purpose/object/version` convention in `rootcommit/SPEC.md`.

One difference from `rootcommit/v2-sig` worth naming: your signature covers the *commitment*, so
every preimage line is cryptographically bound. Ours covers only `digest`, so `tier=` is an
unsigned annotation — a valid `(digest, signer, signature)` triple relabelled to the other tier
would still recover. It is inert in practice, since the EIP-712 digest already uniquely identifies
which tier it belongs to and `verify_preimage.py` binds tier to digest through the manifest, but it
is a real asymmetry rather than a hidden one.

The "who" layer needs no new signature: the receipt's own EIP-712 `PayloadAttestation` signature
already recovers to `signer`, and travels in `manifest.json` beside the preimage.

There is no `domain=` line because the EIP-712 digest already commits to the full domain separator
(name, version, chainId, verifyingContract) — the domain is inside `digest`, not lost. For the
record, and because it is the kind of thing that should never be implicit: that domain is
`eip155:421614`, **Arbitrum Sepolia** — a frozen, pre-audit *signing namespace*, deliberately not a
settlement rail. The USDC settlement in the same receipt is **Base mainnet** (`eip155:8453`). The
two chain IDs differ on purpose.

The commitment is **SHA-256 over exactly those bytes**:

```
ots stamp delivery.preimage.bin
ots info  delivery.preimage.bin.ots   # first line: File sha256 hash: <commitment, without the 0x>
```

## What is committed here

Both attestation tiers of one real paid x402 call — a `$0.10` request whose settlement is a real
Base-mainnet transaction, and whose subject is an address we control: our own payout Safe, which
is the `payTo` in that same settlement. So no third party's data is in it.

| file | tier | signed payload | commitment (SHA-256 of the preimage) |
|---|---|---|---|
| `delivery.preimage.bin` | delivery | the entire response body, 2682 B | `0x414266f6…29fc1260` |
| `provenance.preimage.bin` | provenance | the `answer` slice, 2095 B | `0x27591056…57daaeb6` |

Two tiers because one response carries two attestations under the same frozen domain, over
different byte ranges and **signed by different keys** — the paid endpoint over the whole body,
and the publishing key over the `answer` slice. The publishing key is not the payment-recipient
key. (We do not claim the two keys are independently controlled; binding either recovered address
to a named role is out-of-band.)

`manifest.json` carries the digests, the recovered signers, the source capture and its SHA-256,
and the settlement transaction.

## Checking it

```
python3 verify_preimage.py     # stdlib only — no network, no node, no calendar
```

That asserts the files parse as `payperbyte.io/x402-anchor/receipt/v2-sig`, that SHA-256 over the
exact file bytes equals the committed value, and that the tier, digest and signer lines are well
formed and agree with `manifest.json`. There is no signature line in the preimage — that is the
point of the format — so the manifest's signature is checked only for presence and shape.

Two limits worth stating rather than discovering. It does not validate the signer's EIP-55
checksum, and it does not recover the signature to `signer`: both need keccak256 / secp256k1, which
are not in the standard library. A preimage emitted with a non-checksummed signer would pass here,
because the commitment is computed from the file and therefore always agrees with a consistently
emitted file — the hash check catches tampering after emission, not a preimage that was
spec-violating when written. Recovery in the source repo is what catches that.

Signer recovery, the adversarial cases, and the cross-language vectors live in the source repo:

**https://github.com/0rkz/foreseal-x402-conformance** (that repo is Apache-2.0, with one vendored
upstream checker that stays AGPL-3.0 — see its `NOTICE`)

```
npm install
npm run verify           # both eip712 digests + both anchor_input values
npm run anchor:preimage  # both preimage-file COMMITMENTS — the values stamped here
npm run vector           # 9 cases, TypeScript

python3 -m venv .venv && . .venv/bin/activate   # Debian/Ubuntu/Homebrew pythons are PEP-668 managed
pip install -r requirements.txt
npm run vector:py        # the same 9 cases, Python — cross-impl parity
```

Two different values, deliberately not conflated: `anchor_input` is `SHA-256(digest ‖ signature)`,
the superseded fused form, retained in that repo for lineage; the **commitment** here is `SHA-256`
over the v2-sig preimage *file bytes* and is what `ots stamp` commits to and what `manifest.json`
binds.

Those include a forked-domain case showing the signature is bound to the chainId rather than
string-compared, and tamper cases on both tiers. Note the capture's short freshness deadline has
long passed, so `verify` reports it expired and prints `PROVENANCE HOLDS` — provenance is
timeless, the deadline is a policy for acting on a verdict live, and anchoring is precisely what
makes the timeless half durably checkable afterwards. That is why this directory exists.

## Trust boundaries

| component | trusted for | NOT trusted for |
|---|---|---|
| `manifest.json` | naming which bytes were stamped and what their commitments are | binding those bytes to the receipt — it is unsigned and ships in this same directory, so it is our word alongside our files |
| the ForeSeal EIP-712 signature (in `manifest.json`) | that the key named in `signer` signed that receipt — recover it and compare | that the data in the response is correct |
| `verify_preimage.py` | that the `.bin` files are self-consistent with `manifest.json` | anything about the receipt itself, or about existence-in-time |
| this repo's anchor | existence-in-time for the committed value | any statement about the receipt's contents |

To cross the first boundary — bind these bytes to the actual receipt rather than to our manifest —
fetch `fixtures/live-receipt.json` from the source repo and recover the EIP-712 signers.

## Reproducing the preimages

Emitted from the receipt by two independent implementations that must agree byte-for-byte
(`src/anchorPreimage.ts` and `conformance/anchor_preimage.py` in the source repo):

```
npm run anchor:preimage -- out/                       # TypeScript
python3 conformance/anchor_preimage.py --write out2/  # Python
cmp out/delivery.preimage.bin out2/delivery.preimage.bin
sha256sum out/*.preimage.bin
```

## Not claimed here

No `.ots` proof is included. These are the preimages; the anchoring is this repo's leg. Nothing on
the ForeSeal side asserts a Bitcoin timestamp or an inclusion proof, and the ForeSeal OTS
integration is a sketch rather than a deployed feature.
