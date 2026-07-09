# Bitcoin-anchored transparency-log checkpoints

A worked example that takes a real [Static Certificate Transparency][static-ct] checkpoint from a
live [Sunlight][] log and anchors it to Bitcoin, so the tree head's existence-in-time is verifiable
by anyone, offline, trusting neither the log operator nor us. The anchor rides as an ordinary
[signed-note][] signature line under the `0xff` unassigned type, so the checkpoint still verifies in
stock tooling — unknown signatures MUST be ignored — while gaining a permissionless timestamp.

The checkpoint used here is a genuine one from `tuscolo2026h2.sunlight.geomys.org`.

```
$ go run . tuscolo_checkpoint.anchored.txt
checkpoint: tuscolo2026h2.sunlight.geomys.org  size 207536013
  anchor lines : 1 known, 1 ignored (unknown identifier / grease)
  [1] Structure : PASS  (0xff signed-note line, id=markovianprotocol.com/bitcoin-anchor/ots/v1)
  [2] Binding   : PASS  (proof commits sha256(note body) 7208a041bc85370d…)
  [3] Temporal  : PASS  (Bitcoin block 957350)   [native scan: Bitcoin attestation present]
  [4] Self-check: PASS  (mutated note body correctly rejected)

  WHO : 4 log signature line(s) intact — verify with the log's key / stock CT tooling.
  WHEN: this exact tree head is anchored to Bitcoin — no key, no witness, offline.
```

## Verify it yourself

Two independent verifiers, one in Go (standard library only) and one in Python. Both do the format
and binding work natively and use the stock [OpenTimestamps][] client for the Bitcoin step.

```
# Go — no dependencies
cd goverify && go run . ../tuscolo_checkpoint.anchored.txt

# Python — needs the stock `ots` client
python3 verify_sunlight_anchor.py tuscolo_checkpoint.anchored.txt

# Conformance corpus (any independent implementation should reproduce these)
python3 run_vectors.py
```

## Trust boundaries

Who and what a verifier has to trust, stated plainly.

| Party | Trusted for | NOT trusted for |
|---|---|---|
| The log operator | its own signature (WHO issued the tree head) | existence-in-time; it cannot backdate an anchor |
| Markovian | nothing | verification never depends on us; we only attached a proof |
| OpenTimestamps calendars | nothing | they may delay or refuse, but cannot forge a Bitcoin confirmation |
| Bitcoin proof-of-work | block existence and timestamp (the only trust root) | — |

A verifier needs only the checkpoint, the proof (which rides inside it), and Bitcoin block headers,
all of which may be held offline. No live log, witness, calendar, or party is contacted.

## What is anchored

The anchor commits the checkpoint's **note body** — the origin, tree size, and root hash lines, the
identical bytes the log's own signature signs. It asserts that this tree head existed at or before a
Bitcoin block, un-backdatable. It does **not** assert consistency or append-only operation; that is
what witness [cosignatures][] provide, and the two compose on the same checkpoint.

## Forward compatibility

Every build also emits a "grease" anchor line: a well-formed line under our key name carrying an
unknown identifier and random bytes. It verifies to nothing. Its only job is to keep the ignore-path
warm, so a verifier that does not skip unknown anchor identifiers fails immediately, in testing,
rather than years later when a new anchor format ships. Anchor-line order is randomized for the same
reason.

## Files

```
tuscolo_checkpoint.txt           the pinned, real checkpoint
tuscolo_checkpoint.anchored.txt  the checkpoint + our anchor line + a grease line
tlog-bitcoin-anchor.md           the format specification
goverify/                        Go reference verifier (stdlib only)
verify_sunlight_anchor.py        Python reference verifier
build_sunlight_anchor.py         produces the anchored checkpoint
vectors/                         conformance corpus + manifest.json
make_vectors.py / run_vectors.py generate and run the corpus
```

## Limitations

- The asserted time has Bitcoin-block granularity — an upper bound on existence, not the exact
  production time.
- Verification depends on the Bitcoin blockchain. Where that dependency is unacceptable, use witness
  [cosignatures][] instead of, or alongside, anchoring.
- An anchor authenticates *when*, not *who*. The log's own signature provides *who*, unchanged.

## References

- [c2sp.org/tlog-checkpoint][signed-note] — the checkpoint / signed-note format this rides on
- [c2sp.org/tlog-cosignature][cosignatures] — the witness cosignature this composes with
- [opentimestamps.org][OpenTimestamps] — the Bitcoin timestamping proof format

[static-ct]: https://c2sp.org/static-ct-api
[Sunlight]: https://sunlight.dev
[signed-note]: https://c2sp.org/signed-note
[cosignatures]: https://c2sp.org/tlog-cosignature
[OpenTimestamps]: https://opentimestamps.org
