# Transparency Log Bitcoin Anchors

Draft, proposed for https://c2sp.org/tlog-bitcoin-anchor

A Bitcoin anchor is a statement that a [checkpoint][] existed at or before a
given point in time, proven by committing the checkpoint to the Bitcoin
blockchain via [OpenTimestamps][]. Unlike a [cosignature][], an anchor makes
**no statement about consistency**: it asserts *existence in time*, not that the
log operated append-only. Its distinguishing property is that verification
requires **no configured key and no live party** — only Bitcoin block headers,
which are public, un-curated, and reconstructable offline indefinitely.

Below is a checkpoint carrying a Bitcoin anchor, alongside the log's own
signature.

```
tuscolo2026h2.sunlight.geomys.org
207536013
gjLY/Kb0aNy8Kh4IKR6DpGW7NlhemGD71nzjtKJyrDM=

— tuscolo2026h2.sunlight.geomys.org a24oV86Dsdcq+408FqEWIyUAoTfnfrRzbf8RCVZUeyp6icLc8HdVTGERZJNNMTp2RVyCBpWnVrHmmw==
— markovianprotocol.com/bitcoin-anchor N0adxf8rbWFya292aWFucHJvdG9jb2wuY29tL2JpdGNvaW4tYW5jaG9yL290cy92MQBPc+…
```

An anchor is applied as an ordinary [signed note][] signature line. Per
[tlog-checkpoint][], clients that do not implement this specification MUST
ignore the anchor line, exactly as they ignore any unknown signature. An anchor
is therefore always safe to add to an existing checkpoint: the log's signatures
and any cosignatures are unaffected.

## Conventions used in this document

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

## Format

An anchor is a [note signature][] applied to a [checkpoint][], using the `0xff`
unassigned signature type reserved by [signed-note][].

The key name SHOULD be a schema-less URL identifying the anchoring party. This
document uses `markovianprotocol.com/bitcoin-anchor`.

Because an anchor has no signing key, the key ID is derived from the anchor's
identifier in place of public key material:

    key ID = SHA-256(<key name> || 0x0A || 0xff || <identifier>)[:4]

where `<identifier>` is the ASCII string `markovianprotocol.com/bitcoin-anchor/ots/v1`.

The signature bytes carried in the note signature line (before base64 encoding)
are:

    key ID (4 bytes) || 0xff || uint8 identifier_length || identifier || ots_proof

`ots_proof` is a serialized [OpenTimestamps][] proof whose committed digest is
the SHA-256 of the checkpoint's **note body** — that is, the origin, tree size,
and root hash lines up to but not including the separating blank line, exactly as
signed per [tlog-checkpoint][]. Embedding the proof inline makes the anchored
checkpoint self-contained: it can be verified with no side channel.

An anchor MUST NOT be included in the note body of a checkpoint, and MUST NOT be
covered by any log signature or cosignature; it is purely additive.

## Forward compatibility

A checkpoint MAY carry more than one anchor line under the same key name. A
verifier MUST match anchors by their full identifier and MUST ignore any anchor
line whose identifier it does not implement, rather than rejecting the
checkpoint. Producers SHOULD emit, in addition to any real anchor, a "grease"
anchor line carrying an unknown identifier and random opaque bytes, so that the
ignore path is continuously exercised and future anchor identifiers (new proof
formats or chains) remain deployable without breaking existing verifiers. The
relative order of anchor lines is not significant and SHOULD be randomized.

## Verification

Inputs:

* a checkpoint carrying one or more anchor lines
* the set of Bitcoin block headers (which MAY be held offline)

Output: for each anchor line whose identifier is implemented, either a verified
anchoring time, or a verification failure. Anchor lines with unimplemented
identifiers are ignored.

A verifier that implements this specification MUST, for an anchor line on a
checkpoint:

1. Decode the signature bytes and confirm the key ID, `0xff` type byte, and
   identifier match a supported anchor identifier. Unknown identifiers MUST be
   ignored, not rejected.
2. Recompute the SHA-256 of the checkpoint's note body and confirm the embedded
   OpenTimestamps proof commits exactly that digest.
3. Verify the OpenTimestamps proof against a Bitcoin block header. The anchor's
   asserted time is the Bitcoin block's timestamp.

Verification MUST NOT require contacting the log, the anchoring party, any
witness, or any OpenTimestamps calendar. A verifier needs only the checkpoint,
the inline proof, and Bitcoin block headers, all of which MAY be held offline.

A proof that has been submitted to OpenTimestamps calendars but not yet confirmed
in a Bitcoin block is *pending*. A pending anchor asserts nothing verifiable and
MUST NOT be accepted as a completed anchor; it becomes verifiable once upgraded
with a Bitcoin attestation.

## Semantics

A v1 Bitcoin anchor is a statement that the tree head identified by the
checkpoint's note body existed at or before the anchoring Bitcoin block, and that
it cannot have been fabricated after that block. It is **not** a statement of
append-only operation or of consistency with any other checkpoint.

Non-equivocation is obtained differently than under [tlog-cosignature][]. A
cosigner refuses to sign a checkpoint inconsistent with its observed history,
preventing a split view at signing time among a configured witness set. A Bitcoin
anchor instead makes equivocation **publicly and permanently detectable**: two
conflicting tree heads anchored under the same origin are both visible on a ledger
no party curates, and either can be produced years later by any auditor. Anchoring
and cosigning are complementary and MAY both be applied to the same checkpoint.

## Security considerations

The asserted time has the granularity and adversarial properties of a Bitcoin
block timestamp, which is not the exact time the tree head was produced but an
upper bound on its existence that cannot be backdated.

Verification trusts the Bitcoin proof-of-work consensus rather than a configured
key or witness quorum. This removes any curated trust set and any dependence on
key rotation or party liveness over time, at the cost of a dependency on the
Bitcoin blockchain. Deployments for which that dependency is unacceptable SHOULD
use [tlog-cosignature][] instead of, or in addition to, anchoring.

An anchor does not authenticate *who* produced the checkpoint. The log's own
signature and any cosignatures continue to provide that property unchanged.

## Test vectors

A conformance corpus is provided alongside this document in `vectors/`, each
case a checkpoint file with the documented expected outcome in `manifest.json`:

* `01-valid` — a real anchor plus a grease line; the known anchor verifies, the
  grease line is ignored.
* `02-unknown-id` — only an unknown-identifier anchor; MUST be ignored, MUST NOT
  cause rejection (forward compatibility).
* `03-tampered-body` — the checkpoint's root hash is altered so the note body no
  longer matches the proof; binding MUST fail.
* `04-tampered-proof` — the committed digest in the proof is corrupted; binding
  MUST fail.

An independent implementation is conformant if it reproduces these outcomes. A
non-production reference verifier is provided.

[checkpoint]: https://c2sp.org/tlog-checkpoint
[signed note]: https://c2sp.org/signed-note
[note signature]: https://c2sp.org/signed-note#signatures
[cosignature]: https://c2sp.org/tlog-cosignature
[tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-cosignature]: https://c2sp.org/tlog-cosignature
[OpenTimestamps]: https://opentimestamps.org/
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
