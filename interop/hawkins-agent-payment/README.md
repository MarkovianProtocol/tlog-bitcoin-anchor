# Scope-shaped statement, registered and witnessed

A conformance example for draft-hawkins-scitt-attested-agent-payment-00,
registered as leaf 7235 of the Markovian transparency log. The statement
carries the draft's six Authorization Scope members (apk, code, limits,
expiry, rails, payees) and declares in its own body that it carries no
payment authority. apk is a computed RFC 9679 COSE Key Thumbprint over a
throwaway Ed25519 key. Encoding is RFC 8785 canonical JSON — a declared
deviation from the draft's CBOR map.

Verify (Python 3 stdlib only, public endpoints only):

    python3 verify_claim_leaf.py scope_receipt_7235.json

The verifier recomputes the leaf hash, re-derives the RFC 6962 inclusion
fold against the current witnessed checkpoint, and lists the independent
witnesses whose cosignatures the checkpoint carries. At registration the
tree was 7236 leaves with 7 of 7 witnesses cosigning.

Scope of the claim: existence and witnessed order of the canonical bytes.
Nothing about whether any attested software is correct, whether the key is
hardware-bound, or whether limits are honored.
