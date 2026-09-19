package ots

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strconv"
	"testing"
)

func TestTuscoloProof(t *testing.T) {
	proof, err := os.ReadFile("../../tuscolo_notebody.txt.ots")
	if err != nil {
		t.Skip("no fixture")
	}
	body, err := os.ReadFile("../../tuscolo_notebody.txt")
	if err != nil {
		t.Skip("no fixture")
	}
	d := sha256.Sum256(body)
	p, err := Verify(proof, d[:])
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("file digest %s (%s)", hex.EncodeToString(p.FileDigest), p.HashOp)
	for _, a := range p.Attestations {
		t.Logf("attestation kind=%s height=%d merkleroot(display)=%s uri=%s", a.Kind, a.Height, a.MerkleRootHex(), a.URI)
	}
	if _, ok := p.Bitcoin(); !ok {
		t.Fatalf("no bitcoin attestation")
	}
}

func TestWrongDigestRejected(t *testing.T) {
	proof, err := os.ReadFile("../../tuscolo_notebody.txt.ots")
	if err != nil {
		t.Skip("no fixture")
	}
	if _, err := Verify(proof, make([]byte, 32)); err == nil {
		t.Fatal("accepted a proof for a different digest")
	}
}

func TestTamperedProofRejected(t *testing.T) {
	proof, err := os.ReadFile("../../tuscolo_notebody.txt.ots")
	if err != nil {
		t.Skip("no fixture")
	}
	body, _ := os.ReadFile("../../tuscolo_notebody.txt")
	d := sha256.Sum256(body)
	good, err := Verify(proof, d[:])
	if err != nil {
		t.Fatal(err)
	}
	for i := 60; i < len(proof)-1; i += 137 {
		bad := append([]byte(nil), proof...)
		bad[i] ^= 0x01
		p, err := Verify(bad, d[:])
		if err != nil {
			continue // rejected outright, fine
		}
		if fingerprint(p) == fingerprint(good) {
			t.Fatalf("byte %d flipped and every attestation stayed the same", i)
		}
	}
}

func fingerprint(p *Proof) string {
	s := ""
	for _, a := range p.Attestations {
		s += a.Kind + ":" + itoa(a.Height) + ":" + a.MerkleRootHex() + ":" + a.URI + "|"
	}
	return s
}

func itoa(u uint64) string { return strconv.FormatUint(u, 10) }

// TestPinnedAnchor pins the one worked instance: the Tuscolo note body's proof
// commits to block 957350, whose Merkle root is fcaeee72...db3b on the chain
// (checked against mempool.space when this test was written, 2026-09-18).
func TestPinnedAnchor(t *testing.T) {
	proof, err := os.ReadFile("../../tuscolo_notebody.txt.ots")
	if err != nil {
		t.Skip("no fixture")
	}
	body, err := os.ReadFile("../../tuscolo_notebody.txt")
	if err != nil {
		t.Skip("no fixture")
	}
	d := sha256.Sum256(body)
	p, err := Verify(proof, d[:])
	if err != nil {
		t.Fatal(err)
	}
	b, ok := p.Bitcoin()
	if !ok {
		t.Fatal("no bitcoin attestation")
	}
	if b.Height != 957350 {
		t.Errorf("height = %d, want 957350", b.Height)
	}
	const want = "fcaeee72588400b910a53d0fbbb6d4d8c671045d9f450636a89f9338670cdb3b"
	if got := b.MerkleRootHex(); got != want {
		t.Errorf("merkle root = %s, want %s", got, want)
	}
}
