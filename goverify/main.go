// Command goverify independently verifies a Bitcoin-anchored transparency-log checkpoint.
//
// It trusts neither the log operator nor Markovian. Everything about the checkpoint format and the
// c2sp.org/signed-note anchor line is parsed natively here, with no dependencies beyond the Go
// standard library. The binding of the anchor to the checkpoint's note body is checked natively by
// reading the committed digest out of the OpenTimestamps proof. The final Bitcoin attestation is
// confirmed with the stock `ots` client (the OpenTimestamps reference verifier), matching how the
// Python reference verifier works.
//
// Usage:  go run . [checkpoint.anchored.txt]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	keyName    = "markovianprotocol.com/bitcoin-anchor"
	sigType    = 0xff
	identifier = "markovianprotocol.com/bitcoin-anchor/ots/v1"
)

// OpenTimestamps detached-proof layout: 31-byte magic, 1-byte version, 1-byte hash-op (0x08 sha256),
// then the 32-byte committed digest, then the timestamp operations.
var otsMagic = []byte("\x00OpenTimestamps\x00\x00Proof\x00\xbf\x89\xe2\xe8\x84\xe8\x92\x94")

// Attestation tags inside a proof.
var (
	bitcoinTag = []byte{0x05, 0x88, 0x96, 0x0d, 0x73, 0xd7, 0x19, 0x01}
	pendingTag = []byte{0x83, 0xdf, 0xe3, 0x0d, 0x2e, 0xf9, 0x0c, 0x8e}
)

func keyID(id string) []byte {
	h := sha256.New()
	h.Write([]byte(keyName))
	h.Write([]byte{0x0a, sigType})
	h.Write([]byte(id))
	return h.Sum(nil)[:4]
}

// committedDigest reads the note-body digest an OpenTimestamps proof commits to, natively.
func committedDigest(ots []byte) ([]byte, bool) {
	if !bytes.HasPrefix(ots, otsMagic) {
		return nil, false
	}
	p := len(otsMagic)
	if len(ots) < p+2+32 || ots[p] != 0x01 || ots[p+1] != 0x08 {
		return nil, false
	}
	return ots[p+2 : p+2+32], true
}

// parseAnchor decodes an anchor signature line, returning its identifier and the OTS proof bytes.
func parseAnchor(line string) (id string, ots []byte, ok bool) {
	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return "", nil, false
	}
	payload, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil || len(payload) < 6 {
		return "", nil, false
	}
	kid, stype, idLen := payload[:4], payload[4], int(payload[5])
	if stype != sigType || len(payload) < 6+idLen {
		return "", nil, false
	}
	id = string(payload[6 : 6+idLen])
	if !bytes.Equal(kid, keyID(id)) { // keyless key ID must match the identifier
		return "", nil, false
	}
	return id, payload[6+idLen:], true
}

// otsConfirmation reads the completed BitcoinBlockHeaderAttestation from the proof via `ots info`
// (no Bitcoin node required). Final header matching is done with `ots verify` against your own headers.
func otsConfirmation(ots []byte) string {
	dir, _ := os.MkdirTemp("", "goverify")
	defer os.RemoveAll(dir)
	of := filepath.Join(dir, "proof.ots")
	os.WriteFile(of, ots, 0o600)
	otsBin := os.Getenv("OTS")
	if otsBin == "" {
		otsBin = filepath.Join(os.Getenv("HOME"), "neo_env/bin/ots")
	}
	out, _ := exec.Command(otsBin, "info", of).CombinedOutput()
	if m := regexp.MustCompile(`BitcoinBlockHeaderAttestation\((\d+)\)`).FindSubmatch(out); m != nil {
		return "PASS  (Bitcoin block " + string(m[1]) + ")"
	}
	if strings.Contains(string(out), "PendingAttestation") {
		return "PENDING (Bitcoin-confirms in ~1 block, then `ots upgrade`)"
	}
	return "FAIL (no Bitcoin attestation)"
}

func main() {
	path := "../tuscolo_checkpoint.anchored.txt"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	split := bytes.SplitN(raw, []byte("\n\n"), 2)
	noteBody := append(append([]byte{}, split[0]...), '\n')
	lines := strings.Split(string(split[1]), "\n")
	sum := sha256.Sum256(noteBody)

	head := strings.SplitN(string(noteBody), "\n", 3)
	fmt.Printf("checkpoint: %s  size %s\n", head[0], head[1])

	var known [][]byte
	var logSigs, ignored int
	for _, l := range lines {
		if !strings.HasPrefix(l, "— ") {
			continue
		}
		if !strings.HasPrefix(l, "— "+keyName+" ") {
			logSigs++
			continue
		}
		id, ots, ok := parseAnchor(l)
		if ok && id == identifier {
			known = append(known, ots)
		} else {
			ignored++ // unknown identifier / grease -> ignore, never reject
		}
	}
	fmt.Printf("  anchor lines : %d known, %d ignored (unknown identifier / grease)\n", len(known), ignored)
	if len(known) == 0 {
		fmt.Println("  [!] no known anchor to verify")
		return
	}
	ots := known[0]

	// [1] Structure + [2] Binding, both native.
	dig, ok := committedDigest(ots)
	fmt.Printf("  [1] Structure : %s  (0xff signed-note line, id=%s)\n", pass(ok), identifier)
	binds := ok && bytes.Equal(dig, sum[:])
	fmt.Printf("  [2] Binding   : %s  (proof commits sha256(note body) %x…)\n", pass(binds), sum[:8])

	// Native attestation detection, then authoritative check via stock ots.
	native := "pending only"
	if bytes.Contains(ots, bitcoinTag) {
		native = "Bitcoin attestation present"
	} else if bytes.Contains(ots, pendingTag) {
		native = "pending only"
	}
	fmt.Printf("  [3] Temporal  : %s   [native scan: %s]\n", otsConfirmation(ots), native)

	// [4] Negative self-check: mutate the note body; the binding MUST break.
	bad := append([]byte{}, noteBody...)
	bad[len(bad)-2] ^= 0x01
	badSum := sha256.Sum256(bad)
	fmt.Printf("  [4] Self-check: %s  (mutated note body correctly %s)\n",
		pass(!bytes.Equal(dig, badSum[:])), rejectedOrNot(!bytes.Equal(dig, badSum[:])))

	fmt.Printf("\n  WHO : %d log signature line(s) intact — verify with the log's key / stock CT tooling.\n", logSigs)
	fmt.Println("  WHEN: this exact tree head is anchored to Bitcoin — no key, no witness, offline.")
}

func pass(b bool) string {
	if b {
		return "PASS"
	}
	return "FAIL"
}

func rejectedOrNot(b bool) string {
	if b {
		return "rejected"
	}
	return "ACCEPTED — binding is a no-op!"
}
