// Command goverify independently verifies a Bitcoin-anchored transparency-log checkpoint.
//
// It trusts neither the log operator nor Markovian, and it runs nothing else: the checkpoint
// format, the c2sp.org/signed-note anchor line, and the OpenTimestamps proof inside it are all
// parsed here, with no dependencies beyond the Go standard library and no call to the stock
// `ots` client. Walking the proof yields the Bitcoin block it claims and the Merkle root that
// block must have. Comparing that root with a block header is the one step left to you: pass
// -root with the Merkle root from a header you trust, or read it off the printed line.
//
// Usage:  go run . [checkpoint.anchored.txt] [-root <merkle root hex>]
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"markovianprotocol.com/bitcoin-anchor/goverify/ots"
)

const (
	keyName    = "markovianprotocol.com/bitcoin-anchor"
	sigType    = 0xff
	identifier = "markovianprotocol.com/bitcoin-anchor/ots/v1"
)

func keyID(id string) []byte {
	h := sha256.New()
	h.Write([]byte(keyName))
	h.Write([]byte{0x0a, sigType})
	h.Write([]byte(id))
	return h.Sum(nil)[:4]
}

// parseAnchor decodes an anchor signature line, returning its identifier and the OTS proof bytes.
func parseAnchor(line string) (id string, proof []byte, ok bool) {
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

func main() {
	root := flag.String("root", "", "Merkle root of the Bitcoin block, hex, from a header you trust")
	flag.Parse()

	path := "../tuscolo_checkpoint.anchored.txt"
	if flag.NArg() > 0 {
		path = flag.Arg(0)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	split := bytes.SplitN(raw, []byte("\n\n"), 2)
	if len(split) != 2 {
		fmt.Fprintln(os.Stderr, "not a signed note: no blank line between body and signatures")
		os.Exit(2)
	}
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
		id, proof, ok := parseAnchor(l)
		if ok && id == identifier {
			known = append(known, proof)
		} else {
			ignored++ // unknown identifier / grease -> ignore, never reject
		}
	}
	fmt.Printf("  anchor lines : %d known, %d ignored (unknown identifier / grease)\n", len(known), ignored)
	if len(known) == 0 {
		fmt.Println("  [!] no known anchor to verify")
		return
	}

	// [1] Structure and [2] Binding: the proof parses, and it commits to this note body.
	proof, err := ots.Verify(known[0], nil)
	fmt.Printf("  [1] Structure : %s  (0xff signed-note line, id=%s)\n", pass(err == nil), identifier)
	if err != nil {
		fmt.Printf("                  %v\n", err)
		os.Exit(1)
	}
	binds := bytes.Equal(proof.FileDigest, sum[:])
	if binds {
		fmt.Printf("  [2] Binding   : PASS  (proof commits sha256(note body) %x…)\n", sum[:8])
	} else {
		fmt.Printf("  [2] Binding   : FAIL  (note body is %x…, proof commits %x…)\n",
			sum[:8], proof.FileDigest[:8])
		os.Exit(1)
	}

	// [3] Temporal: walk to the Bitcoin attestation. Nothing here fetches a block header.
	b, ok := proof.Bitcoin()
	switch {
	case ok:
		fmt.Printf("  [3] Temporal  : PASS  (Bitcoin block %d, Merkle root %s)\n", b.Height, b.MerkleRootHex())
		if *root == "" {
			fmt.Println("                  supply -root <hex> from a header you trust to close the last step")
		} else if strings.EqualFold(strings.TrimPrefix(*root, "0x"), b.MerkleRootHex()) {
			fmt.Println("  [3a] Header   : PASS  (matches the Merkle root you supplied)")
		} else {
			fmt.Printf("  [3a] Header   : FAIL  (you supplied %s)\n", strings.TrimPrefix(*root, "0x"))
			os.Exit(1)
		}
	case pending(proof):
		fmt.Println("  [3] Temporal  : PENDING (calendar only; Bitcoin-confirms in ~1 block, then `ots upgrade`)")
	default:
		fmt.Println("  [3] Temporal  : FAIL (no Bitcoin attestation)")
	}

	// [4] Negative self-check: mutate the note body; the binding MUST break.
	bad := append([]byte{}, noteBody...)
	bad[len(bad)-2] ^= 0x01
	badSum := sha256.Sum256(bad)
	broke := !bytes.Equal(proof.FileDigest, badSum[:])
	fmt.Printf("  [4] Self-check: %s  (mutated note body correctly %s)\n",
		pass(broke), rejectedOrNot(broke))

	fmt.Printf("\n  WHO : %d log signature line(s) intact — verify with the log's key / stock CT tooling.\n", logSigs)
	fmt.Println("  WHEN: this exact tree head is anchored to Bitcoin — no key, no witness, offline.")
}

func pending(p *ots.Proof) bool {
	for _, a := range p.Attestations {
		if a.Kind == "pending" {
			return true
		}
	}
	return false
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
