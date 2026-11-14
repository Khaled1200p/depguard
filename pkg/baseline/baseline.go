// Package baseline defines the depguard.baseline.json format shared by the
// generator (depguard-gen) and the eBPF sensor. The Python/Node agents
// re-implement the (tiny) Merkle computation so they stay zero-dependency.
package baseline

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

const SchemaVersion = 1

// Entry describes one executable file that belongs to a locked package.
type Entry struct {
	Package   string `json:"package"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"` // "pypi" | "npm"
	SHA256    string `json:"sha256"`
}

// Baseline maps resolved absolute (symlink-free) paths to their entries.
type Baseline struct {
	SchemaVersion int              `json:"schema_version"`
	GeneratedAt   string           `json:"generated_at"`
	Root          string           `json:"root"`
	Files         map[string]Entry `json:"files"`
	MerkleRoot    string           `json:"merkle_root"`
	Signature     string           `json:"signature,omitempty"` // base64 ed25519 over MerkleRoot (hex string bytes)
	Warnings      []string         `json:"warnings,omitempty"`
}

// ComputeMerkle returns SHA-256 over "<sha256>  <path>\n" lines sorted by path
// (byte order). Python and Node agents compute exactly the same value.
func (b *Baseline) ComputeMerkle() string {
	keys := make([]string, 0, len(b.Files))
	for k := range b.Files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		fmt.Fprintf(h, "%s  %s\n", b.Files[k].SHA256, k)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Seal fills MerkleRoot and, when priv is non-nil, Signature.
func (b *Baseline) Seal(priv ed25519.PrivateKey) {
	b.MerkleRoot = b.ComputeMerkle()
	if priv != nil {
		b.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(b.MerkleRoot)))
	}
}

// Verify checks internal consistency and, if pub != nil, the signature.
func (b *Baseline) Verify(pub ed25519.PublicKey) error {
	if b.ComputeMerkle() != b.MerkleRoot {
		return errors.New("merkle root mismatch: baseline content was modified")
	}
	if pub != nil {
		sig, err := base64.StdEncoding.DecodeString(b.Signature)
		if err != nil || !ed25519.Verify(pub, []byte(b.MerkleRoot), sig) {
			return errors.New("baseline signature missing or invalid")
		}
	}
	return nil
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if b.Files == nil {
		return nil, errors.New("baseline has no files map")
	}
	return &b, nil
}

func (b *Baseline) WriteFile(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o644)
}

// GenerateKeyPair writes depguard.key (PKCS#8, 0600) and depguard.pub (PKIX).
func GenerateKeyPair(dir string) (privPath, pubPath string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", "", err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", "", err
	}
	privPath, pubPath = filepath.Join(dir, "depguard.key"), filepath.Join(dir, "depguard.pub")
	if err = os.WriteFile(privPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER}), 0o600); err != nil {
		return
	}
	err = os.WriteFile(pubPath, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}), 0o644)
	return
}

func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block in private key")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an ed25519 key")
	}
	return pk, nil
}

func LoadPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(data)
	if blk == nil {
		return nil, errors.New("no PEM block in public key")
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	pk, ok := k.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an ed25519 key")
	}
	return pk, nil
}
