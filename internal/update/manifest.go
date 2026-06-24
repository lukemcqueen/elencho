// Package update provides Ed25519-signed update verification for Elencho rules.
// The update system uses a JSON manifest signed with an Ed25519 keypair.
// The public key is embedded in the binary; the private key is held by the maintainer.
package update

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

// Manifest describes a set of rule files to download and verify.
type Manifest struct {
	// Version of the elencho binary this manifest targets.
	Version string `json:"version"`
	// RulesVersion is a monotonically increasing version for the rules database.
	RulesVersion int `json:"rules_version"`
	// CreatedAt is the ISO 8601 timestamp of when the manifest was created.
	CreatedAt string `json:"created_at"`
	// Files lists the rule files included in this update.
	Files []ManifestFile `json:"files"`
	// Signature is the Ed25519 signature over the rest of the manifest (base64).
	Signature string `json:"signature"`
}

// ManifestFile describes a single file in an update manifest.
type ManifestFile struct {
	// Path is the relative path of the file (e.g., "rules/rules.yaml").
	Path string `json:"path"`
	// SHA256 is the hex-encoded SHA-256 checksum of the file content.
	SHA256 string `json:"sha256"`
	// Size is the file size in bytes.
	Size int64 `json:"size"`
}

// SigningPayload returns the canonical JSON bytes to sign.
// This is the manifest without the signature field, deterministic marshaled.
func (m *Manifest) SigningPayload() ([]byte, error) {
	// Create a copy without the signature
	payload := struct {
		Version      string         `json:"version"`
		RulesVersion int            `json:"rules_version"`
		CreatedAt    string         `json:"created_at"`
		Files        []ManifestFile `json:"files"`
	}{
		Version:      m.Version,
		RulesVersion: m.RulesVersion,
		CreatedAt:    m.CreatedAt,
		Files:        m.Files,
	}
	return json.Marshal(payload)
}

// Sign signs the manifest with the given Ed25519 private key.
// The signature is set on the manifest in-place.
func (m *Manifest) Sign(privateKey ed25519.PrivateKey) error {
	payload, err := m.SigningPayload()
	if err != nil {
		return fmt.Errorf("signing payload: %w", err)
	}
	sig := ed25519.Sign(privateKey, payload)
	m.Signature = encodeBase64(sig)
	return nil
}

// Verify checks the Ed25519 signature on the manifest against the given public key.
func (m *Manifest) Verify(publicKey ed25519.PublicKey) error {
	if m.Signature == "" {
		return fmt.Errorf("manifest has no signature")
	}
	sig, err := decodeBase64(m.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	payload, err := m.SigningPayload()
	if err != nil {
		return fmt.Errorf("signing payload: %w", err)
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

// Marshal serializes the manifest to JSON (with signature).
func (m *Manifest) Marshal() ([]byte, error) {
	return json.MarshalIndent(m, "", "  ")
}

// UnmarshalManifest parses JSON into a Manifest.
func UnmarshalManifest(data []byte) (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}

// GenerateKey generates a new Ed25519 keypair for signing manifests.
// The private key should be kept secret; the public key should be embedded in the binary.
func GenerateKey() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	return privateKey, publicKey, nil
}

// PEMEncodePrivateKey encodes an Ed25519 private key as a PEM block.
func PEMEncodePrivateKey(privateKey ed25519.PrivateKey) []byte {
	block := &pem.Block{
		Type:  "ED25519 PRIVATE KEY",
		Bytes: privateKey,
	}
	return pem.EncodeToMemory(block)
}

// PEMEncodePublicKey encodes an Ed25519 public key as a PEM block.
func PEMEncodePublicKey(publicKey ed25519.PublicKey) []byte {
	block := &pem.Block{
		Type:  "ED25519 PUBLIC KEY",
		Bytes: publicKey,
	}
	return pem.EncodeToMemory(block)
}

// PEMDecodePublicKey decodes a PEM-encoded Ed25519 public key.
func PEMDecodePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "ED25519 PUBLIC KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	if len(block.Bytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid public key length: %d", len(block.Bytes))
	}
	return ed25519.PublicKey(block.Bytes), nil
}

// PEMDecodePrivateKey decodes a PEM-encoded Ed25519 private key.
func PEMDecodePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	if block.Type != "ED25519 PRIVATE KEY" {
		return nil, fmt.Errorf("unexpected PEM type: %s", block.Type)
	}
	// Ed25519 private key can be 32 bytes (seed) or 64 bytes (seed + public key)
	if len(block.Bytes) != ed25519.SeedSize && len(block.Bytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key length: %d", len(block.Bytes))
	}
	return ed25519.PrivateKey(block.Bytes), nil
}

// encodeBase64 encodes bytes to standard base64.
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes a standard base64 string.
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
