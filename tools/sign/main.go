package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/lukemcqueen/elencho/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: go run ./tools/sign/ <rules.yaml> [version] [private_key.pem]\n")
		os.Exit(1)
	}

	rulesPath := os.Args[1]
	version := "0.1.0-dev"
	if len(os.Args) > 2 {
		version = os.Args[2]
	}
	keyPath := "update_private_key.pem"
	if len(os.Args) > 3 {
		keyPath = os.Args[3]
	}

	// Read private key
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read private key: %v\n", err)
		os.Exit(1)
	}
	privateKey, err := update.PEMDecodePrivateKey(keyData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(1)
	}

	// Read rules file
	rulesData, err := os.ReadFile(rulesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read rules: %v\n", err)
		os.Exit(1)
	}

	hash := sha256.Sum256(rulesData)
	sha256Hex := hex.EncodeToString(hash[:])

	manifest := &update.Manifest{
		Version:      version,
		RulesVersion: 1,
		CreatedAt:    "2026-06-24T13:00:00Z",
		Files: []update.ManifestFile{
			{Path: "rules/rules.yaml", SHA256: sha256Hex, Size: int64(len(rulesData))},
		},
	}

	if err := manifest.Sign(privateKey); err != nil {
		fmt.Fprintf(os.Stderr, "sign: %v\n", err)
		os.Exit(1)
	}

	manifestData, err := manifest.Marshal()
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile("update-manifest.json", manifestData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write manifest: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Signed manifest written to update-manifest.json")
	fmt.Printf("  Version:       %s\n", version)
	fmt.Printf("  Rules version: %d\n", manifest.RulesVersion)
	fmt.Printf("  SHA256:        %s\n", sha256Hex)
}
