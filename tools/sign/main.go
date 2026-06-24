package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/lukemcqueen/elencho/internal/update"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: go run ./tools/sign/ <rules.yaml> <known-malicious.yaml> [version] [private_key.pem]\n")
		os.Exit(1)
	}

	rulesPath := os.Args[1]
	maliciousPath := os.Args[2]
	version := "0.1.0-dev"
	if len(os.Args) > 3 {
		version = os.Args[3]
	}
	keyPath := "update_private_key.pem"
	if len(os.Args) > 4 {
		keyPath = os.Args[4]
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

	// Build manifest with multiple files
	var files []update.ManifestFile

	for _, path := range []string{rulesPath, maliciousPath} {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
			os.Exit(1)
		}
		hash := sha256.Sum256(data)
		sha256Hex := hex.EncodeToString(hash[:])

		// Determine the remote path (relative to repo root)
		relPath := path
		// Strip leading ./ or ../internal/scan/... to get the rule-relative path
		for _, prefix := range []string{"internal/scan/", "./internal/scan/"} {
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				relPath = "rules/" + path[len(prefix):]
				break
			}
		}

		files = append(files, update.ManifestFile{
			Path:   relPath,
			SHA256: sha256Hex,
			Size:   int64(len(data)),
		})
	}

	manifest := &update.Manifest{
		Version:      version,
		RulesVersion: 1,
		CreatedAt:    "2026-06-24T13:00:00Z",
		Files:        files,
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
	for _, f := range manifest.Files {
		fmt.Printf("  %s: %s (%d bytes)\n", f.Path, f.SHA256, f.Size)
	}
}
