package update

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// UpdateDir returns the path to the user's elencho update directory.
// Downloaded rules are stored here, overlaid on top of the embedded base rules.
func UpdateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "elencho", "rules")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create update dir: %w", err)
	}
	return dir, nil
}

// BackupDir returns the path where previous rules are backed up for rollback.
func BackupDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("home dir: %w", err)
	}
	dir := filepath.Join(home, ".config", "elencho", "backups")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
	}
	return dir, nil
}

// CheckForUpdate downloads the manifest and checks if a newer rules version exists.
// Returns the manifest if an update is available, or nil if already current.
func CheckForUpdate(baseURL string, currentVersion int) (*Manifest, error) {
	manifestURL := baseURL + "/update-manifest.json"

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(manifestURL)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	manifest, err := UnmarshalManifest(body)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}

	// Verify signature
	publicKey, err := PEMDecodePublicKey([]byte(PublicKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}

	if err := manifest.Verify(publicKey); err != nil {
		return nil, fmt.Errorf("verify manifest signature: %w", err)
	}

	// Check if there's actually a newer version
	if manifest.RulesVersion <= currentVersion {
		return nil, nil // Already current
	}

	return manifest, nil
}

// DownloadUpdate downloads the rules specified in the manifest and applies them.
func DownloadUpdate(baseURL string, manifest *Manifest) error {
	updateDir, err := UpdateDir()
	if err != nil {
		return err
	}

	// Backup existing overlay rules
	backupDir, err := BackupDir()
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC().Format("20060102T150405Z")

	for _, mf := range manifest.Files {
		// Download the file
		fileURL := baseURL + "/" + mf.Path
		data, err := downloadFile(fileURL)
		if err != nil {
			return fmt.Errorf("download %s: %w", mf.Path, err)
		}

		// Verify size
		if int64(len(data)) != mf.Size {
			return fmt.Errorf("size mismatch for %s: expected %d, got %d", mf.Path, mf.Size, len(data))
		}

		// Verify checksum
		hash := sha256.Sum256(data)
		gotHash := hex.EncodeToString(hash[:])
		if gotHash != mf.SHA256 {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", mf.Path, mf.SHA256, gotHash)
		}

		// Backup existing file if present
		target := filepath.Join(updateDir, mf.Path)
		if _, err := os.Stat(target); err == nil {
			backupFile := filepath.Join(backupDir, timestamp+"_"+filepath.Base(mf.Path))
			if err := copyFile(target, backupFile); err != nil {
				return fmt.Errorf("backup %s: %w", mf.Path, err)
			}
		}

		// Ensure target directory exists
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return fmt.Errorf("create target dir: %w", err)
		}

		// Write new file
		if err := os.WriteFile(target, data, 0644); err != nil {
			return fmt.Errorf("write %s: %w", mf.Path, err)
		}
	}

	return nil
}

// VerifyLocal checks that locally overlaid rule files have valid checksums
// by loading the manifest from the update directory.
func VerifyLocal() error {
	updateDir, err := UpdateDir()
	if err != nil {
		return err
	}

	manifestPath := filepath.Join(updateDir, "update-manifest.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read local manifest: %w (no updates applied yet)", err)
	}

	manifest, err := UnmarshalManifest(data)
	if err != nil {
		return fmt.Errorf("parse local manifest: %w", err)
	}

	// Verify signature
	publicKey, err := PEMDecodePublicKey([]byte(PublicKeyPEM))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if err := manifest.Verify(publicKey); err != nil {
		return fmt.Errorf("manifest signature: %w", err)
	}

	// Verify each file
	for _, mf := range manifest.Files {
		target := filepath.Join(updateDir, mf.Path)
		data, err := os.ReadFile(target)
		if err != nil {
			return fmt.Errorf("read %s: %w", mf.Path, err)
		}
		hash := sha256.Sum256(data)
		gotHash := hex.EncodeToString(hash[:])
		if gotHash != mf.SHA256 {
			return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", mf.Path, mf.SHA256, gotHash)
		}
		fmt.Printf("  ✓ %s (checksum OK)\n", mf.Path)
	}
	return nil
}

// downloadFile fetches a URL and returns the body bytes.
func downloadFile(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http get: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	return data, nil
}

// copyFile copies a file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// ParsePublicKey returns the embedded Ed25519 public key for verification.
func ParsePublicKey() (ed25519.PublicKey, error) {
	return PEMDecodePublicKey([]byte(PublicKeyPEM))
}

// ReadEmbeddedPublicKey returns the raw PEM string of the embedded public key.
func ReadEmbeddedPublicKey() string {
	return PublicKeyPEM
}
