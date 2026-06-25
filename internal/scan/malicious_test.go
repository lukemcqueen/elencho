package scan

import (
	"testing"
)

// TestKnownMaliciousPackages verifies the embedded known-malicious.yaml
// contains entries for the latest supply-chain malware campaigns.
func TestKnownMaliciousPackages(t *testing.T) {
	// Verify npmMalicious map has entries loaded
	if len(npmMalicious) == 0 {
		t.Fatal("npmMalicious map is empty — known-malicious.yaml may not have loaded")
	}

	// Verify key npm malicious packages are present
	npmChecks := map[string]bool{
		// Classic entries that should always be present
		"colors":       false,
		"faker.js":     false,
		"event-stream": false,
		"ua-parser-js": false,
		// 2025-2026 supply-chain campaigns
		"axios":                              false,
		"plain-crypto-js":                    false,
		"@ctrl/tinycolor":                    false,
		"@redhat-cloud-services/types":       false,
		"opensearch-setup":                   false,
		"@cloudplatform-single-spa/svp-baas": false,
	}

	for name := range npmMalicious {
		if _, ok := npmChecks[name]; ok {
			npmChecks[name] = true
		}
	}

	for name, found := range npmChecks {
		if !found {
			t.Errorf("missing npm malicious package entry: %s", name)
		}
	}

	// Verify key PyPI malicious packages are present
	pypiChecks := map[string]bool{
		"colorama":    false,
		"requests":    false,
		"pytorch":     false,
		"durabletask": false,
		"termncolor":  false,
	}

	for name := range pypiMalicious {
		if _, ok := pypiChecks[name]; ok {
			pypiChecks[name] = true
		}
	}

	for name, found := range pypiChecks {
		if !found {
			t.Errorf("missing PyPI malicious package entry: %s", name)
		}
	}

	// Verify Go module entries
	goChecks := map[string]bool{
		"github.com/nothub/hubert": false,
		"github.com/lu4p/ToRat":    false,
	}

	for name := range goMalicious {
		if _, ok := goChecks[name]; ok {
			goChecks[name] = true
		}
	}

	for name, found := range goChecks {
		if !found {
			t.Errorf("missing Go malicious module entry: %s", name)
		}
	}
}
