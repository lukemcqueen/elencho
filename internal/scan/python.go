package scan

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
)

// ── setup.py cmdclass ─────────────────────────────────────────────────────────

type PythonCmdclassRule struct {
	BaseRule
	Config RuleConfig
}

func (r *PythonCmdclassRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "setup.py" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if strings.Contains(line, "cmdclass") && strings.Contains(line, "=") {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "setup.py defines cmdclass — can execute arbitrary build code",
				})
			}
		}
	}
	return findings, nil
}

// ── setup.py network/shell calls ──────────────────────────────────────────────

type PythonSetupDownloadRule struct {
	BaseRule
	Config RuleConfig
}

var pyDangerCalls = []string{"os.system(", "subprocess.call", "subprocess.Popen", "subprocess.run",
	"urllib.request", "urllib.urlopen", "requests.get", "requests.post"}

func (r *PythonSetupDownloadRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if filepath.Base(f) != "setup.py" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			for _, pat := range pyDangerCalls {
				if strings.Contains(line, pat) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "setup.py calls network or shell command: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// Verify implements the Verifier interface for python-setup-download.
// Lowers confidence for standard ML build patterns and vendored dependencies.
func (r *PythonSetupDownloadRule) Verify(_ context.Context, _ string, finding *Finding, _ []Finding) error {
	// Vendor/third-party/site-packages directories — these are bundled deps, not malware
	if strings.Contains(finding.File, "site-packages") ||
		strings.Contains(finding.File, "vendor/") ||
		strings.Contains(finding.File, "third_party") ||
		strings.Contains(finding.File, "third-party") ||
		strings.Contains(finding.File, "lib/python") {
		finding.Confidence = 0.3
		return nil
	}
	// Standard build commands in setup.py — cmake, make, git clone, ninja
	msg := finding.Message
	if strings.Contains(msg, "cmake") || strings.Contains(msg, "make ") ||
		strings.Contains(msg, "ninja") || strings.Contains(msg, "meson") {
		finding.Confidence = 0.5
		return nil
	}

	return nil
}

// ── Unusual build backends ────────────────────────────────────────────────────

type PythonBuildBackendRule struct {
	BaseRule
	Config RuleConfig
}

var knownBackends = []string{"setuptools", "flit", "poetry", "pdm", "hatchling", "mesonpy", "maturin", "scikit-build"}

func (r *PythonBuildBackendRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	backendFiles := []string{"setup.cfg", "pyproject.toml"}
	re := regexp.MustCompile(`backend\s*=\s*["']`)
	for _, f := range files {
		if !FilenameMatch(f, backendFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if !re.MatchString(line) {
				continue
			}
			isKnown := false
			for _, known := range knownBackends {
				if strings.Contains(line, known) {
					isKnown = true
					break
				}
			}
			if !isKnown {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Unusual build backend: " + strings.TrimSpace(line),
				})
			}
		}
	}
	return findings, nil
}

// ── Custom pip indexes ────────────────────────────────────────────────────────

type PythonCustomIndexRule struct {
	BaseRule
	Config RuleConfig
}

func (r *PythonCustomIndexRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	pipFiles := []string{"pip.conf", "pip.ini"}
	for _, f := range files {
		if !FilenameMatch(f, pipFiles) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			if strings.HasPrefix(line, "extra-index-url") || strings.HasPrefix(line, "index-url") {
				if !strings.Contains(line, "pypi.org") {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Custom pip index (potential dependency confusion): " + strings.TrimSpace(line),
					})
				}
			}
		}
	}
	return findings, nil
}

// ── Dynamic imports (__import__ / importlib) ───────────────────────────────────

type PythonDynamicImportRule struct {
	BaseRule
	Config RuleConfig
}

var dynamicImportPats = []*regexp.Regexp{
	regexp.MustCompile(`__import__\(["'][^"']+["']\)`),
	regexp.MustCompile(`importlib\.import_module\(`),
	regexp.MustCompile(`importlib\.__import__\(`),
}

func (r *PythonDynamicImportRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !HasExtension(f, []string{".py"}) {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		for i, line := range lines {
			// Skip imports in standard __init__ or Known safe patterns
			if strings.Contains(line, "importlib.metadata") || strings.Contains(line, "importlib.resources") {
				continue
			}
			for _, pat := range dynamicImportPats {
				if pat.MatchString(line) {
					findings = append(findings, Finding{
						Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
						File: f, Line: i + 1,
						Message: "Dynamic module import — common malware loader pattern: " + strings.TrimSpace(line),
					})
					break
				}
			}
		}
	}
	return findings, nil
}

// ── Git dependencies in requirements.txt ──────────────────────────────────────

type PythonGitDependencyRule struct {
	BaseRule
	Config RuleConfig
}

func (r *PythonGitDependencyRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding
	for _, f := range files {
		if !strings.HasPrefix(filepath.Base(f), "requirements") || !strings.HasSuffix(f, ".txt") {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		lines := strings.Split(data, "\n")
		re := regexp.MustCompile(`^(git\+|https?://.*\.(tar\.gz|zip|whl)#)`)
		for i, line := range lines {
			if re.MatchString(line) {
				findings = append(findings, Finding{
					Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
					File: f, Line: i + 1,
					Message: "Unpinned dependency from external source",
				})
			}
		}
	}
	return findings, nil
}
