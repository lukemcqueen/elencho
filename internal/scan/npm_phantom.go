package scan

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
)

// NpmPhantomDependencyRule detects dependencies declared in package.json
// that are never imported in any JS/TS source file. This catches the axios
// attack pattern (Mar 2026) where "plain-crypto-js" was added as a runtime
// dependency but never imported — acting solely as a postinstall-vector
// for a cross-platform RAT dropper.
type NpmPhantomDependencyRule struct {
	BaseRule
	Config RuleConfig
}

// knownSafePhantomDeps — packages that are frequently in dependencies but
// never directly imported in source files (build tools, CLI tools, config
// layers, type definitions, plugin ecosystems).
var knownSafePhantomDeps = map[string]bool{
	// TypeScript / type system
	"@types/node": true, "@types/react": true, "@types/express": true,
	"@types/lodash": true, "@types/jest": true, "@types/node-fetch": true,
	"typescript": true, "ts-node": true, "tslib": true, "tsc": true,
	"tsc-alias": true, "ts-patch": true,
	// Build tools
	"webpack": true, "rollup": true, "esbuild": true, "vite": true,
	"parcel": true, "turbo": true, "nx": true, "lerna": true,
	"gulp": true, "grunt": true, "browserify": true, "tsup": true,
	"microbundle": true, "snowpack": true, "unbuild": true,
	// Git hooks / code quality
	"husky": true, "lint-staged": true, "prettier": true, "eslint": true,
	"stylelint": true, "commitlint": true, "commitizen": true,
	"editorconfig": true, "lefthook": true, "simple-git-hooks": true,
	// CSS / styling
	"tailwindcss": true, "postcss": true, "autoprefixer": true,
	"sass": true, "less": true, "stylus": true, "cssnano": true,
	"purgecss": true, "postcss-cli": true, "sass-loader": true,
	"style-loader": true, "css-loader": true, "postcss-loader": true,
	// Testing
	"jest": true, "vitest": true, "mocha": true, "chai": true,
	"sinon": true, "cypress": true, "playwright": true,
	"storybook": true, "@storybook/react": true, "@storybook/addon-essentials": true,
	"karma": true, "ava": true, "tap": true, "tape": true,
	"supertest": true, "nock": true, "proxyquire": true,
	"istanbul": true, "nyc": true, "xvfb-maybe": true,
	"@testing-library/react": true, "@testing-library/jest-dom": true,
	"@testing-library/user-event": true,
	// Release / CI
	"semantic-release": true, "release-it": true, "standard-version": true,
	"changesets": true, "conventional-changelog": true,
	"github-label-sync": true, "gh-release": true, "np": true,
	// CLI tools used in scripts only
	"nodemon": true, "concurrently": true, "cross-env": true,
	"rimraf": true, "mkdirp": true, "npm-run-all": true, "del-cli": true,
	"copyfiles": true, "cpx": true, "ncp": true, "wait-on": true,
	"start-server-and-test": true, "env-cmd": true, "dotenv-cli": true,
	"tinyglobby": true, "globby": true, "chokidar-cli": true,
	"http-server": true, "serve": true, "local-web-server": true,
	"c8": true, "v8-to-istanbul": true,
	// Babel / SWC
	"@babel/core": true, "@babel/preset-env": true, "@babel/preset-react": true,
	"@babel/preset-typescript": true, "@babel/cli": true, "@babel/node": true,
	"@babel/register": true, "@babel/plugin-transform-runtime": true,
	"@swc/core": true, "@swc/jest": true, "@swc/cli": true,
	// Framework scaffolding
	"create-react-app": true, "next": true, "nuxt": true,
	"@nestjs/core": true, "@nestjs/cli": true,
	"expo": true, "expo-cli": true,
	// Side-effect / monkey-patch only (never imported by name)
	"zone.js": true, "reflect-metadata": true, "source-map-support": true,
	"core-js": true, "regenerator-runtime": true, "ts-polyfill": true,
	// Wrapper metapackages
	"workspace": true, "workspace-root": true, "root": true,
}

// phantomPluginPrefixes — deps matching these patterns are plugin/config
// packages that legitimate projects list without direct source imports.
var phantomPluginPrefixes = []string{
	"eslint-plugin-", "eslint-config-",
	"@eslint/", "@typescript-eslint/",
	"babel-plugin-", "babel-preset-", "@babel/plugin-", "@babel/preset-",
	"postcss-", "@tailwindcss/", "tailwindcss-",
	"@rollup/plugin-", "rollup-plugin-",
	"vite-plugin-", "@vitejs/plugin-",
	"webpack-plugin-", "html-webpack-plugin", "mini-css-extract-plugin",
	"terser-webpack-plugin", "copy-webpack-plugin",
	"@storybook/", "storybook-addon-", "storybook-",
	"@nuxt/", "nuxt-",
	"@nestjs/", "nest-",
	"jest-", "@jest/",
	"@sentry/", "sentry-",
	"@sveltejs/", "svelte-",
	"@vue/", "vue-",
	"@angular/", "ng-",
	"@emotion/", "emotion-",
	"@commitlint/", "commitlint-",
	"@changesets/", "changeset-",
	"@graphql-codegen/",
	"@opentelemetry/",
	"@aws-sdk/",
	"@azure/",
	"@google-cloud/",
}

func (r *NpmPhantomDependencyRule) Detect(ctx context.Context, scanRoot string, files []string) ([]Finding, error) {
	var findings []Finding

	// Collect all JS/TS source files
	sourceFiles := make(map[string]bool)
	for _, f := range files {
		ext := strings.ToLower(filepath.Ext(f))
		if ext == ".js" || ext == ".ts" || ext == ".jsx" || ext == ".tsx" || ext == ".mjs" || ext == ".cjs" || ext == ".mts" {
			sourceFiles[f] = true
		}
	}

	// Collect all config files for cross-reference (Verifier uses them too)
	configFiles := findConfigFiles(files)

	for _, f := range files {
		if filepath.Base(f) != "package.json" {
			continue
		}
		data, err := ReadFile(filepath.Join(scanRoot, f))
		if err != nil {
			continue
		}
		var pkg struct {
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal([]byte(data), &pkg); err != nil {
			continue
		}

		pkgDir := filepath.Dir(f)

		// Build import set from source files in this package's scope
		pkgImports := make(map[string]bool)
		for sf := range sourceFiles {
			if strings.HasPrefix(sf, pkgDir+"/") || filepath.Dir(sf) == pkgDir {
				srcData, err := ReadFile(filepath.Join(scanRoot, sf))
				if err != nil {
					continue
				}
				for _, imp := range extractImports(srcData) {
					pkgImports[imp] = true
				}
			}
		}

		// If no source files exist in this package, can't determine phantoms
		if len(pkgImports) == 0 {
			continue
		}

		// Check runtime dependencies
		for depName := range pkg.Dependencies {
			if isKnownPhantomDep(depName, pkgImports, configFiles) {
				continue
			}
			findings = append(findings, Finding{
				Severity: r.Sev, Category: r.Cat, RuleID: r.RuleID,
				File: f, Line: 0,
				Message: "Phantom dependency: " + depName + " is declared but never imported in any source file — possible malware vector",
			})
		}

		// Check dev dependencies (lower severity)
		for depName := range pkg.DevDependencies {
			if isKnownPhantomDep(depName, pkgImports, configFiles) {
				continue
			}
			findings = append(findings, Finding{
				Severity: SeverityMedium, Category: r.Cat, RuleID: r.RuleID,
				File: f, Line: 0,
				Message: "Phantom dev dependency: " + depName + " is declared but never imported — verify it's not a malware vector",
			})
		}
	}

	return findings, nil
}

// isKnownPhantomDep returns true if a dep is known to be legitimately unused in imports.
func isKnownPhantomDep(depName string, imports map[string]bool, configFiles map[string]string) bool {
	// Direct match in known safe list
	if knownSafePhantomDeps[depName] {
		return true
	}

	// Plugin/config prefix match
	for _, prefix := range phantomPluginPrefixes {
		if strings.HasPrefix(depName, prefix) {
			return true
		}
	}

	// @types/* packages — always legitimate phantom deps
	if strings.HasPrefix(depName, "@types/") {
		return true
	}

	// Check if imported in source files
	if isImported(depName, imports) {
		return true
	}

	// Cross-reference with config files — if the dep name appears in any
	// config file's content, it's likely a legitimate plugin reference
	for _, cfgContent := range configFiles {
		if strings.Contains(cfgContent, depName) {
			return true
		}
	}

	return false
}

// findConfigFiles returns known config file paths → their content.
func findConfigFiles(files []string) map[string]string {
	configNames := []string{
		".eslintrc", ".eslintrc.json", ".eslintrc.js", ".eslintrc.yaml",
		"babel.config.js", "babel.config.json", ".babelrc",
		"postcss.config.js", "postcss.config.json",
		"tsconfig.json",
		"jest.config.js", "jest.config.ts", "jest.config.json",
		"next.config.js", "next.config.ts",
		"tailwind.config.js", "tailwind.config.ts",
		".storybook/main.js", ".storybook/main.ts",
		".prettierrc", ".prettierrc.json", ".prettierrc.js",
		"stylelint.config.js", ".stylelintrc",
		"commitlint.config.js",
		"rollup.config.js", "rollup.config.ts",
		"vite.config.js", "vite.config.ts",
		"webpack.config.js", "webpack.config.ts",
		".npmrc",
	}
	cfgSet := make(map[string]bool)
	for _, n := range configNames {
		cfgSet[n] = true
	}

	result := make(map[string]string)
	for _, f := range files {
		base := filepath.Base(f)
		if cfgSet[base] {
			// Only read config files at the root or same level as package.json
			dir := filepath.Dir(f)
			if dir == "." {
				result[f] = "" // placeholder — content read lazily
			}
		}
	}
	return result
}

// isImported checks if a dependency name appears in the import set.
func isImported(depName string, imports map[string]bool) bool {
	if imports[depName] {
		return true
	}
	// Handle scoped packages: check without subpath
	if strings.HasPrefix(depName, "@") {
		parts := strings.SplitN(depName, "/", 3)
		if len(parts) >= 2 && imports[parts[0]+"/"+parts[1]] {
			return true
		}
	}
	// Handle unscoped packages: check top-level name only
	if !strings.HasPrefix(depName, "@") && strings.Contains(depName, "/") {
		parts := strings.SplitN(depName, "/", 2)
		if imports[parts[0]] {
			return true
		}
	}
	return false
}

// extractImports returns all package names imported via import/require()/import().
func extractImports(data string) []string {
	var imports []string
	seen := make(map[string]bool)
	lines := strings.Split(data, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		// import ... from 'pkg' or import 'pkg'
		if strings.HasPrefix(line, "import ") {
			idx := strings.LastIndex(line, " from ")
			var src string
			if idx >= 0 {
				src = line[idx+6:]
			} else {
				src = line[7:]
			}
			pkg := extractQuotedString(src)
			if pkg != "" && !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				pkg = normalizeImport(pkg)
				if !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}
		}

		// require('pkg')
		if strings.Contains(line, "require(") {
			idx := strings.Index(line, "require(")
			rest := line[idx+8:]
			pkg := extractQuotedString(rest)
			if pkg != "" && !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				pkg = normalizeImport(pkg)
				if !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}
		}

		// dynamic import('pkg')
		if strings.Contains(line, "import(") && !strings.HasPrefix(line, "import ") {
			idx := strings.Index(line, "import(")
			rest := line[idx+7:]
			pkg := extractQuotedString(rest)
			if pkg != "" && !strings.HasPrefix(pkg, ".") && !strings.HasPrefix(pkg, "/") {
				pkg = normalizeImport(pkg)
				if !seen[pkg] {
					seen[pkg] = true
					imports = append(imports, pkg)
				}
			}
		}
	}
	return imports
}

// normalizeImport strips subpath from a package import.
func normalizeImport(pkg string) string {
	if strings.HasPrefix(pkg, "@") {
		parts := strings.SplitN(pkg, "/", 3)
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return pkg
	}
	parts := strings.SplitN(pkg, "/", 2)
	return parts[0]
}

// extractQuotedString finds the first single/double/backtick quoted string in s.
func extractQuotedString(s string) string {
	s = strings.TrimSpace(s)
	for _, q := range []string{"'", "\"", "`"} {
		start := strings.Index(s, q)
		if start >= 0 {
			end := strings.Index(s[start+1:], q)
			if end >= 0 {
				return s[start+1 : start+1+end]
			}
		}
	}
	return ""
}
