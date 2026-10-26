// Package scanner provides fast pre-commit and CI/CD secret detection
// enforcing Google Secret Manager usage and blocking hardcoded credentials.
package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding represents a detected hardcoded secret or policy violation.
type Finding struct {
	File        string `json:"file"`
	Line        int    `json:"line"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

type rule struct {
	id          string
	description string
	pattern     *regexp.Regexp
	remediation string
}

var defaultRules = []rule{
	{
		id:          "GCP-API-KEY",
		description: "Hardcoded Google Cloud API Key detected",
		pattern:     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		remediation: "Store API keys in Google Secret Manager and retrieve at runtime via Application Default Credentials (ADC).",
	},
	{
		id:          "GCP-SA-PRIVATE-KEY",
		description: "Google Cloud Service Account JSON private key detected",
		pattern:     regexp.MustCompile(`"type"\s*:\s*"service_account"`),
		remediation: "Never commit Service Account JSON keys. Use Workload Identity Federation (WIF) in CI/CD and ADC locally.",
	},
	{
		id:          "PRIVATE-KEY-BLOCK",
		description: "PEM or SSH Private Key block detected",
		pattern:     regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) PRIVATE KEY-----`),
		remediation: "Remove the private key immediately, rotate the keypair, and store secrets in Google Secret Manager.",
	},
	{
		id:          "GITHUB-PAT",
		description: "GitHub Personal Access Token detected",
		pattern:     regexp.MustCompile(`(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})`),
		remediation: "Revoke the token and use GitHub App tokens or Google Secret Manager.",
	},
	{
		id:          "AWS-ACCESS-KEY",
		description: "AWS Access Key ID detected",
		pattern:     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		remediation: "Remove the hardcoded access key and use federated workload identity or Secret Manager.",
	},
	{
		id:          "HARDCODED-SECRET-TOKEN",
		description: "Hardcoded application secret token or password literal detected",
		pattern:     regexp.MustCompile(`(?i)(SECRET_TOKEN_[0-9a-fA-F]{16,}|password\s*:\s*['"](SuperSecretPassword|root|admin123)['"]|secret\s*:\s*['"]keyboard cat['"])`),
		remediation: "Replace hardcoded token/password literals with Google Secret Manager lookups via service/secret-manager.js or internal/secrets.",
	},
	{
		id:          "DB-CONNECTION-URI-CREDS",
		description: "Database connection URI with embedded credentials detected",
		pattern:     regexp.MustCompile(`(?i)(mongodb(\+srv)?|postgres(ql)?|mysql)://[^/\s:@]+:[^/\s@]+@[^/\s]+`),
		remediation: "Remove embedded credentials from connection URIs and inject passwords from Google Secret Manager via ADC.",
	},
}

// Ignored directories and historical fixture files when scanning a repository tree.
var ignoredDirs = map[string]bool{
	".git":         true,
	"node_modules": true,
	"vendor":       true,
	"dist":         true,
	"build":        true,
	"bin":          true,
}

var ignoredFixtureFiles = map[string]bool{
	"sarif.json":      true,
	"example111.json": true,
	"package-lock.json": true,
}

// ScanStagedDiff inspects staged Git changes (`git diff --cached`) for secrets and prohibited .env files.
func ScanStagedDiff(ctx context.Context, repoDir string) ([]Finding, error) {
	cmd := exec.CommandContext(ctx, "git", "diff", "--cached", "--unified=0", "--no-color")
	cmd.Dir = repoDir
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("executing git diff --cached in %s: %w", repoDir, err)
	}
	return ParseUnifiedDiff(string(out)), nil
}

// ParseUnifiedDiff parses `git diff --unified=0` output and scans all added lines.
func ParseUnifiedDiff(diffOutput string) []Finding {
	var findings []Finding
	var currentFile string
	currentLine := 0

	hunkHeader := regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)
	scanner := bufio.NewScanner(strings.NewReader(diffOutput))

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "+++ b/") {
			currentFile = strings.TrimPrefix(line, "+++ b/")
			if isProhibitedEnvFile(currentFile) {
				findings = append(findings, Finding{
					File:        currentFile,
					Line:        1,
					RuleID:      "PROHIBITED-ENV-FILE",
					Description: "Local .env file staged for commit (violates Objective 2.3)",
					Remediation: "Unstage and remove the .env file. Use Google Secret Manager with Application Default Credentials (ADC) exclusively.",
				})
			}
			continue
		}
		if m := hunkHeader.FindStringSubmatch(line); m != nil {
			_, _ = fmt.Sscanf(m[1], "%d", &currentLine)
			continue
		}
		if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
			addedContent := strings.TrimPrefix(line, "+")
			findings = append(findings, scanLine(currentFile, currentLine, addedContent)...)
			currentLine++
		}
	}
	return findings
}

// ScanRepository walks a directory tree and scans tracked source files for hardcoded secrets.
func ScanRepository(rootDir string) ([]Finding, error) {
	var findings []Finding

	err := filepath.WalkDir(rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking path %s: %w", path, err)
		}
		if d.IsDir() {
			if ignoredDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		relPath, relErr := filepath.Rel(rootDir, path)
		if relErr != nil {
			relPath = path
		}

		if ignoredFixtureFiles[filepath.Base(relPath)] {
			return nil
		}
		if strings.HasSuffix(relPath, "_test.go") {
			return nil
		}

		if isProhibitedEnvFile(relPath) {
			findings = append(findings, Finding{
				File:        relPath,
				Line:        1,
				RuleID:      "PROHIBITED-ENV-FILE",
				Description: "Local .env file present in repository (violates Objective 2.3)",
				Remediation: "Delete the .env file and fetch secrets from Google Secret Manager via ADC.",
			})
			return nil
		}

		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return fmt.Errorf("reading file %s: %w", path, readErr)
		}
		// Skip binary files
		if bytes.IndexByte(data, 0) != -1 {
			return nil
		}

		sc := bufio.NewScanner(bytes.NewReader(data))
		lineNum := 0
		for sc.Scan() {
			lineNum++
			findings = append(findings, scanLine(relPath, lineNum, sc.Text())...)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("scanning repository %s: %w", rootDir, err)
	}
	return findings, nil
}

func isProhibitedEnvFile(relPath string) bool {
	base := filepath.Base(relPath)
	return base == ".env" || strings.HasPrefix(base, ".env.")
}

func scanLine(file string, lineNum int, content string) []Finding {
	if strings.Contains(content, "secretguard:allow") {
		return nil
	}

	var findings []Finding
	for _, r := range defaultRules {
		if r.pattern.MatchString(content) {
			findings = append(findings, Finding{
				File:        file,
				Line:        lineNum,
				RuleID:      r.id,
				Description: r.description,
				Remediation: r.remediation,
			})
		}
	}
	return findings
}

// ShannonEntropy computes the information entropy in bits per character.
func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	counts := make(map[rune]int)
	total := 0
	for _, r := range s {
		counts[r]++
		total++
	}
	var entropy float64
	for _, c := range counts {
		p := float64(c) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}
