// Command secretguard enforces pre-commit and CI/CD secret scanning,
// Google Secret Manager verification, and Vertex AI SARIF gate summarization.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/iuriikogan/vuln-nodejs-goof/internal/scanner"
	"github.com/iuriikogan/vuln-nodejs-goof/internal/secrets"
	"github.com/iuriikogan/vuln-nodejs-goof/internal/vertex"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "scan":
		if err := runScan(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[secretguard] ERROR: %v\n", err)
			os.Exit(1)
		}
	case "summarize-sarif":
		if err := runSummarizeSARIF(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[secretguard] ERROR: %v\n", err)
			os.Exit(1)
		}
	case "fetch-secret":
		if err := runFetchSecret(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "[secretguard] ERROR: %v\n", err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(2)
	}
}

func runScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	staged := fs.Bool("staged", false, "Scan only staged git changes (git diff --cached)")
	repoDir := fs.String("repo", ".", "Repository directory to scan")
	jsonOut := fs.Bool("json", false, "Output findings as JSON")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parsing scan flags: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var (
		findings []scanner.Finding
		err      error
	)
	if *staged {
		findings, err = scanner.ScanStagedDiff(ctx, *repoDir)
	} else {
		findings, err = scanner.ScanRepository(*repoDir)
	}
	if err != nil {
		return fmt.Errorf("running secret scan: %w", err)
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if encErr := enc.Encode(findings); encErr != nil {
			return fmt.Errorf("encoding findings JSON: %w", encErr)
		}
	} else if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "\n[secretguard] BLOCKED: %d hardcoded secret(s) or policy violation(s) detected:\n", len(findings))
		for i, f := range findings {
			fmt.Fprintf(os.Stderr, "  %d. [%s] %s:%d — %s\n     Remediation: %s\n",
				i+1, f.RuleID, f.File, f.Line, f.Description, f.Remediation)
		}
		fmt.Fprintln(os.Stderr)
	} else {
		fmt.Println("[secretguard] PASS: 0 hardcoded secrets or prohibited .env files found.")
	}

	if len(findings) > 0 {
		return fmt.Errorf("secretguard blocked %d finding(s)", len(findings))
	}
	return nil
}

func runSummarizeSARIF(args []string) error {
	cfg := vertex.ConfigFromEnv()
	fs := flag.NewFlagSet("summarize-sarif", flag.ContinueOnError)
	sarifPath := fs.String("file", "codemender.sarif", "Path to CodeMender SARIF report")
	projectID := fs.String("project", cfg.ProjectID, "Google Cloud Project ID")
	location := fs.String("location", cfg.Location, "Google Cloud region")
	flashModel := fs.String("model", cfg.FlashModelID, "Default Gemini Flash model ID")
	proModel := fs.String("pro-model", cfg.ProModelID, "Complex Gemini Pro model ID")
	deep := fs.Bool("deep", false, "Use Gemini Pro model for complex multi-step synthesis")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parsing summarize-sarif flags: %w", err)
	}

	data, err := os.ReadFile(*sarifPath)
	if err != nil {
		return fmt.Errorf("reading SARIF file %s: %w", *sarifPath, err)
	}

	cfg.ProjectID = *projectID
	cfg.Location = *location
	cfg.FlashModelID = *flashModel
	cfg.ProModelID = *proModel

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	advisor, err := vertex.NewAdvisor(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initializing Vertex AI advisor: %w", err)
	}
	defer func() { _ = advisor.Close() }()

	if err := advisor.StreamSARIFSummary(ctx, string(data), *deep, os.Stdout); err != nil {
		return fmt.Errorf("summarizing SARIF report: %w", err)
	}
	return nil
}

func runFetchSecret(args []string) error {
	fs := flag.NewFlagSet("fetch-secret", flag.ContinueOnError)
	projectID := fs.String("project", os.Getenv("GOOGLE_CLOUD_PROJECT"), "Google Cloud Project ID")
	secretName := fs.String("name", "", "Secret ID in Google Secret Manager")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("parsing fetch-secret flags: %w", err)
	}
	if *secretName == "" {
		return fmt.Errorf("--name is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cli, err := secrets.NewClient(ctx, *projectID)
	if err != nil {
		return fmt.Errorf("initializing Secret Manager client: %w", err)
	}
	defer func() { _ = cli.Close() }()

	val, err := cli.AccessSecret(ctx, *secretName)
	if err != nil {
		return fmt.Errorf("fetching secret %s: %w", *secretName, err)
	}
	fmt.Print(val)
	return nil
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: secretguard <command> [flags]")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  scan             Scan staged git changes (--staged) or repository (--repo) for hardcoded secrets")
	fmt.Fprintln(os.Stderr, "  summarize-sarif  Stream a Vertex AI executive summary of a CodeMender SARIF report")
	fmt.Fprintln(os.Stderr, "  fetch-secret     Retrieve a secret from Google Secret Manager via ADC")
}
