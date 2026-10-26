# Securing the Agentic Development Lifecycle with Google CodeMender (`cm`)

**Repository:** `iuriikogan/vuln-nodejs-goof` (forked from `snyk-labs/nodejs-goof`)  
**Official Google Cloud CodeMender Documentation:** `https://docs.cloud.google.com/gemini-enterprise-agent-platform/agents/codemender/`

---

## 1. Why This Exists: The AI Threat Velocity Gap

AI has compressed the software development lifecycle—85% of developers use AI coding assistants and 41% of new code is AI-generated—while simultaneously accelerating offensive exploitation:

* **Mean Time-to-Exploit (MTTE):** Collapsed from **1.3 years (2020) to 1.6 days (2026)** across weaponizable CVEs, with flaws like *React 2 Shell* exploited in cloud environments within **6 hours** of CVE assignment.
* **Sub-Zero Patch Windows:** Mandiant *M-Trends 2026* shows zero-day flaws are exploited **-7 days** before patch release, post-breach hand-off takes **22 seconds**, and ransomware dwell time fell from **48 hours to 25 minutes**.
* **Manual Remediation Lag:** Traditional AppSec triage, patch authoring, regression testing, and change management still take **20 to 70 days**.

This repository demonstrates how to close that gap by embedding **Google CodeMender (`cm`)** directly into a developer workflow across four pillars:
1. **Creating a Secure Repository** (`cm init --verify`, `.codemender/config.yaml`, `permissive-closed` sandbox, Google Secret Manager via ADC).
2. **Pre-Commit Security & Secrets Hooks** (`.git/hooks/pre-commit` combining `<200ms` staged diff secrets scanning via `cmd/secretguard` with `cm find . --diff --staged --fail-on=CRITICAL,HIGH`).
3. **Local Sandboxed Exploit Verification & 4-Step Auto-Patching** (`cm verify <ID>` $\rightarrow$ `cm fix <ID>` $\rightarrow$ `cm vcs diff && cm vcs stage`).
4. **CI/CD Pull Request Security Gates & Autonomous Companion Fix PRs** (`.github/workflows/codemender.yml` & `cloudbuild.yaml` using `cm find . --diff=origin/main --fail-on=CRITICAL,HIGH`, automatic `[LEGACY / UNTOUCHED]` baseline filtering, SARIF upload, and `codemender/fix-pr-<N>` creation).

---

## 2. Repository Structure (`golang-standards/project-layout`)

```text
nodejs-goof/
├── .codemender/
│   └── config.yaml                     # Official Google Cloud CodeMender configuration
├── .github/
│   └── workflows/
│       └── codemender.yml              # Official 2-job GitHub Actions (scan + autofix PR)
├── cmd/
│   └── secretguard/
│       └── main.go                     # Pre-commit secrets scanner & Vertex AI SARIF summarizer
├── internal/
│   ├── scanner/
│   │   ├── scanner.go                  # Regex + entropy staged diff secret detector (<200ms)
│   │   └── scanner_test.go             # Unit tests for secret detection & allowlisting
│   ├── secrets/
│   │   └── manager.go                  # Google Secret Manager ADC client (PoLP, zero .env fallback)
│   └── vertex/
│       └── advisor.go                  # Official cloud.google.com/go/vertexai & aiplatform SDKs
├── deployments/
│   └── terraform/
│       ├── main.tf                     # Official WIF Pool, SAs, SARIF Bucket, Secret Manager, VPC-SC
│       ├── variables.tf                # Configurable model IDs, project, region, FinOps label vars
│       └── outputs.tf                  # Structured outputs (WIF provider, SA emails, Bucket URI)
├── scripts/
│   ├── setup-secure-repo.sh            # Runs cm init, syncs config.yaml, installs pre-commit hook
│   ├── install-hooks.sh                # Installs .git/hooks/pre-commit (secretguard + cm find --staged)
│   └── run-live-demo.sh                # Interactive 3-Act runner for the 15-minute live demo
├── service/
│   └── secret-manager.js               # Node.js Google Secret Manager ADC helper
├── tests/
│   └── security-regression.test.js     # Offline regression test suite run by `cm fix` in sandbox
├── cloudbuild.yaml                     # Official Cloud Build CodeMender pipeline + enterprise gates
├── Dockerfile                          # Multi-stage distroless container build (non-root UID 65532)
└── go.mod                              # Go module definition
```

---

## 3. Quickstart: Creating a Secure Repo & Pre-Commit Hook

### Prerequisites
1. Install the official CodeMender CLI (`cm`) and authenticate with Google Cloud Application Default Credentials (ADC):
   ```bash
   gcloud auth login
   gcloud auth application-default login
   export GOOGLE_CLOUD_PROJECT="your-gcp-project-id"
   export GOOGLE_CLOUD_LOCATION="us-central1"
   export CODEMENDER_MODEL="gemini-3.8-flash"
   ```
2. Pre-fetch Node.js dependencies on the host before running sandboxed commands (`permissive-closed` network profile blocks outbound network calls inside the sandbox):
   ```bash
   npm ci --ignore-scripts
   ```
3. Initialize the secure repository and install the pre-commit hook:
   ```bash
   chmod +x scripts/*.sh
   ./scripts/setup-secure-repo.sh
   ```

---

## 4. Running the 15-Minute Live Demo (3 Acts)

Use `./scripts/run-live-demo.sh` to step through the three acts of the live demonstration:

### Act 1: Pre-Commit Secrets Scanning & Google Secret Manager Enforcement (`0:00–4:00`)
```bash
# Stages a hardcoded Google Cloud API key in routes/index.js and attempts git commit
./scripts/run-live-demo.sh act1-secrets

# Reset back to clean Secret Manager ADC state
./scripts/run-live-demo.sh reset
```

### Act 2: Pre-Commit CodeMender Staged Scan, PoC Verification & 4-Step Patching (`4:00–10:00`)
```bash
# Stages an OS Command Injection vulnerability in routes/index.js and runs the pre-commit gate:
# cm find . --diff --staged --fail-on=CRITICAL,HIGH --model "${CODEMENDER_MODEL:-gemini-3.8-flash}"
./scripts/run-live-demo.sh act2-precommit

# 1. Inspect the open CRITICAL finding
cm report --status=OPEN

# 2. Verify exploitability inside the local exebox sandbox (generates & runs safe PoC exploit)
cm verify <FINDING_ID>

# 3. Generate & validate root-cause patch (4-step loop: patch -> sandbox apply -> npm test -> re-run PoC)
cm fix <FINDING_ID>

# 4. Review the verified diff and stage the patched file for commit
cm vcs diff
cm vcs stage
```

### Act 3: CI/CD Pull Request Security Gate (`[LEGACY / UNTOUCHED]` vs. Net-New Block & Autofix PR) (`10:00–15:00`)
```bash
# Runs the CI/CD PR Diff Scan against the base branch:
# Pre-existing nodejs-goof issues are labeled [LEGACY / UNTOUCHED] while PR-introduced CRITICAL/HIGH bugs fail the gate
./scripts/run-live-demo.sh act3-cicd
```

---

## 5. Deploying Enterprise Infrastructure & CI/CD Gates with Terraform

Provision the Workload Identity Federation pool, least-privilege Service Accounts (`roles/aiplatform.user`), KMS-encrypted SARIF GCS bucket, Google Secret Manager secrets, Cloud Build PR trigger, and VPC Service Controls perimeter:

```bash
cd deployments/terraform
terraform init
terraform plan \
  -var="project_id=${GOOGLE_CLOUD_PROJECT}" \
  -var="environment=prod" \
  -var="region=us-central1" \
  -var="github_org=iuriikogan" \
  -var="github_repo=nodejs-goof" \
  -var="access_policy_id=1234567890" \
  -var="codemender_default_model=gemini-3.8-flash" \
  -var="codemender_complex_model=gemini-3.1-pro"
```
