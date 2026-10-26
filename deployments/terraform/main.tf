terraform {
  required_version = ">= 1.6.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}

locals {
  # Hierarchical naming convention (Objective 6.1): {project}-{env}-{region}-{service}-{resource_type}
  name_prefix = "${var.project_id}-${var.environment}-${var.region}-${var.service_name}"

  # Mandatory FinOps & Governance Labels (Objective 6.2)
  common_labels = {
    environment = var.environment
    owner       = var.owner
    cost-center = var.cost_center
    managed-by  = "terraform"
    service     = var.service_name
  }
}

provider "google" {
  project      = var.project_id
  region       = var.region
  default_labels = local.common_labels
}

# 1. Enable Required Google Cloud APIs (set-up-environment.md)
resource "google_project_service" "required_apis" {
  for_each = toset([
    "aiplatform.googleapis.com",
    "cloudresourcemanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudkms.googleapis.com",
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "accesscontextmanager.googleapis.com",
  ])
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# 2. Cloud KMS KeyRing & Customer-Managed Encryption Key (CMEK) for SARIF Reports & Artifacts
resource "google_kms_key_ring" "codemender_kr" {
  name     = "${local.name_prefix}-kr"
  location = var.region
  depends_on = [google_project_service.required_apis]
}

resource "google_kms_crypto_key" "codemender_cmek" {
  name            = "${local.name_prefix}-cmek"
  key_ring        = google_kms_key_ring.codemender_kr.id
  rotation_period = "7776000s" # 90-day key rotation (SCC / tfsec compliance)
  labels          = local.common_labels

  lifecycle {
    prevent_destroy = true
  }
}

# 3. Access Logs Bucket & KMS-Encrypted SARIF Report Bucket (integrate-with-cicd.md)
resource "google_storage_bucket" "access_logs_bkt" {
  name                        = "${local.name_prefix}-logs-bkt"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.common_labels

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.codemender_cmek.id
  }
}

resource "google_storage_bucket" "sarif_reports_bkt" {
  name                        = "${local.name_prefix}-sarif-bkt"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  labels                      = local.common_labels

  versioning {
    enabled = true
  }

  logging {
    log_bucket        = google_storage_bucket.access_logs_bkt.name
    log_object_prefix = "sarif-bucket-access/"
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.codemender_cmek.id
  }

  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
}

# 4. Least-Privilege Service Accounts for GitHub Actions & Cloud Build (integrate-with-cicd.md)
resource "google_service_account" "codemender_ci_sa" {
  account_id   = "${var.environment}-${var.service_name}-ci-sa"
  display_name = "CodeMender GitHub Actions Service Account (${local.name_prefix}-ci-sa)"
  description  = "Keyless WIF Service Account for CodeMender GitHub Actions scan and autofix jobs"
}

resource "google_service_account" "codemender_build_sa" {
  account_id   = "${var.environment}-${var.service_name}-cb-sa"
  display_name = "CodeMender Cloud Build Service Account (${local.name_prefix}-cb-sa)"
  description  = "Least-privilege Service Account for CodeMender Cloud Build pipeline"
}

# PoLP IAM Bindings: roles/aiplatform.user (Objective 2.3 & integrate-with-cicd.md)
resource "google_project_iam_member" "ci_sa_aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.codemender_ci_sa.email}"
}

resource "google_project_iam_member" "build_sa_aiplatform_user" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.codemender_build_sa.email}"
}

resource "google_storage_bucket_iam_member" "build_sa_sarif_writer" {
  bucket = google_storage_bucket.sarif_reports_bkt.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.codemender_build_sa.email}"
}

# 5. Keyless Workload Identity Federation for GitHub Actions (integrate-with-cicd.md)
resource "google_iam_workload_identity_pool" "github_pool" {
  workload_identity_pool_id = "${var.environment}-${var.service_name}-gh-pool"
  display_name              = "GitHub Actions Pool"
  description               = "Workload Identity Pool for ${var.github_org}/${var.github_repo}"
  depends_on                = [google_project_service.required_apis]
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC Provider"

  attribute_mapping = {
    "google.subject"             = "assertion.sub"
    "attribute.repository"       = "assertion.repository"
    "attribute.repository_owner" = "assertion.repository_owner"
  }

  attribute_condition = "assertion.repository_owner == '${var.github_org}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account_iam_member" "github_wif_binding" {
  service_account_id = google_service_account.codemender_ci_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool.name}/attribute.repository/${var.github_org}/${var.github_repo}"
}

# 6. Google Secret Manager Application Secrets (Objective 2.3 — Zero Hardcoded Secrets)
resource "google_secret_manager_secret" "app_secrets" {
  for_each = toset([
    "nodejs-goof-service-token",
    "nodejs-goof-admin-password",
    "nodejs-goof-mysql-password",
  ])
  secret_id = each.value
  labels    = local.common_labels

  replication {
    user_managed {
      replicas {
        location = var.region
        customer_managed_encryption {
          kms_key_name = google_kms_crypto_key.codemender_cmek.id
        }
      }
    }
  }
  depends_on = [google_project_service.required_apis]
}

resource "google_secret_manager_secret_iam_member" "build_sa_secret_accessor" {
  for_each  = google_secret_manager_secret.app_secrets
  secret_id = each.value.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.codemender_build_sa.email}"
}

# 7. Artifact Registry Repository with Container Scanning
resource "google_artifact_registry_repository" "container_repo" {
  location      = var.region
  repository_id = "${local.name_prefix}-ar"
  description   = "Hardened container repository for CodeMender-secured nodejs-goof"
  format        = "DOCKER"
  kms_key_name  = google_kms_crypto_key.codemender_cmek.id
  labels        = local.common_labels
  depends_on    = [google_project_service.required_apis]
}

# 8. Official Cloud Build PR Trigger (integrate-with-cicd.md)
resource "google_cloudbuild_trigger" "codemender_pr_trigger" {
  name            = "${local.name_prefix}-pr-trigger"
  location        = var.region
  description     = "Runs CodeMender diff scan and enterprise security gates on pull requests"
  service_account = google_service_account.codemender_build_sa.id
  filename        = "cloudbuild.yaml"

  github {
    owner = var.github_org
    name  = var.github_repo
    pull_request {
      branch = "^main$"
    }
  }

  substitutions = {
    _BASE_BRANCH          = "main"
    _FAIL_ON              = "CRITICAL,HIGH"
    _GCP_LOCATION         = var.region
    _CODEMENDER_MODEL     = var.codemender_default_model
    _CODEMENDER_PRO_MODEL = var.codemender_complex_model
    _REPORT_BUCKET        = google_storage_bucket.sarif_reports_bkt.name
  }
}

# 9. VPC Service Controls Perimeter Protecting Vertex AI & Secret Manager (Objective 4.4)
resource "google_access_context_manager_service_perimeter" "codemender_vpc_sc" {
  parent = "accessPolicies/${var.access_policy_id}"
  name   = "accessPolicies/${var.access_policy_id}/servicePerimeters/${replace(var.service_name, "-", "_")}_${var.environment}_perimeter"
  title  = "${local.name_prefix}-vpc-sc"

  status {
    restricted_services = [
      "aiplatform.googleapis.com",
      "secretmanager.googleapis.com",
      "storage.googleapis.com",
      "artifactregistry.googleapis.com",
    ]
  }
}
