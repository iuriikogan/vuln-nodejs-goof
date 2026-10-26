output "workload_identity_provider_name" {
  description = "Full resource name of the GitHub OIDC Workload Identity Provider (set as GCP_WORKLOAD_IDENTITY_PROVIDER in GitHub Actions)"
  value       = google_iam_workload_identity_pool_provider.github_provider.name
}

output "github_actions_service_account_email" {
  description = "Email of the least-privilege CodeMender GitHub Actions Service Account (set as GCP_SERVICE_ACCOUNT in GitHub Actions)"
  value       = google_service_account.codemender_ci_sa.email
}

output "cloud_build_service_account_email" {
  description = "Email of the least-privilege CodeMender Cloud Build Service Account"
  value       = google_service_account.codemender_build_sa.email
}

output "sarif_reports_bucket_uri" {
  description = "Cloud KMS-encrypted GCS Bucket URI for archiving CodeMender SARIF reports"
  value       = google_storage_bucket.sarif_reports_bkt.url
}

output "sarif_reports_bucket_self_link" {
  description = "Self-link of the CodeMender SARIF reports GCS bucket"
  value       = google_storage_bucket.sarif_reports_bkt.self_link
}

output "artifact_registry_uri" {
  description = "Artifact Registry Docker endpoint URI"
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.container_repo.repository_id}"
}

output "cloudbuild_trigger_id" {
  description = "Resource ID of the CodeMender Cloud Build pull request trigger"
  value       = google_cloudbuild_trigger.codemender_pr_trigger.id
}

output "vpc_sc_perimeter_name" {
  description = "Resource name of the VPC Service Controls perimeter protecting Vertex AI and Secret Manager"
  value       = google_access_context_manager_service_perimeter.codemender_vpc_sc.name
}
