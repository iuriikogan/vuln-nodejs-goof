variable "project_id" {
  description = "Google Cloud Project ID hosting CodeMender Vertex AI and CI/CD resources"
  type        = string
}

variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  default     = "prod"
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be one of: dev, staging, prod."
  }
}

variable "region" {
  description = "Primary Google Cloud region for resources"
  type        = string
  default     = "us-central1"
}

variable "service_name" {
  description = "Service identifier used in hierarchical resource naming"
  type        = string
  default     = "codemender"
}

variable "owner" {
  description = "Team or owner identifier for FinOps resource governance labels"
  type        = string
  default     = "appsec-engineering"
}

variable "cost_center" {
  description = "Cost center code for FinOps attribution"
  type        = string
  default     = "cc-security-ai"
}

variable "github_org" {
  description = "GitHub organization or user owner allowed to authenticate via Workload Identity Federation"
  type        = string
  default     = "iuriikogan"
}

variable "github_repo" {
  description = "GitHub repository name for CodeMender PR scanning and autofix"
  type        = string
  default     = "vuln-nodejs-goof"
}

variable "access_policy_id" {
  description = "Organization Access Context Manager Policy ID for VPC Service Controls"
  type        = string
}

variable "codemender_default_model" {
  description = "Default Gemini model ID for CodeMender scanning, verification, and routine patching (Objective 4.2)"
  type        = string
  default     = "gemini-3.8-flash"
}

variable "codemender_complex_model" {
  description = "Gemini Pro model ID reserved for complex multi-step reasoning and large-context synthesis (Objective 4.2)"
  type        = string
  default     = "gemini-3.1-pro"
}
