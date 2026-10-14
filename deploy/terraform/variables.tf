variable "project_id" {
  description = "The Google Cloud project to deploy into."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id))
    error_message = "project_id must be a project ID (6 to 30 lowercase letters, digits or hyphens), not a project name or number."
  }
}

variable "region" {
  description = "Region for the Cloud Run service, the Artifact Registry repository and the state bucket, for example europe-west1. The ledger and the usage log stay in this region."
  type        = string
}

variable "image_tag" {
  description = "Tag of the llm-gateway image in this project's agent-gate Artifact Registry repository. Tags there are immutable, so a tag names exactly one build. The image must be pushed before the first full apply."
  type        = string
  default     = "0.1.0"
}

variable "gateway_config_file" {
  description = "Path to the gateway config to deploy. Default: deploy/k8s/llm-gateway.config.json, the file the Kubernetes manifests use too. Its listen, stateDir and policy must match the container paths (checked at plan time)."
  type        = string
  default     = null
}

variable "leak_policy_file" {
  description = "Path to the leak-guard policy to deploy. Default: llm-policy.example.json at the repository root."
  type        = string
  default     = null
}

variable "invoker_members" {
  description = "Principals allowed to call the service (roles/run.invoker), such as \"serviceAccount:agent@PROJECT.iam.gserviceaccount.com\". Empty: nobody can call it. \"allUsers\" makes it public, which leaves only the gateway keys between the internet and the provider budgets."
  type        = list(string)
  default     = []
}

variable "deletion_protection" {
  description = "Refuse to destroy the Cloud Run service. Set to false before terraform destroy."
  type        = bool
  default     = true
}

variable "enable_budget_alert" {
  description = "Create a billing budget that emails the billing account's admins at 50%, 90% and 100% of budget_amount. It covers this project's Google Cloud charges only, not the LLM providers' bills, and it alerts without stopping anything."
  type        = bool
  default     = false
}

variable "billing_account_id" {
  description = "Billing account ID (XXXXXX-XXXXXX-XXXXXX) for the budget. Needed only with enable_budget_alert, by a caller who may manage budgets on that account."
  type        = string
  default     = null
}

variable "budget_amount" {
  description = "Monthly budget, in whole units of budget_currency."
  type        = number
  default     = 50

  validation {
    condition     = var.budget_amount >= 1 && floor(var.budget_amount) == var.budget_amount
    error_message = "budget_amount must be a whole number of at least 1."
  }
}

variable "budget_currency" {
  description = "Currency of budget_amount. It must be the billing account's currency."
  type        = string
  default     = "USD"
}
