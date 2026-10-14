# The LLM gateway on Cloud Run, with what it needs and nothing more:
#
#   Artifact Registry   the image
#   service account     the gateway's identity: its own secrets and its own bucket, nothing else
#   Secret Manager      the provider API keys (values added out of band), the config, the policy
#   Cloud Storage       the state directory (ledger.json, usage.jsonl), mounted as a volume
#   Cloud Run           the service, 0 to 1 instance (cloud_run.tf)
#   billing budget      an optional alert on this project's spend (budget.tf)
#
# deploy/README.md has the steps. None of this has been applied to a real project.

provider "google" {
  project = var.project_id
  region  = var.region

  # Bill API calls to this project. The Billing Budgets API (budget.tf) refuses calls made with
  # user credentials unless they name a quota project.
  billing_project       = var.project_id
  user_project_override = true
}

locals {
  config_file = coalesce(var.gateway_config_file, "${path.module}/../k8s/llm-gateway.config.json")
  policy_file = coalesce(var.leak_policy_file, "${path.module}/../../llm-policy.example.json")
  config      = jsondecode(file(local.config_file))

  # Paths inside the container, the same as in the Dockerfile and the Kubernetes manifests.
  config_dir = "/etc/agent-gate/config"
  policy_dir = "/etc/agent-gate/policy"
  state_dir  = "/var/lib/agent-gate"

  # The environment variables the gateway reads its provider keys from: every apiKeyEnv in the
  # config, once. The config is the only list, and upstreams of one provider share its key.
  provider_key_envs = toset([for upstream in local.config.upstreams : upstream.apiKeyEnv])

  image = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}/llm-gateway:${var.image_tag}"

  apis = concat(
    ["artifactregistry.googleapis.com", "iam.googleapis.com", "run.googleapis.com", "secretmanager.googleapis.com", "storage.googleapis.com"],
    var.enable_budget_alert ? ["billingbudgets.googleapis.com", "cloudresourcemanager.googleapis.com"] : [],
  )
}

resource "google_project_service" "apis" {
  for_each = toset(local.apis)
  service  = each.value
  # Left on at destroy: other things in the project may use them.
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "images" {
  location      = var.region
  repository_id = "agent-gate"
  format        = "DOCKER"
  description   = "agent-gate container images"

  docker_config {
    # A pushed tag cannot be moved, so image_tag always means the same bytes.
    immutable_tags = true
  }

  depends_on = [google_project_service.apis]
}

# The gateway's identity. It has no project-wide role. It gets read access to its own secrets and
# object access in its own bucket (below), and nothing else: Cloud Run pulls the image from this
# project's registry with its own service agent, and container logs reach Cloud Logging without a
# role on this account.
resource "google_service_account" "gateway" {
  account_id   = "llm-gateway"
  display_name = "agent-gate LLM gateway"
  description  = "Runs the LLM gateway on Cloud Run. Reads its own secrets, reads and writes its own state bucket."
  depends_on   = [google_project_service.apis]
}

# One secret per provider key. Terraform creates the secret and never a version: the value is
# added out of band, so it is never in this code, a plan or the state file:
#   printf %s "$PROVIDER_A_API_KEY" | gcloud secrets versions add llm-gateway-provider-a-api-key --data-file=-
resource "google_secret_manager_secret" "provider_key" {
  for_each  = local.provider_key_envs
  secret_id = "llm-gateway-${lower(replace(each.value, "_", "-"))}"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_iam_member" "provider_key" {
  for_each  = google_secret_manager_secret.provider_key
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gateway.email}"
}

# The config and the leak-guard policy, as files. Cloud Run has no ConfigMap; a Secret Manager
# volume is how a file gets into a Cloud Run container. Neither file is secret (the config holds
# the SHA-256 of each gateway key, not the key), so unlike the provider keys their content is
# managed here: an edit makes a new version, which the service pins, so it also rolls out a new
# revision.
locals {
  files = {
    config = local.config_file
    policy = local.policy_file
  }
}

resource "google_secret_manager_secret" "file" {
  for_each  = local.files
  secret_id = "llm-gateway-${each.key}-file"

  replication {
    auto {}
  }

  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "file" {
  for_each    = local.files
  secret      = google_secret_manager_secret.file[each.key].id
  secret_data = file(each.value)
}

resource "google_secret_manager_secret_iam_member" "file" {
  for_each  = google_secret_manager_secret.file
  secret_id = each.value.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.gateway.email}"
}

# The state directory. Cloud Run's own filesystem is in memory and is gone when an instance stops,
# which with min instances 0 happens after every idle spell: without this bucket, every cold start
# would reset every budget to zero. force_destroy is off, so terraform destroy refuses to delete a
# bucket that still holds a ledger.
resource "google_storage_bucket" "state" {
  name                        = "${var.project_id}-llm-gateway-state"
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  depends_on = [google_project_service.apis]
}

resource "google_storage_bucket_iam_member" "state" {
  bucket = google_storage_bucket.state.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.gateway.email}"
}
