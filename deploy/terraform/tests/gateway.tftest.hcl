# Plan-only tests with a mocked google provider: no credentials, no project, nothing is created.
# They check what this configuration derives from the gateway config and the variables.
#   terraform init -backend=false && terraform test

mock_provider "google" {}

variables {
  project_id = "example-project"
  region     = "europe-west1"
}

run "defaults" {
  command = plan

  assert {
    condition     = toset(keys(google_secret_manager_secret.provider_key)) == toset(["PROVIDER_A_API_KEY", "PROVIDER_B_API_KEY"])
    error_message = "There must be one secret per distinct apiKeyEnv in the config (3 upstreams, 2 keys)."
  }

  assert {
    condition     = google_secret_manager_secret.provider_key["PROVIDER_A_API_KEY"].secret_id == "llm-gateway-provider-a-api-key"
    error_message = "Provider key secrets are named llm-gateway-<variable name in lowercase, with hyphens>."
  }

  assert {
    condition     = toset([for env in google_cloud_run_v2_service.gateway.template[0].containers[0].env : env.name]) == toset(["PROVIDER_A_API_KEY", "PROVIDER_B_API_KEY"])
    error_message = "Every provider key must reach the container as the environment variable the config names."
  }

  assert {
    condition     = google_cloud_run_v2_service.gateway.scaling[0].min_instance_count == 0 && google_cloud_run_v2_service.gateway.scaling[0].max_instance_count == 1
    error_message = "The service must scale between 0 and 1 instance (single-writer ledger)."
  }

  assert {
    condition     = google_cloud_run_v2_service.gateway.template[0].containers[0].ports[0].container_port == 8787
    error_message = "The container port must be listen.port from the config."
  }

  assert {
    condition     = google_cloud_run_v2_service.gateway.template[0].volumes[2].gcs[0].bucket == "example-project-llm-gateway-state"
    error_message = "The state volume must be the project's state bucket."
  }

  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.invoker) == 0 && length(google_billing_budget.gateway) == 0
    error_message = "By default nobody may call the service and there is no budget."
  }
}

run "invokers_and_budget" {
  command = plan

  variables {
    invoker_members     = ["serviceAccount:agent@example-project.iam.gserviceaccount.com"]
    enable_budget_alert = true
    billing_account_id  = "000000-000000-000000"
  }

  assert {
    condition     = length(google_cloud_run_v2_service_iam_member.invoker) == 1 && length(google_billing_budget.gateway) == 1
    error_message = "One invoker binding per member, and a budget when it is enabled."
  }
}

run "budget_needs_a_billing_account" {
  command = plan

  variables {
    enable_budget_alert = true
  }

  expect_failures = [google_billing_budget.gateway]
}

run "config_that_listens_on_localhost_is_refused" {
  command = plan

  # The repository's example config listens on 127.0.0.1 and keeps state in .agent-gate.
  variables {
    gateway_config_file = "../../llm-gateway.config.example.json"
  }

  expect_failures = [google_cloud_run_v2_service.gateway]
}

run "project_name_is_not_a_project_id" {
  command = plan

  variables {
    project_id = "My Project"
  }

  expect_failures = [var.project_id]
}
