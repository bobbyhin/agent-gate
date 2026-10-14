# Optional: an email to the billing account's admins when this project's Google Cloud spend
# passes 50%, 90% and 100% of budget_amount in a month. Off by default, because it needs a billing
# account ID and permission to manage budgets on that account.
#
# It counts Google Cloud charges only: Cloud Run, Cloud Storage, Secret Manager, Artifact
# Registry. The LLM providers bill separately; the gateway's own daily and monthly caps per key
# are what limit that spend. A budget alerts, it does not stop anything.

data "google_project" "this" {
  count      = var.enable_budget_alert ? 1 : 0
  project_id = var.project_id
}

resource "google_billing_budget" "gateway" {
  count           = var.enable_budget_alert ? 1 : 0
  billing_account = var.billing_account_id
  display_name    = "agent-gate LLM gateway (${var.project_id})"

  budget_filter {
    projects = ["projects/${data.google_project.this[0].number}"]
  }

  amount {
    specified_amount {
      currency_code = var.budget_currency
      units         = tostring(var.budget_amount)
    }
  }

  dynamic "threshold_rules" {
    for_each = [0.5, 0.9, 1.0]
    content {
      threshold_percent = threshold_rules.value
    }
  }

  lifecycle {
    precondition {
      condition     = var.billing_account_id != null
      error_message = "enable_budget_alert needs billing_account_id."
    }
  }

  depends_on = [google_project_service.apis]
}
