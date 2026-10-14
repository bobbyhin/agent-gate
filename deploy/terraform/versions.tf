terraform {
  # Checked with Terraform 1.16.6 and google provider 8.7.0: fmt, validate and the mocked tests in
  # tests/. Never applied to a real project.
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 8.7"
    }
  }

  # State is local. A team keeps it in a Cloud Storage bucket instead, for example:
  #   backend "gcs" {
  #     bucket = "<your-terraform-state-bucket>"
  #     prefix = "agent-gate"
  #   }
}
