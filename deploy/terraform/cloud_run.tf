resource "google_cloud_run_v2_service" "gateway" {
  name                = "llm-gateway"
  location            = var.region
  ingress             = "INGRESS_TRAFFIC_ALL"
  deletion_protection = var.deletion_protection

  # Service-level scaling: 0 instances when idle (an idle gateway costs nothing) and at most 1,
  # because the ledger has a single writer (docs/adr/0003-single-writer-state.md).
  # ponytail: "at most 1" is not a hard guarantee. Cloud Run documents that the maximum "can be
  # exceeded for a brief period", for example in a traffic spike, and the gateway's lock directory
  # does not keep two instances apart on Cloud Storage FUSE, which has no file locking (the last
  # write wins). During such an overlap, bookings by one instance can be overwritten by the other,
  # and a cap can be passed by the calls made in that window. Exact caps under any load need the
  # shared store from the ADR.
  scaling {
    min_instance_count = 0
    max_instance_count = 1
  }

  template {
    service_account = google_service_account.gateway.email
    # Volume mounts need the second-generation execution environment.
    execution_environment = "EXECUTION_ENVIRONMENT_GEN2"
    # Longer than the gateway's longest call with the shipped config: two upstreams, each with
    # 2 attempts of timeoutMs 60000 plus 250 ms backoff, is 240.5 s.
    timeout                          = "300s"
    max_instance_request_concurrency = 80

    containers {
      image = local.image
      args  = ["llm", "serve", "--config", "${local.config_dir}/llm-gateway.config.json"]

      ports {
        container_port = try(local.config.listen.port, 8787)
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        # CPU only while requests are in flight (request-based billing). The gateway does no work
        # outside a request.
        cpu_idle = true
      }

      # One variable per provider key, from Secret Manager. "latest" is read when an instance
      # starts; after adding a new version, deploy a new revision to use it.
      dynamic "env" {
        for_each = google_secret_manager_secret.provider_key
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = env.value.secret_id
              version = "latest"
            }
          }
        }
      }

      volume_mounts {
        name       = "config"
        mount_path = local.config_dir
      }
      volume_mounts {
        name       = "policy"
        mount_path = local.policy_dir
      }
      volume_mounts {
        name       = "state"
        mount_path = local.state_dir
      }

      # Probes go to each instance's /healthz. Calls from outside should not rely on /healthz:
      # Cloud Run reserves some URL paths that end in "z".
      startup_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds    = 2
        failure_threshold = 15
      }
      liveness_probe {
        http_get {
          path = "/healthz"
        }
        period_seconds = 30
      }
    }

    volumes {
      name = "config"
      secret {
        secret = google_secret_manager_secret.file["config"].secret_id
        items {
          version = google_secret_manager_secret_version.file["config"].version
          path    = "llm-gateway.config.json"
        }
      }
    }

    volumes {
      name = "policy"
      secret {
        secret = google_secret_manager_secret.file["policy"].secret_id
        items {
          version = google_secret_manager_secret_version.file["policy"].version
          path    = "llm-policy.json"
        }
      }
    }

    # ponytail: Cloud Storage FUSE is not a POSIX disk. Every ledger update is a few object
    # operations (tens of milliseconds each), done with synchronous file calls that block the
    # gateway's event loop, so throughput is a few calls per second at best; and while
    # usage.jsonl is under 2 MiB, each appended line uploads the whole object again. Fine for a
    # team's gateway at low traffic; for more, move the state to a database (ADR 0003).
    volumes {
      name = "state"
      gcs {
        bucket    = google_storage_bucket.state.name
        read_only = false
        # The volume is owned by root unless told otherwise; the image runs as uid/gid 65532.
        mount_options = ["uid=65532", "gid=65532"]
      }
    }
  }

  lifecycle {
    precondition {
      condition     = try(local.config.listen.host, "") == "0.0.0.0"
      error_message = "The gateway config must listen on 0.0.0.0: Cloud Run sends requests to the container from outside it."
    }
    precondition {
      condition     = try(local.config.stateDir, "") == local.state_dir
      error_message = "The gateway config's stateDir must be ${local.state_dir}, the Cloud Storage volume. Anywhere else, the ledger would be lost whenever the instance stops."
    }
    precondition {
      condition     = try(local.config.policy, "") == "${local.policy_dir}/llm-policy.json"
      error_message = "The gateway config's policy must be ${local.policy_dir}/llm-policy.json, where the policy volume is mounted."
    }
  }

  # The service account must be able to read every secret and the bucket before the first revision
  # starts.
  depends_on = [
    google_secret_manager_secret_iam_member.provider_key,
    google_secret_manager_secret_iam_member.file,
    google_storage_bucket_iam_member.state,
  ]
}

# Who may call the service. Each caller sends its Google ID token in X-Serverless-Authorization,
# which Cloud Run checks, and its gateway key in Authorization, which the gateway checks.
resource "google_cloud_run_v2_service_iam_member" "invoker" {
  for_each = toset(var.invoker_members)
  project  = var.project_id
  location = google_cloud_run_v2_service.gateway.location
  name     = google_cloud_run_v2_service.gateway.name
  role     = "roles/run.invoker"
  member   = each.value
}
