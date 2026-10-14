output "service_url" {
  description = "The gateway's URL. Clients use <service_url>/v1 as their OpenAI base URL."
  value       = google_cloud_run_v2_service.gateway.uri
}

output "image" {
  description = "The image the service runs. Push it before the first full apply."
  value       = local.image
}

output "docker_repository" {
  description = "The Artifact Registry repository to push images to."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.images.repository_id}"
}

output "provider_key_secrets" {
  description = "Environment variable name to the Secret Manager secret that holds its value. Add each value out of band with gcloud secrets versions add."
  value       = { for name, secret in google_secret_manager_secret.provider_key : name => secret.secret_id }
}

output "service_account_email" {
  description = "The identity the gateway runs as."
  value       = google_service_account.gateway.email
}

output "state_bucket" {
  description = "The bucket that holds ledger.json and usage.jsonl."
  value       = google_storage_bucket.state.name
}
