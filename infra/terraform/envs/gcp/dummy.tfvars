project_id = "axis-dev-dummy-000000"
region     = "us-east1"
env_name   = "axis-dev-dummy"

db_tier = "db-custom-4-16384"

# Well-formed but fake image self-link; never resolved without real creds.
clickhouse_image = "projects/debian-cloud/global/images/family/debian-12"

object_storage_bucket_name = "axis-dev-dummy-audit-export"
