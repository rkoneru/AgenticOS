# Root composition for one AWS "dedicated tenant" environment, matching the
# control-plane's dedicated-tenant deployment target described in
# docs/plans/phase-10.md and services/control-plane. Composes every
# modules/aws/* module; this is the thing a Phase 10 `k3s-homelab`-equivalent
# cloud profile ultimately targets (EKS instead of k3s).

module "networking" {
  source = "../../modules/aws/networking"

  name = var.env_name
  azs  = var.azs
}

module "kms" {
  source = "../../modules/aws/kms"

  alias = "alias/${var.env_name}"
}

module "k8s" {
  source = "../../modules/aws/k8s"

  cluster_name     = "${var.env_name}-eks"
  subnet_ids       = module.networking.private_subnet_ids
  cluster_role_arn = var.cluster_role_arn
  node_role_arn    = var.node_role_arn
}

module "postgres" {
  source = "../../modules/aws/postgres"

  identifier             = "${var.env_name}-pg"
  password               = var.db_password
  subnet_ids             = module.networking.private_subnet_ids
  vpc_security_group_ids = []
  kms_key_arn            = module.kms.key_arn
}

module "redis" {
  source = "../../modules/aws/redis"

  replication_group_id = "${var.env_name}-redis"
  subnet_ids           = module.networking.private_subnet_ids
  security_group_ids   = []
}

module "clickhouse" {
  source = "../../modules/aws/clickhouse"

  name               = "${var.env_name}-ch"
  ami_id             = var.clickhouse_ami_id
  subnet_ids         = module.networking.private_subnet_ids
  security_group_ids = []
}

module "object_storage" {
  source = "../../modules/aws/object-storage"

  bucket_name = "${var.env_name}-audit-export"
  kms_key_arn = module.kms.key_arn
}
