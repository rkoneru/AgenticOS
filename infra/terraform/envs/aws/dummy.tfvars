# Fabricated-but-well-formed values for `terraform plan` with no real AWS
# account. Never use these for a real deployment.

region        = "us-east-1"
dev_plan_mode = true
env_name      = "axis-dev-dummy"
azs           = ["us-east-1a", "us-east-1b"]

db_password = "DummyPlanOnlyPassword123!"

# Fake-but-well-formed ARNs; a real deployer supplies real IAM role ARNs.
cluster_role_arn = "arn:aws:iam::123456789012:role/axis-eks-cluster-role"
node_role_arn    = "arn:aws:iam::123456789012:role/axis-eks-node-role"

# Fake AMI id, well-formed (ami-xxxxxxxxxxxxxxxxx), never resolved against a
# real account in plan-only/dev mode.
clickhouse_ami_id = "ami-0123456789abcdef0"
