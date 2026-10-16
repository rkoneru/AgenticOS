# aws/clickhouse

Self-managed ClickHouse on an EC2 autoscaling group with gp3 EBS data
volumes. AWS (like GCP and Azure) has no managed ClickHouse service, so
AXIS self-hosts it: either here (bare VM) or as a StatefulSet via the Phase
10 Helm chart on the `modules/aws/k8s` cluster. This module does not
configure ClickHouse clustering/replication itself -- that is the job of
`var.user_data` (cloud-init) or an external configuration tool.

`ami_id` has **no default**: picking one would require either a
`data "aws_ami"` "most recent" lookup (a live EC2 call this project avoids
on principle for `plan`) or baking in a hard-coded, region-specific,
silently-stale AMI ID. Callers must pass a real AMI ID for their region and
distro of choice.
