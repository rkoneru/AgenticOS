# aws/k8s

EKS cluster with one managed node group.

## Live-API-dependency note

`cluster_role_arn` and `node_role_arn` are inputs, not managed by this
module: IAM role creation is out of scope here (kept in a separate,
not-yet-written `modules/aws/iam` or handled by the platform team's existing
IAM tooling) so this module has no `aws_iam_role`/`aws_iam_role_policy_attachment`
coupling to manage. `node_ami_type` picks a named EKS-managed AMI family
instead of a `data "aws_ami"` "most recent" lookup, so `terraform plan` never
issues an EC2/SSM image query.

`terraform validate` passes with no credentials. `terraform plan` additionally
needs `eks:DescribeCluster`-shaped read access during a *real* plan against an
existing cluster (not applicable to a from-scratch create plan, which only
needs the API to be reachable); with dummy AWS keys and the provider's
`skip_*` flags (see `envs/aws/providers.tf`) a from-scratch create plan for
this module still requires one live STS/EKS call in some provider versions
to resolve the partition/region for ARN construction -- see
`infra/terraform/envs/aws/README.md` for the exact observed result.
