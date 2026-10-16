# aws/networking

VPC with one public and one private subnet per AZ, an internet gateway, and
(optionally) one NAT gateway per AZ for private-subnet egress.

## Why `azs` is a variable, not a data source

A `data "aws_availability_zones" "available" {}` lookup is the idiomatic way
to write this module, but it requires a real, authenticated `ec2:DescribeAvailabilityZones`
call -- which fails during `terraform plan` with no live AWS credentials
(this repo's Phase 10 constraint: no real cloud account, ever). Instead this
module takes `azs`, `public_subnet_cidrs` and `private_subnet_cidrs` as
variables with documented two-AZ `us-east-1` defaults. Operators targeting a
different region must override all three to the real AZ names and matching
CIDRs for that region.

## Inputs / outputs

See `variables.tf` / `outputs.tf`.
