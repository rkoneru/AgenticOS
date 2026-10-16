# AWS EKS cluster + one managed node group. Deliberately avoids any
# `data "aws_ami"` / SSM "latest AMI" lookup: `node_ami_type` selects an
# EKS-managed AMI family by name (resolved by the EKS service at node-group
# creation time, not by Terraform), so plan does not need an image query.

resource "aws_eks_cluster" "this" {
  name     = var.cluster_name
  role_arn = var.cluster_role_arn
  version  = var.kubernetes_version

  vpc_config {
    subnet_ids              = var.subnet_ids
    endpoint_public_access  = var.endpoint_public_access
    endpoint_private_access = true
  }

  tags = var.tags
}

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "${var.cluster_name}-default"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.subnet_ids
  instance_types  = var.node_instance_types
  ami_type        = var.node_ami_type

  scaling_config {
    desired_size = var.desired_size
    min_size     = var.min_size
    max_size     = var.max_size
  }

  tags = var.tags
}
