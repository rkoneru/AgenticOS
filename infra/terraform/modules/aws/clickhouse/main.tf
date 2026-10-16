# Self-managed ClickHouse on an EC2 autoscaling group. AWS has no managed
# ClickHouse product (as GCP/Azure also do not), so AXIS runs ClickHouse
# itself -- either here (bare EC2) or via the Phase 10 Helm chart on the EKS
# cluster from modules/aws/k8s. This module is the "self-managed VM" option;
# it is intentionally simple (one ASG, one EBS data volume spec per node via
# the launch template's block device mapping) and does not implement
# ClickHouse Keeper/cluster replication topology -- that is configured by
# `var.user_data` or a post-provision configuration-management step.

resource "aws_launch_template" "this" {
  name_prefix   = "${var.name}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_name

  block_device_mappings {
    device_name = "/dev/xvdf"
    ebs {
      volume_size = var.data_volume_size_gb
      volume_type = "gp3"
      encrypted   = true
    }
  }

  vpc_security_group_ids = var.security_group_ids

  user_data = var.user_data != "" ? base64encode(var.user_data) : null

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = var.name })
  }
}

resource "aws_autoscaling_group" "this" {
  name                = "${var.name}-asg"
  desired_capacity    = var.desired_capacity
  min_size            = var.desired_capacity
  max_size            = var.desired_capacity
  vpc_zone_identifier = var.subnet_ids

  launch_template {
    id      = aws_launch_template.this.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = var.name
    propagate_at_launch = true
  }
}
