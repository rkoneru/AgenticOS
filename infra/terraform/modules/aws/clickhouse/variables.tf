variable "name" {
  type = string
}

variable "ami_id" {
  description = "AMI ID for the ClickHouse node (e.g. a pre-baked AXIS ClickHouse image, or a stock Ubuntu/Debian AMI with a user-data bootstrap). Taken as a variable with no default on purpose: there is no sane region-independent default AMI, and this module must never look one up via `data \"aws_ami\"` (that needs a live EC2 call). Callers MUST set this per region."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "m6i.2xlarge"
}

variable "subnet_ids" {
  description = "Private subnet IDs for the ClickHouse autoscaling group."
  type        = list(string)
}

variable "security_group_ids" {
  type = list(string)
}

variable "desired_capacity" {
  description = "Node count. AWS has no managed ClickHouse service (unlike RDS/ElastiCache), so this module runs ClickHouse self-managed on EC2; a sharded/replicated topology beyond a single ASG is out of scope here (see README)."
  type        = number
  default     = 3
}

variable "data_volume_size_gb" {
  type    = number
  default = 500
}

variable "key_name" {
  description = "EC2 key pair name for SSH access. Optional."
  type        = string
  default     = null
}

variable "user_data" {
  description = "Cloud-init / user-data script that installs and configures ClickHouse on boot. Left as a variable (not hard-coded) so the caller supplies the real bootstrap; defaults to an empty string (bare instances) for `plan`-only validation."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
