variable "cluster_name" {
  type = string
}

variable "kubernetes_version" {
  description = "EKS control-plane Kubernetes version."
  type        = string
  default     = "1.30"
}

variable "subnet_ids" {
  description = "Subnet IDs (private, typically) the control plane and nodes attach to."
  type        = list(string)
}

variable "cluster_role_arn" {
  description = "IAM role ARN for the EKS control plane (pre-created; this module does not manage IAM)."
  type        = string
}

variable "node_role_arn" {
  description = "IAM role ARN for the managed node group."
  type        = string
}

variable "node_instance_types" {
  type    = list(string)
  default = ["m6i.large"]
}

variable "node_ami_type" {
  description = "EKS-managed node group AMI type. A fixed, documented value -- not a looked-up 'latest AMI' data source -- so plan never needs an SSM/EC2 AMI query."
  type        = string
  default     = "AL2023_x86_64_STANDARD"
}

variable "desired_size" {
  type    = number
  default = 2
}

variable "min_size" {
  type    = number
  default = 2
}

variable "max_size" {
  type    = number
  default = 4
}

variable "endpoint_public_access" {
  type    = bool
  default = false
}

variable "tags" {
  type    = map(string)
  default = {}
}
