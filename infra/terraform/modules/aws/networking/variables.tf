variable "name" {
  description = "Name prefix for networking resources (e.g. axis-dedicated-tenantx)."
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.60.0.0/16"
}

variable "azs" {
  description = "Availability zone names to spread subnets across. No data-source lookup is used here on purpose (see module README) -- pass the real AZ names for the target region."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets, one per AZ."
  type        = list(string)
  default     = ["10.60.0.0/20", "10.60.16.0/20"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets, one per AZ."
  type        = list(string)
  default     = ["10.60.128.0/20", "10.60.144.0/20"]
}

variable "enable_nat_gateway" {
  description = "Create a NAT gateway per AZ for private-subnet egress. Costs money; disable for a plan-only dry run."
  type        = bool
  default     = true
}

variable "tags" {
  description = "Common tags applied to every resource in this module."
  type        = map(string)
  default     = {}
}
