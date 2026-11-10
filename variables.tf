variable "aws_region" {
  description = "AWS Region for deployment."
  type        = string
  default     = "ap-southeast-2"
}

variable "aws_profile" {
  description = "Optional AWS CLI profile name. Leave null to use standard environment variables or default credentials."
  type        = string
  default     = null
}

variable "project_name" {
  description = "Prefix used for naming AWS resources and SSM Parameter Store paths."
  type        = string
  default     = "cf-china-beacon"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC."
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for the Multi-AZ public subnets (one per Availability Zone)."
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "instance_type" {
  description = "EC2 instance type (t4g.micro is Free Tier eligible and the lowest-cost Graviton2 instance available on Free/Paid plans)."
  type        = string
  default     = "t4g.micro"
}

variable "china_office_cidrs" {
  description = "List of public IPv4 CIDRs for China office locations to EXCLUDE (packets from these IPs on TCP 443 will be rejected so office users do not match the roaming China profile)."
  type        = list(string)
  default     = []
}

variable "allowed_test_cidrs" {
  description = "Optional list of additional IPv4 CIDRs (e.g., admin workstation IP outside China) allowed to reach TCP 443 for testing and certificate verification."
  type        = list(string)
  default     = []
}
