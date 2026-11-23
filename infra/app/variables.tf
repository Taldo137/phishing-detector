variable "aws_region" {
  type    = string
  default = "eu-north-1" # the only region the account allows
}

variable "image_tag" {
  description = "App image tag in ECR (git short SHA printed by scripts/push_image.ps1)."
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.micro"
}

variable "asg_min" {
  description = "2 = one instance per AZ."
  type        = number
  default     = 2
}

variable "asg_max" {
  type    = number
  default = 3
}

variable "enable_cache" {
  description = "Create the ElastiCache result cache (bonus). The app works without it."
  type        = bool
  default     = true
}

variable "log_retention_days" {
  type    = number
  default = 7
}
