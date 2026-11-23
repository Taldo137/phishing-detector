variable "aws_region" {
  description = "AWS region. eu-north-1 because the account's Organization SCP denies all other regions."
  type        = string
  default     = "eu-north-1"
}

variable "alert_email" {
  description = "Email address that receives CloudWatch alarm notifications (confirm the subscription once)."
  type        = string

  validation {
    condition     = can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", var.alert_email))
    error_message = "alert_email must be a valid email address."
  }
}

variable "db_instance_class" {
  description = "RDS instance class. Smallest Graviton class: cheapest option that runs PostgreSQL 16."
  type        = string
  default     = "db.t4g.micro"
}

variable "log_retention_days" {
  description = "Retention of the RDS PostgreSQL log group (AWS would keep it forever by default)."
  type        = number
  default     = 7
}
