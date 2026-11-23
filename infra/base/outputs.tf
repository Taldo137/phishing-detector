# Read by the app stack (terraform_remote_state) and by scripts/push_image.*.
# No secret values: only the ARN of the secret, never its content.

output "aws_region" {
  value = var.aws_region
}

output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "rds_security_group_id" {
  value = aws_security_group.rds.id
}

output "db_identifier" {
  value = aws_db_instance.main.identifier
}

output "db_endpoint" {
  description = "Hostname only (no port)."
  value       = aws_db_instance.main.address
}

output "db_port" {
  value = aws_db_instance.main.port
}

output "db_name" {
  value = aws_db_instance.main.db_name
}

output "db_username" {
  value = aws_db_instance.main.username
}

output "db_master_secret_arn" {
  description = "Secrets Manager secret (managed by RDS) holding the master username and password."
  value       = aws_db_instance.main.master_user_secret[0].secret_arn
}

output "ecr_repository_url" {
  value = aws_ecr_repository.app.repository_url
}

output "ecr_repository_arn" {
  value = aws_ecr_repository.app.arn
}

output "alerts_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
