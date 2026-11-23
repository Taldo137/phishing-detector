# Base stack: long-lived resources created before the demo (network, database, image
# registry, alert topic). The app stack (infra/app) reads its outputs.

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
  # Local state (gitignored). Production: S3 backend with locking.
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project     = "phishing-detector"
      Environment = "demo"
      ManagedBy   = "terraform"
      Stack       = "base"
    }
  }
}

# --- Network ---------------------------------------------------------------------
# One VPC in two AZs. Public subnets: ALB + EC2. Private subnets: RDS + cache, no internet route.
# No NAT Gateway (cost): EC2 gets public IPs for outbound traffic, but its security group
# accepts traffic only from the load balancer.

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs                  = slice(data.aws_availability_zones.available.names, 0, 2)
  public_subnet_cidrs  = ["10.0.1.0/24", "10.0.2.0/24"]
  private_subnet_cidrs = ["10.0.11.0/24", "10.0.12.0/24"]
}

resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "phishing-detector-vpc" }
}

# Locks down the default security group (it allows all traffic by default). Nothing uses it.
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "phishing-detector-default-sg-unused" }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "phishing-detector-igw" }
}

resource "aws_subnet" "public" {
  count = 2

  vpc_id                  = aws_vpc.main.id
  cidr_block              = local.public_subnet_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "phishing-detector-public-${local.azs[count.index]}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = { Name = "phishing-detector-public-rt" }
}

resource "aws_route_table_association" "public" {
  count = 2

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_subnet" "private" {
  count = 2

  vpc_id            = aws_vpc.main.id
  cidr_block        = local.private_subnet_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = { Name = "phishing-detector-private-${local.azs[count.index]}" }
}

# Only the implicit local route: the data tier has no internet access.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = { Name = "phishing-detector-private-rt" }
}

resource "aws_route_table_association" "private" {
  count = 2

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- Database: RDS PostgreSQL 16 --------------------------------------------------

resource "aws_db_subnet_group" "main" {
  name       = "phishing-detector-db"
  subnet_ids = aws_subnet.private[*].id

  tags = { Name = "phishing-detector-db-subnets" }
}

# No rules here: the app stack adds "5432 from ec2-sg", so the DB is closed when the app is down.
resource "aws_security_group" "rds" {
  name        = "phishing-detector-rds-sg"
  description = "PostgreSQL. Ingress is added by the app stack (5432 from ec2-sg only)."
  vpc_id      = aws_vpc.main.id

  tags = { Name = "phishing-detector-rds-sg" }
}

resource "aws_db_parameter_group" "postgres16" {
  name        = "phishing-detector-postgres16"
  family      = "postgres16"
  description = "Log slow queries; require TLS"

  parameter {
    name         = "log_min_duration_statement" # log queries slower than 500 ms
    value        = "500"
    apply_method = "immediate"
  }

  parameter {
    name         = "rds.force_ssl" # reject unencrypted connections
    value        = "1"
    apply_method = "pending-reboot"
  }
}

# Created by Terraform so it gets a retention (RDS would create it with "never expire").
resource "aws_cloudwatch_log_group" "rds_postgresql" {
  name              = "/aws/rds/instance/phishing-detector-db/postgresql"
  retention_in_days = var.log_retention_days
}

resource "aws_db_instance" "main" {
  identifier     = "phishing-detector-db"
  engine         = "postgres"
  engine_version = "16" # latest 16.x; minor upgrades do not show as drift
  instance_class = var.db_instance_class

  allocated_storage = 20
  storage_type      = "gp3"
  storage_encrypted = true

  db_name                     = "phishing"
  username                    = "phishadmin"
  manage_master_user_password = true # RDS generates the password and keeps it in Secrets Manager

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  parameter_group_name   = aws_db_parameter_group.postgres16.name
  publicly_accessible    = false
  multi_az               = false # cost; production: true

  backup_retention_period    = 1
  copy_tags_to_snapshot      = true
  skip_final_snapshot        = true # demo; production: false
  deletion_protection        = false
  apply_immediately          = true
  auto_minor_version_upgrade = true

  enabled_cloudwatch_logs_exports = ["postgresql"]
  performance_insights_enabled    = false # cost
  monitoring_interval             = 0     # cost

  depends_on = [aws_cloudwatch_log_group.rds_postgresql]

  tags = { Name = "phishing-detector-db" }
}

# --- Image registry ---------------------------------------------------------------

resource "aws_ecr_repository" "app" {
  name                 = "phishing-detector"
  image_tag_mutability = "MUTABLE" # `latest` moves; git SHA tags are never reused
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep only the last 5 images"
      selection = {
        tagStatus   = "any"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = { type = "expire" }
    }]
  })
}

# --- Alerts -------------------------------------------------------------------------
# In the base stack so the email subscription is confirmed once. Not SSE-encrypted: CloudWatch
# cannot publish to a topic using the AWS-managed key, and alarm messages are not sensitive.

resource "aws_sns_topic" "alerts" {
  name = "phishing-detector-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
