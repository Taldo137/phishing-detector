# App stack: deployed live in the demo. Reads the base stack's outputs.
# `terraform destroy` here leaves the database and its data untouched.
#
#   internet --80--> ALB --8000--> EC2 (ASG, 2 AZs) --5432--> RDS
#                                                   --6379--> ElastiCache (optional)

terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = local.tags
  }
}

data "terraform_remote_state" "base" {
  backend = "local"
  config  = { path = "${path.module}/../base/terraform.tfstate" }
}

locals {
  name = "phishing-detector"
  base = data.terraform_remote_state.base.outputs
  tags = { Project = "phishing-detector", Environment = "demo", ManagedBy = "terraform", Stack = "app" }
}

# --- Security groups: each layer only accepts traffic from the layer in front of it ---------
# No port 22 anywhere: shell access is through SSM Session Manager.

resource "aws_security_group" "alb" {
  name        = "${local.name}-alb-sg"
  description = "Application Load Balancer: HTTP from the internet"
  vpc_id      = local.base.vpc_id
}

resource "aws_security_group" "ec2" {
  name        = "${local.name}-ec2-sg"
  description = "App instances: port 8000 from the ALB only, no SSH"
  vpc_id      = local.base.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "alb_http" {
  security_group_id = aws_security_group.alb.id
  description       = "HTTP from anywhere (HTTPS needs a domain + certificate)"
  ip_protocol       = "tcp"
  from_port         = 80
  to_port           = 80
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_app" {
  security_group_id            = aws_security_group.alb.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.ec2.id
}

resource "aws_vpc_security_group_ingress_rule" "app_from_alb" {
  security_group_id            = aws_security_group.ec2.id
  ip_protocol                  = "tcp"
  from_port                    = 8000
  to_port                      = 8000
  referenced_security_group_id = aws_security_group.alb.id
}

resource "aws_vpc_security_group_egress_rule" "app_https_out" {
  security_group_id = aws_security_group.ec2.id
  description       = "ECR, Secrets Manager, CloudWatch, SSM, package repos"
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
  cidr_ipv4         = "0.0.0.0/0"
}

resource "aws_vpc_security_group_egress_rule" "app_to_rds" {
  security_group_id            = aws_security_group.ec2.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = local.base.rds_security_group_id
}

# The RDS security group is created empty by the base stack: the DB is closed without the app.
resource "aws_vpc_security_group_ingress_rule" "rds_from_app" {
  security_group_id            = local.base.rds_security_group_id
  description                  = "PostgreSQL from the app instances only"
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
  referenced_security_group_id = aws_security_group.ec2.id
}

# --- IAM: no access keys, the instances get short-lived credentials from their role ------------

resource "aws_iam_role" "app" {
  name = "${local.name}-ec2-role"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "sts:AssumeRole", Principal = { Service = "ec2.amazonaws.com" } }]
  })
}

resource "aws_iam_instance_profile" "app" {
  name = "${local.name}-ec2-profile"
  role = aws_iam_role.app.name
}

# AWS-managed: Session Manager (instead of SSH) and the CloudWatch agent (memory/disk, boot log).
resource "aws_iam_role_policy_attachment" "managed" {
  for_each   = toset(["AmazonSSMManagedInstanceCore", "CloudWatchAgentServerPolicy"])
  role       = aws_iam_role.app.name
  policy_arn = "arn:aws:iam::aws:policy/${each.key}"
}

# Our own permissions, scoped to exact resources.
resource "aws_iam_role_policy" "app" {
  name = "${local.name}-app-permissions"
  role = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = "ecr:GetAuthorizationToken", Resource = "*" }, # cannot be scoped
      { Effect = "Allow", Action = ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
      Resource = local.base.ecr_repository_arn },
      { Effect = "Allow", Action = "secretsmanager:GetSecretValue", Resource = local.base.db_master_secret_arn },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.app.arn}:*" },
    ]
  })
}

# --- Load balancer ------------------------------------------------------------------------

resource "aws_lb" "app" {
  name                       = "${local.name}-alb"
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.alb.id]
  subnets                    = local.base.public_subnet_ids
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name                 = "${local.name}-tg"
  port                 = 8000
  protocol             = "HTTP"
  vpc_id               = local.base.vpc_id
  deregistration_delay = 30

  # /health (liveness), not /health/ready: a DB outage must not mark every instance unhealthy
  # and make the ASG replace healthy instances in a loop.
  health_check {
    path                = "/health"
    interval            = 15
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# --- App instances: Auto Scaling Group across both AZs ------------------------------------

data "aws_ssm_parameter" "al2023_ami" {
  name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

resource "aws_launch_template" "app" {
  name                   = "${local.name}-app"
  image_id               = data.aws_ssm_parameter.al2023_ami.insecure_value
  instance_type          = var.instance_type
  update_default_version = true

  iam_instance_profile {
    arn = aws_iam_instance_profile.app.arn
  }

  network_interfaces {
    associate_public_ip_address = true # outbound internet without a NAT Gateway
    security_groups             = [aws_security_group.ec2.id]
  }

  # IMDSv2 only, hop limit 1: containers cannot read the instance credentials.
  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 8
      volume_type = "gp3"
      encrypted   = true
    }
  }

  # replace(): strip Windows line endings, bash on EC2 would fail on them.
  user_data = base64encode(replace(templatefile("${path.module}/user_data.sh", {
    region        = var.aws_region
    image         = "${local.base.ecr_repository_url}:${var.image_tag}"
    image_tag     = var.image_tag
    db_host       = local.base.db_endpoint
    db_name       = local.base.db_name
    db_user       = local.base.db_username
    db_secret_arn = local.base.db_master_secret_arn # the ARN only, never the password
    redis_url     = var.enable_cache ? "rediss://${aws_elasticache_replication_group.cache[0].primary_endpoint_address}:6379/0" : ""
    app_log_group = aws_cloudwatch_log_group.app.name
    agent_config  = local.cloudwatch_agent_config
  }), "\r", ""))

  tag_specifications {
    resource_type = "instance"
    tags          = merge(local.tags, { Name = "${local.name}-app" })
  }
}

resource "aws_autoscaling_group" "app" {
  name                      = "${local.name}-asg"
  min_size                  = var.asg_min
  desired_capacity          = var.asg_min
  max_size                  = var.asg_max
  vpc_zone_identifier       = local.base.public_subnet_ids
  target_group_arns         = [aws_lb_target_group.app.arn]
  health_check_type         = "ELB" # replace instances that fail the ALB health check
  health_check_grace_period = 300
  default_instance_warmup   = 300
  wait_for_elb_capacity     = var.asg_min # apply finishes only when the site is serving

  launch_template {
    id      = aws_launch_template.app.id
    version = aws_launch_template.app.latest_version
  }

  # A new image tag replaces the instances gradually, at least half stay in service.
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
    }
  }

  enabled_metrics = ["GroupInServiceInstances", "GroupDesiredCapacity"]

  lifecycle {
    ignore_changes = [desired_capacity] # decided by scaling after creation
  }

  depends_on = [aws_iam_role_policy.app, aws_iam_role_policy_attachment.managed,
  aws_vpc_security_group_ingress_rule.rds_from_app, aws_vpc_security_group_ingress_rule.cache_from_app]
}

# Keep the average CPU around 60% (2 to 3 instances). Scans are CPU-bound.
resource "aws_autoscaling_policy" "cpu_target" {
  name                   = "${local.name}-cpu-target-60"
  autoscaling_group_name = aws_autoscaling_group.app.name
  policy_type            = "TargetTrackingScaling"
  target_tracking_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ASGAverageCPUUtilization"
    }
    target_value = 60
  }
}

# --- Bonus: ElastiCache (Valkey) result cache. The app works without it (fails open). ---------

resource "aws_security_group" "cache" {
  count       = var.enable_cache ? 1 : 0
  name        = "${local.name}-cache-sg"
  description = "ElastiCache Valkey: 6379 from the app instances only"
  vpc_id      = local.base.vpc_id
}

resource "aws_vpc_security_group_ingress_rule" "cache_from_app" {
  count                        = var.enable_cache ? 1 : 0
  security_group_id            = aws_security_group.cache[0].id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.ec2.id
}

resource "aws_vpc_security_group_egress_rule" "app_to_cache" {
  count                        = var.enable_cache ? 1 : 0
  security_group_id            = aws_security_group.ec2.id
  ip_protocol                  = "tcp"
  from_port                    = 6379
  to_port                      = 6379
  referenced_security_group_id = aws_security_group.cache[0].id
}

resource "aws_elasticache_subnet_group" "cache" {
  count      = var.enable_cache ? 1 : 0
  name       = "${local.name}-cache"
  subnet_ids = local.base.private_subnet_ids
}

resource "aws_elasticache_replication_group" "cache" {
  count                      = var.enable_cache ? 1 : 0
  replication_group_id       = "${local.name}-cache"
  description                = "Scan result cache"
  engine                     = "valkey"
  engine_version             = "8.2"
  node_type                  = "cache.t3.micro"
  num_cache_clusters         = 1 # cost; production: 2 with automatic failover
  subnet_group_name          = aws_elasticache_subnet_group.cache[0].name
  security_group_ids         = [aws_security_group.cache[0].id]
  transit_encryption_enabled = true # rediss://
  at_rest_encryption_enabled = true
  apply_immediately          = true
}
