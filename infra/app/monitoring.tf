# Logs, metrics, dashboard and alarms. The dashboard has one row per monitoring question.

resource "aws_cloudwatch_log_group" "app" {
  name              = "/${local.name}/app" # JSON app logs, one stream per instance
  retention_in_days = var.log_retention_days
}

resource "aws_cloudwatch_log_group" "boot" {
  name              = "/${local.name}/boot" # boot script output, to debug a failed boot
  retention_in_days = var.log_retention_days
}

# Metrics from the JSON app logs.
resource "aws_cloudwatch_log_metric_filter" "app" {
  for_each = {
    AppErrors   = "{ $.level = \"ERROR\" }"
    CacheHits   = "{ $.event = \"scan_completed\" && $.cache = \"hit\" }"
    CacheMisses = "{ $.event = \"scan_completed\" && $.cache = \"miss\" }"
  }
  name           = "${local.name}-${each.key}"
  log_group_name = aws_cloudwatch_log_group.app.name
  pattern        = each.value
  metric_transformation {
    name          = each.key
    namespace     = "PhishingDetector"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_query_definition" "errors" {
  name            = "${local.name}/Errors"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    fields @timestamp, instance_id, message, event, error, path
    | filter level = "ERROR"
    | sort @timestamp desc
    | limit 100
  EOT
}

resource "aws_cloudwatch_query_definition" "requests_per_instance" {
  name            = "${local.name}/Requests per instance"
  log_group_names = [aws_cloudwatch_log_group.app.name]
  query_string    = <<-EOT
    filter event = "http_request"
    | fields status_code >= 500 as is_5xx
    | stats count(*) as requests, sum(is_5xx) as errors_5xx by instance_id, bin(5m)
  EOT
}

# CloudWatch agent (written to each instance by user_data.sh): memory and disk metrics,
# which EC2 cannot see from outside, and the boot log.
locals {
  cloudwatch_agent_config = jsonencode({
    metrics = {
      append_dimensions      = { AutoScalingGroupName = "$${aws:AutoScalingGroupName}", InstanceId = "$${aws:InstanceId}" }
      aggregation_dimensions = [["AutoScalingGroupName"]]
      metrics_collected = {
        mem  = { measurement = ["mem_used_percent"] }
        disk = { measurement = ["used_percent"], resources = ["/"], drop_device = true }
      }
    }
    logs = {
      logs_collected = {
        files = { collect_list = [{ file_path = "/var/log/user-data.log", log_group_name = aws_cloudwatch_log_group.boot.name, log_stream_name = "{instance_id}" }] }
      }
    }
  })

  lb  = aws_lb.app.arn_suffix
  tg  = aws_lb_target_group.app.arn_suffix
  asg = aws_autoscaling_group.app.name
  sns = [local.base.alerts_topic_arn]

  # One row per question; charts share the row width (24-column grid).
  dashboard_rows = [
    { title = "1. Are the instances healthy?", charts = [
      { title = "Healthy vs unhealthy targets", metrics = [
        ["AWS/ApplicationELB", "HealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb, { stat = "Minimum" }],
        ["AWS/ApplicationELB", "UnHealthyHostCount", "TargetGroup", local.tg, "LoadBalancer", local.lb, { stat = "Maximum" }],
      ] },
      { title = "Instances in service (ASG)", metrics = [["AWS/AutoScaling", "GroupInServiceInstances", "AutoScalingGroupName", local.asg]] },
    ] },
    { title = "2. How many requests reach the load balancer, and do they succeed?", charts = [
      { title = "Requests per minute", metrics = [["AWS/ApplicationELB", "RequestCount", "LoadBalancer", local.lb, { stat = "Sum" }]] },
      { title = "Responses", metrics = [
        ["AWS/ApplicationELB", "HTTPCode_Target_2XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "2xx" }],
        ["AWS/ApplicationELB", "HTTPCode_Target_4XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "4xx" }],
        ["AWS/ApplicationELB", "HTTPCode_Target_5XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "5xx (app)" }],
        ["AWS/ApplicationELB", "HTTPCode_ELB_5XX_Count", "LoadBalancer", local.lb, { stat = "Sum", label = "5xx (ALB)" }],
      ] },
      { title = "Response time (s)", metrics = [
        ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb, { stat = "p50" }],
        ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", local.lb, { stat = "p95" }],
      ] },
    ] },
    { title = "3. How much CPU, memory and disk?", charts = [
      { title = "CPU % (ASG average)", metrics = [["AWS/EC2", "CPUUtilization", "AutoScalingGroupName", local.asg, { period = 300 }]] },
      { title = "Memory used % (ASG average)", metrics = [["CWAgent", "mem_used_percent", "AutoScalingGroupName", local.asg]] },
      { title = "Disk used % per instance", metrics = [[{ expression = "SEARCH('{CWAgent,AutoScalingGroupName,InstanceId,fstype,path} MetricName=\"disk_used_percent\"', 'Average', 60)" }]] },
    ] },
    { title = "4. App: errors and result cache", charts = [
      { title = "App errors (ERROR log lines)", metrics = [["PhishingDetector", "AppErrors", { stat = "Sum" }]] },
      { title = "Cache hits vs misses", metrics = [
        ["PhishingDetector", "CacheHits", { stat = "Sum" }],
        ["PhishingDetector", "CacheMisses", { stat = "Sum" }],
      ] },
    ] },
  ]
}

resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = local.name
  dashboard_body = jsonencode({
    widgets = concat(
      flatten([for i, row in local.dashboard_rows : concat(
        [{ type = "text", x = 0, y = i * 7, width = 24, height = 1, properties = { markdown = "## ${row.title}" } }],
        [for j, chart in row.charts : {
          type = "metric", x = j * floor(24 / length(row.charts)), y = i * 7 + 1, width = floor(24 / length(row.charts)), height = 6
          properties = { title = chart.title, metrics = chart.metrics, region = var.aws_region, period = 60, stat = "Average",
          view = "timeSeries", yAxis = { left = { min = 0 } } }
        }]
      )]),
      [
        { type = "text", x = 0, y = 28, width = 24, height = 1, properties = { markdown = "## 5. Where are the logs? `/${local.name}/app` (latest errors below; saved queries in Logs Insights)" } },
        { type = "log", x = 0, y = 29, width = 16, height = 6, properties = {
          title = "Latest app errors", region = var.aws_region, view = "table"
          query = "SOURCE '${aws_cloudwatch_log_group.app.name}' | fields @timestamp, instance_id, message, error | filter level = 'ERROR' | sort @timestamp desc | limit 20"
        } },
        { type = "alarm", x = 16, y = 29, width = 8, height = 6, properties = { title = "Alarms", alarms = [for a in aws_cloudwatch_metric_alarm.alarm : a.arn] } },
      ]
    )
  })
}

# Alarms: email (SNS, base stack) when they fire and when they recover.
locals {
  alarms = {
    unhealthy-targets = {
      description = "An instance fails the ALB health check. Check target health and the instance's log stream."
      namespace   = "AWS/ApplicationELB", metric = "UnHealthyHostCount", stat = "Maximum", dimensions = { TargetGroup = local.tg, LoadBalancer = local.lb }
      period      = 60, periods = 2, operator = "GreaterThanThreshold", threshold = 0, missing = "notBreaching"
    }
    healthy-hosts-low = {
      description = "Fewer than ${var.asg_min} healthy instances for 3 minutes: no redundancy. Check ASG activity and boot logs."
      namespace   = "AWS/ApplicationELB", metric = "HealthyHostCount", stat = "Minimum", dimensions = { TargetGroup = local.tg, LoadBalancer = local.lb }
      period      = 60, periods = 3, operator = "LessThanThreshold", threshold = var.asg_min, missing = "breaching"
    }
    target-5xx = {
      description = "The app returned 5+ errors (5xx) in 5 minutes. Check the 'Errors' saved query (503 = database unreachable)."
      namespace   = "AWS/ApplicationELB", metric = "HTTPCode_Target_5XX_Count", stat = "Sum", dimensions = { LoadBalancer = local.lb }
      period      = 300, periods = 1, operator = "GreaterThanOrEqualToThreshold", threshold = 5, missing = "notBreaching"
    }
    latency-p95 = {
      description = "p95 response time above 1 s for 3 minutes. Check CPU/memory (row 3) and the database."
      namespace   = "AWS/ApplicationELB", metric = "TargetResponseTime", stat = "p95", dimensions = { LoadBalancer = local.lb }
      period      = 60, periods = 3, operator = "GreaterThanThreshold", threshold = 1, missing = "notBreaching"
    }
    ec2-cpu-high = {
      description = "Average CPU above 80% for 5 minutes. Scaling (target 60%) should already be adding instances."
      namespace   = "AWS/EC2", metric = "CPUUtilization", stat = "Average", dimensions = { AutoScalingGroupName = local.asg }
      period      = 300, periods = 1, operator = "GreaterThanThreshold", threshold = 80, missing = "notBreaching"
    }
  }
}

resource "aws_cloudwatch_metric_alarm" "alarm" {
  for_each            = local.alarms
  alarm_name          = "${local.name}-${each.key}"
  alarm_description   = each.value.description
  namespace           = each.value.namespace
  metric_name         = each.value.metric
  dimensions          = each.value.dimensions
  statistic           = startswith(each.value.stat, "p") ? null : each.value.stat
  extended_statistic  = startswith(each.value.stat, "p") ? each.value.stat : null
  period              = each.value.period
  evaluation_periods  = each.value.periods
  comparison_operator = each.value.operator
  threshold           = each.value.threshold
  treat_missing_data  = each.value.missing # no traffic is not an incident (except no healthy hosts)
  alarm_actions       = local.sns
  ok_actions          = local.sns
}
