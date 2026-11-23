#!/bin/bash
# Boot script (EC2 user data), rendered by Terraform: $${...} is a Terraform value, $VAR is bash.
# Contains no secrets: the DB password is read from Secrets Manager with the instance role.
# Output goes to /var/log/user-data.log, shipped to the /phishing-detector/boot log group.
set -euxo pipefail
exec > >(tee -a /var/log/user-data.log) 2>&1

retry() {  # up to 5 attempts: network and IAM credentials can lag at boot
  for delay in 5 10 20 40 0; do
    "$@" && return 0
    [ "$delay" -eq 0 ] && return 1
    sleep "$delay"
  done
}

retry dnf install -y docker amazon-cloudwatch-agent jq
systemctl enable --now docker

# Instance identity from the metadata service (IMDSv2: token first).
TOKEN=$(curl -sf -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300")
INSTANCE_ID=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AZ=$(curl -sf -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)

# CloudWatch agent: memory/disk metrics and this boot log.
cat > /opt/aws/amazon-cloudwatch-agent/etc/config.json <<'EOF'
${agent_config}
EOF
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -s \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/config.json

# Database password -> root-only env file. Tracing is off so it never reaches the log.
set +x
get_password() {
  aws secretsmanager get-secret-value --region ${region} --secret-id "${db_secret_arn}" \
    --query SecretString --output text | jq -er .password
}
DB_PASSWORD=$(retry get_password)
umask 077
cat > /etc/phishing-detector.env <<EOF
DB_HOST=${db_host}
DB_NAME=${db_name}
DB_USER=${db_user}
DB_PASSWORD=$DB_PASSWORD
REDIS_URL=${redis_url}
INSTANCE_ID=$INSTANCE_ID
AVAILABILITY_ZONE=$AZ
APP_VERSION=${image_tag}
EOF
unset DB_PASSWORD
set -x

# Pull and run the app. --restart unless-stopped: restarted after a crash or reboot.
# awslogs non-blocking: if CloudWatch Logs is slow, log lines are dropped instead of blocking the app.
ecr_login() {
  aws ecr get-login-password --region ${region} | docker login --username AWS --password-stdin "${split("/", image)[0]}"
}
retry ecr_login
retry docker pull "${image}"
docker rm -f app 2>/dev/null || true
docker run -d --name app --restart unless-stopped -p 8000:8000 \
  --env-file /etc/phishing-detector.env \
  --log-driver awslogs --log-opt awslogs-region=${region} --log-opt awslogs-group=${app_log_group} \
  --log-opt awslogs-stream="$INSTANCE_ID" --log-opt mode=non-blocking \
  "${image}"

for _ in $(seq 1 30); do curl -sf http://localhost:8000/health && break || sleep 2; done
echo "readiness: $(curl -s http://localhost:8000/health/ready || echo 'NOT RESPONDING')"
