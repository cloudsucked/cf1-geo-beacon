terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# ----------------------------------------------------------------------
# VPC and Multi-AZ Public Subnets
# ----------------------------------------------------------------------
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.project_name}-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.project_name}-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.public_subnet_cidrs)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index % length(data.aws_availability_zones.available.names)]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.project_name}-public-subnet-${count.index + 1}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "${var.project_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ----------------------------------------------------------------------
# Static Elastic IP (Automatically Reassociated on ASG Instance Boot)
# ----------------------------------------------------------------------
resource "aws_eip" "beacon" {
  domain = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}

# ----------------------------------------------------------------------
# IAM Role & Instance Profile (EIP Reassociation + SSM Cert Persistence)
# ----------------------------------------------------------------------
resource "aws_iam_role" "beacon" {
  name = "${var.project_name}-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "beacon" {
  name = "${var.project_name}-ec2-policy"
  role = aws_iam_role.beacon.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowElasticIPReassociation"
        Effect   = "Allow"
        Action   = ["ec2:AssociateAddress"]
        Resource = "*"
      },
      {
        Sid    = "AllowBeaconTLSParameterStore"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter",
          "ssm:PutParameter"
        ]
        Resource = "arn:aws:ssm:${var.aws_region}:${data.aws_caller_identity.current.account_id}:parameter/${var.project_name}/tls/*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "beacon" {
  name = "${var.project_name}-instance-profile"
  role = aws_iam_role.beacon.name
}

# ----------------------------------------------------------------------
# Security Group
# ----------------------------------------------------------------------
resource "aws_security_group" "beacon" {
  name        = "${var.project_name}-sg"
  description = "Allow inbound TCP 443 for Cloudflare Managed Network TLS beacon (filtered at kernel layer by nftables)"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Allow HTTPS inbound (filtered by host nftables GeoIP rules)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "Allow all outbound traffic (AWS APIs, package updates, daily China CIDR sync)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-sg"
  }
}

# ----------------------------------------------------------------------
# Launch Template & Multi-AZ Auto Scaling Group (min=1, max=1)
# ----------------------------------------------------------------------
data "aws_ami" "al2023_arm64" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-arm64"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  office_elements = length(var.china_office_cidrs) > 0 ? "elements = { ${join(", ", var.china_office_cidrs)} }" : ""
  test_elements   = length(var.allowed_test_cidrs) > 0 ? "elements = { ${join(", ", var.allowed_test_cidrs)} }" : ""
}

resource "aws_launch_template" "beacon" {
  name_prefix   = "${var.project_name}-lt-"
  image_id      = data.aws_ami.al2023_arm64.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.beacon.arn
  }

  vpc_security_group_ids = [aws_security_group.beacon.id]

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(<<-EOF
              #!/bin/bash
              set -euo pipefail

              AWS_REGION="${var.aws_region}"
              EIP_ALLOC_ID="${aws_eip.beacon.allocation_id}"
              SSM_PREFIX="/${var.project_name}/tls"

              # ------------------------------------------------------------------
              # 1. Reassociate Static Elastic IP to This Instance
              # ------------------------------------------------------------------
              IMDS_TOKEN=$(curl -fsSL -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
              INSTANCE_ID=$(curl -fsSL -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" "http://169.254.169.254/latest/meta-data/instance-id")

              aws ec2 associate-address \
                --region "$AWS_REGION" \
                --instance-id "$INSTANCE_ID" \
                --allocation-id "$EIP_ALLOC_ID" \
                --allow-reassociation

              dnf update -y
              dnf install -y nftables openssl python3 cronie curl

              # ------------------------------------------------------------------
              # 2. Configure Kernel-Level GeoIP Firewall (nftables)
              # ------------------------------------------------------------------
              cat << 'SCRIPT_EOF' > /usr/local/bin/update-geo-firewall.sh
              #!/bin/bash
              set -euo pipefail

              TMP_CIDRS=$(mktemp)
              trap 'rm -f "$TMP_CIDRS"' EXIT

              if curl -fsSL --connect-timeout 10 --max-time 30 "https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone" -o "$TMP_CIDRS"; then
                echo "Fetched Mainland China CIDRs from ipdeny.com"
              elif curl -fsSL --connect-timeout 10 --max-time 30 "https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt" -o "$TMP_CIDRS"; then
                echo "Fetched Mainland China CIDRs from GitHub fallback"
              else
                echo "ERROR: Failed to download China CIDR list" >&2
                exit 1
              fi

              CHINA_ELEMENTS=$(grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' "$TMP_CIDRS" | paste -sd ',' -)

              if [ -z "$CHINA_ELEMENTS" ]; then
                echo "ERROR: Parsed China CIDR list is empty" >&2
                exit 1
              fi

              cat << NFTEOF > /etc/sysconfig/nftables.conf
              flush ruleset

              table inet geo_filter {
                set china_office_ips {
                  type ipv4_addr
                  flags interval
                  auto-merge
                  ${local.office_elements}
                }

                set allowed_test_ips {
                  type ipv4_addr
                  flags interval
                  auto-merge
                  ${local.test_elements}
                }

                set china_mainland_cidrs {
                  type ipv4_addr
                  flags interval
                  auto-merge
                  elements = { $CHINA_ELEMENTS }
                }

                chain input {
                  type filter hook input priority 0; policy accept;

                  iifname "lo" accept
                  ct state established,related accept

                  # 1. Reject China Office IPs on TCP 443 so office users do NOT trigger the roaming China profile
                  tcp dport 443 ip saddr @china_office_ips reject with tcp reset

                  # 2. Allow explicitly configured test/admin IPs on TCP 443
                  tcp dport 443 ip saddr @allowed_test_ips accept

                  # 3. Allow Mainland China IPs on TCP 443
                  tcp dport 443 ip saddr @china_mainland_cidrs accept

                  # 4. Drop all other global connections on TCP 443 before TCP/TLS handshake
                  tcp dport 443 drop
                }
              }
              NFTEOF

              nft -f /etc/sysconfig/nftables.conf
              SCRIPT_EOF

              chmod +x /usr/local/bin/update-geo-firewall.sh
              /usr/local/bin/update-geo-firewall.sh

              systemctl enable --now nftables
              ln -sf /usr/local/bin/update-geo-firewall.sh /etc/cron.daily/update-geo-firewall
              systemctl enable --now crond

              # ------------------------------------------------------------------
              # 3. Load or Generate Persistent TLS Certificate via SSM Parameter Store
              # ------------------------------------------------------------------
              mkdir -p /opt/webserver
              cd /opt/webserver

              if aws ssm get-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/cert" --query "Parameter.Value" --output text > /opt/webserver/server.crt 2>/dev/null && \
                 aws ssm get-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/key" --with-decryption --query "Parameter.Value" --output text > /opt/webserver/server.key 2>/dev/null; then
                echo "Loaded existing TLS certificate and private key from SSM Parameter Store"
              else
                echo "Generating new 10-year self-signed TLS beacon certificate..."
                openssl req -x509 -newkey rsa:2048 -keyout /opt/webserver/server.key -out /opt/webserver/server.crt -days 3650 -nodes \
                  -subj "/C=AU/ST=NSW/L=Sydney/O=CloudflareOneBeacon/CN=china-roaming-beacon.internal"

                aws ssm put-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/cert" --type "String" --value "$(cat /opt/webserver/server.crt)" --overwrite
                aws ssm put-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/key" --type "SecureString" --value "$(cat /opt/webserver/server.key)" --overwrite
              fi

              chmod 600 /opt/webserver/server.key

              CERT_FP_COLONS=$(openssl x509 -in /opt/webserver/server.crt -noout -fingerprint -sha256 | cut -d'=' -f2)
              CERT_FP_HEX=$(echo "$CERT_FP_COLONS" | tr -d ':' | tr '[:upper:]' '[:lower:]')
              echo "$CERT_FP_HEX" > /opt/webserver/cert-sha256.txt

              aws ssm put-parameter --region "$AWS_REGION" --name "$SSM_PREFIX/sha256" --type "String" --value "$CERT_FP_HEX" --overwrite

              {
                echo "=================================================================="
                echo "CLOUDFLARE ONE MANAGED NETWORK TLS BEACON READY"
                echo "Instance ID:                  $INSTANCE_ID"
                echo "Certificate SHA-256 (Hex):    $CERT_FP_HEX"
                echo "Certificate SHA-256 (Colons): $CERT_FP_COLONS"
                echo "=================================================================="
              } | tee /dev/console

              # ------------------------------------------------------------------
              # 4. Configure HTTPS Web Server Returning Client IP (200 OK)
              # ------------------------------------------------------------------
              cat << 'PYEOF' > /opt/webserver/server.py
              import http.server
              import ssl

              with open('/opt/webserver/cert-sha256.txt', 'r') as f:
                  CERT_SHA256 = f.read().strip()

              class ClientIPHandler(http.server.BaseHTTPRequestHandler):
                  def do_GET(self):
                      client_ip = self.client_address[0]
                      body = f"{client_ip}\n".encode('utf-8')
                      self.send_response(200)
                      self.send_header("Content-Type", "text/plain")
                      self.send_header("Content-Length", str(len(body)))
                      self.send_header("X-Cert-SHA256", CERT_SHA256)
                      self.end_headers()
                      self.wfile.write(body)

                  def log_message(self, format, *args):
                      pass

              server_address = ('0.0.0.0', 443)
              httpd = http.server.HTTPServer(server_address, ClientIPHandler)
              ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
              ssl_context.load_cert_chain(certfile='/opt/webserver/server.crt', keyfile='/opt/webserver/server.key')
              httpd.socket = ssl_context.wrap_socket(httpd.socket, server_side=True)

              httpd.serve_forever()
              PYEOF

              cat << 'SERVICEEOF' > /etc/systemd/system/ip-server.service
              [Unit]
              Description=Cloudflare One Managed Network HTTPS Beacon & Client IP Server
              After=network.target nftables.service

              [Service]
              Type=simple
              User=root
              WorkingDirectory=/opt/webserver
              ExecStart=/usr/bin/python3 /opt/webserver/server.py
              Restart=always

              [Install]
              WantedBy=multi-user.target
              SERVICEEOF

              systemctl daemon-reload
              systemctl enable --now ip-server.service
              EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.project_name}-ec2"
    }
  }
}

resource "aws_autoscaling_group" "beacon" {
  name                = "${var.project_name}-asg"
  min_size            = 1
  max_size            = 1
  desired_capacity    = 1
  vpc_zone_identifier = aws_subnet.public[*].id
  health_check_type   = "EC2"

  launch_template {
    id      = aws_launch_template.beacon.id
    version = "$Latest"
  }

  instance_refresh {
    strategy = "Rolling"
  }

  tag {
    key                 = "Name"
    value               = "${var.project_name}-ec2"
    propagate_at_launch = true
  }
}
