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

# ----------------------------------------------------------------------
# VPC and Networking
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
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.public_subnet_cidr
  availability_zone = data.aws_availability_zones.available.names[0]

  tags = {
    Name = "${var.project_name}-public-subnet"
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
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
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
    description = "Allow all outbound traffic (for package updates and daily China CIDR list sync)"
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
# EC2 Instance (t4g.nano on Amazon Linux 2023 ARM64)
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

resource "aws_instance" "beacon" {
  ami                         = data.aws_ami.al2023_arm64.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.beacon.id]
  user_data_replace_on_change = true

  user_data = <<-EOF
              #!/bin/bash
              set -euo pipefail

              dnf update -y
              dnf install -y nftables openssl python3 cronie curl

              # ------------------------------------------------------------------
              # 1. Configure Kernel-Level GeoIP Firewall (nftables)
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
              # 2. Generate Self-Signed TLS Beacon Certificate (10-Year Validity)
              # ------------------------------------------------------------------
              mkdir -p /opt/webserver
              cd /opt/webserver

              openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 3650 -nodes \
                -subj "/C=AU/ST=NSW/L=Sydney/O=CloudflareOneBeacon/CN=china-roaming-beacon.internal"

              CERT_FP_COLONS=$(openssl x509 -in /opt/webserver/server.crt -noout -fingerprint -sha256 | cut -d'=' -f2)
              CERT_FP_HEX=$(echo "$CERT_FP_COLONS" | tr -d ':' | tr '[:upper:]' '[:lower:]')
              echo "$CERT_FP_HEX" > /opt/webserver/cert-sha256.txt

              {
                echo "=================================================================="
                echo "CLOUDFLARE ONE MANAGED NETWORK TLS BEACON READY"
                echo "Certificate SHA-256 (Hex):    $CERT_FP_HEX"
                echo "Certificate SHA-256 (Colons): $CERT_FP_COLONS"
                echo "=================================================================="
              } | tee /dev/console

              # ------------------------------------------------------------------
              # 3. Configure HTTPS Web Server Returning Client IP (200 OK)
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

  tags = {
    Name = "${var.project_name}-ec2"
  }
}

# Allocate and associate a static Elastic IP with the EC2 instance
resource "aws_eip" "beacon" {
  instance = aws_instance.beacon.id
  domain   = "vpc"

  tags = {
    Name = "${var.project_name}-eip"
  }
}
