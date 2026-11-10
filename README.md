# Cloudflare One Managed Network TLS Beacon for Mainland China Roaming

An ultra-low-cost (**Free Tier eligible**, or ~$8.09/month with `t4g.nano`), **Multi-AZ High Availability** AWS Terraform solution that deploys a **Layer-3/4 Geo-Filtered TLS Beacon** in a self-healing **Auto Scaling Group (`min=1, max=1`)** using a `t4g.micro` instance. It enables **Cloudflare One (WARP)** clients to automatically detect when a user is roaming in **Mainland China** (while excluding corporate China office egress IPs) and dynamically switch WARP Device Profiles.

---

## Problem Statement

Organizations using **Cloudflare One (WARP)** typically configure their default Device Profile with **Split Tunnels** that exclude latency-sensitive real-time media—such as **Google Meet**—so traffic routes directly from the user's laptop to Google's servers for optimal call quality.

However, when employees travel to **Mainland China**:
1. **Google services (including Google Meet) are blocked** by the Great Firewall (GFW) when routed outside the WARP tunnel.
2. Users roaming in Mainland China need to automatically switch to a **China Roaming Device Profile** where Google Meet traffic is **included inside the WARP tunnel**.
3. Users inside a **corporate China office** (which may already have dedicated routing or its own managed network profile) should **not** match the roaming profile.

### Why Layer-7 WAF Geo-Blocking Fails for Cloudflare Managed Networks

Cloudflare WARP's **Managed Networks** detection works by probing a configured `host:port` over TCP, completing a **TLS handshake**, and verifying that the server certificate matches a configured **SHA-256 thumbprint**.

- **The Caveat:** WARP Managed Network detection **only evaluates the TLS handshake and certificate thumbprint**—it ignores the HTTP response status code.
- If you place a Layer-7 WAF or serverless edge function (e.g., Cloudflare Workers or AWS WAF) in front of the beacon that completes the TLS handshake and returns `HTTP 403 Forbidden` to non-China IPs, **every WARP client worldwide still sees a valid TLS certificate and falsely triggers the China Managed Network**.
- Conversely, native AWS VPC Security Groups and NACLs cannot filter by geolocation, and **AWS Network Firewall** costs **~$285+/month** per endpoint—far too expensive for a lightweight beacon.

---

## Architectural Design

To prevent non-China clients (and China office clients) from completing the TLS handshake without paying for AWS Network Firewall or a Network Load Balancer, this architecture combines:
1. **Linux Kernel `nftables` Stateful Layer-3/4 Geo-IP Filtering** on a `t4g.micro` instance (inspecting the true client source IP before the TCP or TLS handshake ever reaches userspace).
2. **Multi-AZ Self-Healing Auto Scaling Group (`min = 1, max = 1`)** spanning 3 Availability Zones (`2a`, `2b`, `2c`) for **$0.00 extra cost**:
   - **Automatic Elastic IP Reassociation**: On boot, the active instance uses an IAM Instance Profile (`ec2:AssociateAddress`) to bind the static Elastic IP to itself in whichever AZ it launches.
   - **Persistent TLS Certificate via AWS SSM Parameter Store (Standard Tier)**: On initial deployment, a 10-year X.509 certificate, private key (`SecureString`), and SHA-256 thumbprint are generated and stored in SSM Parameter Store (`/<project_name>/tls/*`). If the ASG replaces an unhealthy instance or fails over to another AZ, the new instance automatically loads the existing certificate and key from SSM—ensuring the **SHA-256 thumbprint configured in Cloudflare One never changes**.

![Cloudflare One Managed Network Geo-Beacon Architecture](./architecture.drawio.svg)

*(Tip: [`architecture.drawio.svg`](./architecture.drawio.svg) is both a native vector SVG and an editable Draw.io diagram—open it in [app.diagrams.net](https://app.diagrams.net/) or the VS Code Draw.io extension to customize shapes and connectors).*

### How Packet Evaluation Works

1. **Rule 1 — Exclude China Office IPs (`@china_office_ips`)**:
   - Any packet to `TCP 443` matching your configured `china_office_cidrs` is immediately rejected with a `TCP RST` (`reject with tcp reset`). The WARP probe fails in milliseconds without seeing the TLS certificate.
2. **Rule 2 — Allow Optional Admin Test IPs (`@allowed_test_ips`)**:
   - Any packet matching `allowed_test_cidrs` is permitted through for administrative testing outside China.
3. **Rule 3 — Allow Mainland China CIDRs (`@china_mainland_cidrs`)**:
   - An automated script (`/usr/local/bin/update-geo-firewall.sh`, run at boot and daily via `cron.daily`) fetches Mainland China (`CN`) IPv4 CIDR allocations using a 3-tier fallback hierarchy and loads them atomically into an `nftables` interval set:
     1. **Primary (APNIC Official Registry)**: `https://ftp.apnic.net/apnic/stats/apnic/delegated-apnic-latest` (parsed and aggregated in-memory via Python's standard `ipaddress` library).
     2. **Secondary (`ipdeny.com`)**: `https://www.ipdeny.com/ipblocks/data/aggregated/cn-aggregated.zone`
     3. **Tertiary (`mayaxcn/china-ip-list` on GitHub)**: `https://raw.githubusercontent.com/mayaxcn/china-ip-list/master/chnroute.txt`
   - Matching packets are accepted and reach the userspace TLS server.
4. **Rule 4 — Default Drop Policy**:
   - The `nftables` `input` chain uses a default `policy drop`—dropping invalid conntrack states, rate-limiting new TCP 443 connections per source IP (30/min, burst 15), and dropping all other ports and protocols at the kernel level.
5. **Hardened Userspace HTTPS Beacon Server (`:443`)**:
   - Accepts **only** `GET /` over TLS 1.2/1.3 and returns **only** the client's public IP address as plain text (`200 OK`) with no server banners or extra metadata.

---

## Multi-Layer Security Hardening

The beacon instance and web server are hardened across the kernel, network, TLS, HTTP parser, and OS process layers:

| Layer | Hardening Controls |
| :--- | :--- |
| **Kernel TCP/IP (`sysctl`)** | Enables `tcp_syncookies = 1` (SYN flood defense), strict reverse-path filtering (`rp_filter = 1`), reduced `tcp_synack_retries = 2` & `tcp_fin_timeout = 15`, and disables ICMP redirects and source routing. |
| **Network Firewall (`nftables`)** | Default `policy drop` on `input`; drops `ct state invalid`; rejects China office IPs with `TCP RST`; enforces per-source-IP connection rate limiting (`30/minute`, burst `15`) before accepting Mainland China CIDRs. |
| **TLS & Socket Layer** | Enforces **TLS 1.2 & TLS 1.3 only** with AEAD forward-secrecy ciphers (`ECDHE+AESGCM:ECDHE+CHACHA20`), disables TLS compression & renegotiation, caps concurrent connections with a `BoundedSemaphore(32)`, and performs TLS handshakes inside worker threads with a strict **3.0-second socket timeout** (defeating Slowloris and TLS handshake stalls). |
| **Minimal HTTP Handler** | Custom bounded reader (`max 256 bytes` request line, `max 16` header lines of `1024 bytes`); **never parses headers or reads request bodies**; allows **only `GET /`** (all other methods/paths receive `403 Forbidden` with `Content-Length: 0`); strips `Server`/`Date` banners; forces `Connection: close`, `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Cache-Control: no-store`. |
| **OS & Systemd Sandbox** | Runs as an unprivileged `beacon` system user (`/sbin/nologin`) with read-only `0500`/`0400` permissions on `/opt/webserver`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` only, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `RestrictSUIDSGID=yes`, and `MemoryMax=64M`. |
| **AWS EC2 Metadata** | Enforces **IMDSv2 (`http_tokens = "required"`)** with hop limit `1`. |

---

## Cost Breakdown

> **Note on Instance Size (`t4g.micro` vs `t4g.nano`):** The template defaults to **`t4g.micro`** so that it deploys out-of-the-box on **AWS Free Tier** accounts/projects (where non-Free-Tier instance types like `t4g.nano` are restricted). On paid AWS accounts outside the Free Tier, you can optionally set `instance_type = "t4g.nano"` in `terraform.tfvars` to halve the compute cost (~$3.80/month).

| Resource | Specification | AWS Free Tier | On-Demand Paid (after Free Tier) |
| :--- | :--- | :--- | :--- |
| **Amazon EC2** | `t4g.micro` (2 vCPU, 1 GB RAM, Graviton2, default for Free Tier) *(or `t4g.nano`)* | **$0.00** *(Free Tier / Credits)* | ~$7.59 / mo *(or ~$3.80 with `t4g.nano`)* |
| **Amazon EBS** | 8 GB `gp3` root volume | **$0.00** *(Free Tier 30 GB)* | ~$0.64 / mo |
| **Elastic IP** | 1x Static IPv4 (attached to active ASG instance) | **$0.00** *(Free Tier / Credits)* | ~$3.65 / mo |
| **Auto Scaling Group & Multi-AZ Subnets** | `min=1, max=1` across 3 Availability Zones | **$0.00** | **$0.00** |
| **AWS SSM Parameter Store** | 3x Standard Parameters (`cert`, `key`, `sha256`) | **$0.00** | **$0.00** |
| **Linux `nftables`** | Kernel L3/L4 Geo-Firewall + Daily CIDR Cron | **$0.00** | **$0.00** |
| **Total** | | **$0.00 / month** | **~$8.09 – $11.88 / month** *(vs. ~$290+/mo with AWS Network Firewall)* |

---

## Deployment Instructions

### Prerequisites
- [Terraform](https://developer.hashicorp.com/terraform/install) >= 1.5.0
- [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) configured with credentials for your target AWS account/project

### 1. Configure Variables (Optional)

Copy the example variables file and customize your region, China office egress IPs to exclude, and optional admin test IPs:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
aws_region         = "ap-southeast-2"
china_office_cidrs = ["203.0.113.10/32"] # Replace with your China office public IP(s)
allowed_test_cidrs = ["198.51.100.25/32"] # Optional: Your workstation IP to test with curl
```

### 2. Initialize and Apply

*(Note: If authenticating via `aws login`, export temporary session credentials first with `eval $(aws configure export-credentials --profile <profile> --format env)`).*

```bash
terraform init
terraform plan
terraform apply
```

### 3. Retrieve the Persistent TLS Certificate SHA-256 Thumbprint

Wait ~60 seconds after the ASG launches the first instance for `cloud-init` to complete, then run the command provided in the `get_certificate_sha256_command` Terraform output to fetch the 64-character hex thumbprint from SSM Parameter Store:

```bash
$(terraform output -raw get_certificate_sha256_command)
```

Example output:
```text
4a7f9b2c1d8e3f0a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a
```

*(If you added your IP to `allowed_test_cidrs`, you can also verify the endpoint with `curl -k https://<ELASTIC_IP>`, which returns only your public client IP as plain text).*

---

## Configuring Cloudflare One (Zero Trust)

1. **Create the Managed Network**:
   - In the [Cloudflare One Dashboard](https://one.dash.cloudflare.com/), navigate to **Settings** > **WARP Client** > **Managed networks** > **Add new**.
   - **Name**: `China-Roaming-Beacon`
   - **Host and Port**: Enter the value of `terraform output -raw cloudflare_managed_network_endpoint` (e.g., `<ELASTIC_IP>:443`).
   - **TLS Cert SHA-256**: Enter the 64-character hex string returned by `get_certificate_sha256_command`.

2. **Ensure the Beacon IP Bypasses the WARP Tunnel**:
   - WARP performs Managed Network probes over the local physical interface, but as a best practice, ensure `<ELASTIC_IP>/32` is excluded in your Split Tunnel configuration so traffic to the beacon never hairpins through a Cloudflare Gateway egress IP.

3. **Create the China Roaming Device Profile**:
   - Navigate to **Settings** > **WARP Client** > **Device settings** > **Create profile**.
   - **Rule**: `Managed network` *is* `China-Roaming-Beacon`.
   - **Priority**: Set a higher priority (lower number) than your default global Device Profile.
   - **Split Tunnels**: Modify the Split Tunnel entries on this profile so that Google Meet IP ranges / domains are **routed through the WARP tunnel**.
