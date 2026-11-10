# Cloudflare One Managed Network TLS Beacon for Mainland China Roaming

An ultra-low-cost (~$8.09/month), **Multi-AZ High Availability** AWS Terraform solution that deploys a **Layer-3/4 Geo-Filtered TLS Beacon** in a self-healing **Auto Scaling Group (`min=1, max=1`)** using a `t4g.nano` instance. It enables **Cloudflare One (WARP)** clients to automatically detect when a user is roaming in **Mainland China** (while excluding corporate China office egress IPs) and dynamically switch WARP Device Profiles.

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
1. **Linux Kernel `nftables` Stateful Layer-3/4 Geo-IP Filtering** on a `t4g.nano` instance (inspecting the true client source IP before the TCP or TLS handshake ever reaches userspace).
2. **Multi-AZ Self-Healing Auto Scaling Group (`min = 1, max = 1`)** spanning 3 Availability Zones (`2a`, `2b`, `2c`) for **$0.00 extra cost**:
   - **Automatic Elastic IP Reassociation**: On boot, the active instance uses an IAM Instance Profile (`ec2:AssociateAddress`) to bind the static Elastic IP to itself in whichever AZ it launches.
   - **Persistent TLS Certificate via AWS SSM Parameter Store (Standard Tier)**: On initial deployment, a 10-year X.509 certificate, private key (`SecureString`), and SHA-256 thumbprint are generated and stored in SSM Parameter Store (`/<project_name>/tls/*`). If the ASG replaces an unhealthy instance or fails over to another AZ, the new instance automatically loads the existing certificate and key from SSM—ensuring the **SHA-256 thumbprint configured in Cloudflare One never changes**.

```mermaid
flowchart LR
    subgraph Clients["WARP Clients (Laptops)"]
        C1["User in Mainland China<br/>(Roaming)"]
        C2["User in China Office<br/>(Office Egress IP)"]
        C3["User in Australia / RoW"]
    end

    subgraph AWS["AWS VPC (Multi-AZ: AZ-1, AZ-2, AZ-3)"]
        EIP["Static Elastic IP<br/>(TCP 443)"]
        SSM[("AWS SSM Parameter Store<br/>Persistent TLS Cert & Key")]
        
        subgraph ASG["Auto Scaling Group (min=1, max=1 across 3 AZs)"]
            subgraph EC2["Active EC2 t4g.nano (Amazon Linux 2023)"]
                subgraph Kernel["Linux Kernel Network Layer (nftables)"]
                    R1{"1. Source IP in<br/>@china_office_ips?"}
                    R2{"2. Source IP in<br/>@china_mainland_cidrs?"}
                end
                
                TLS["Userspace TLS Server (:443)<br/>(Python HTTPS with Beacon Cert)"]
            end
        end
    end

    C1 & C2 & C3 -->|"Managed Network Probe"| EIP --> R1
    EC2 -.->|"1. Boot: Associate EIP"| EIP
    EC2 -.->|"2. Boot: Load/Save Cert"| SSM
    R1 -->|"Yes"| DROP1["REJECT (TCP RST)<br/>(Probe Fails Immediately)"]
    R1 -->|"No"| R2
    R2 -->|"No"| DROP2["DROP<br/>(Probe Fails)"]
    R2 -->|"Yes"| TLS
    TLS -->|"Presents SHA-256 Cert"| MATCH["TLS Handshake Succeeds<br/>(Switches to China WARP Profile)"]
```

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
4. **Rule 4 — Default Drop on TCP 443**:
   - All other global traffic to `TCP 443` is dropped at the kernel level before the TCP `SYN` is acknowledged.
5. **Userspace HTTPS Beacon Server (`:443`)**:
   - Serves the client's public IP address as plain text (`200 OK`) alongside an `X-Cert-SHA256` response header using the persistent TLS certificate from SSM Parameter Store.

---

## Cost Breakdown

| Resource | Specification | Estimated Monthly Cost (USD) |
| :--- | :--- | :--- |
| **Amazon EC2** | `t4g.nano` (2 vCPU, 0.5 GB RAM, Graviton2, On-Demand) | ~$3.80 |
| **Amazon EBS** | 8 GB `gp3` root volume | ~$0.64 |
| **Elastic IP** | 1x Static IPv4 (attached to active ASG instance) | ~$3.65 |
| **Auto Scaling Group & Multi-AZ Subnets** | `min=1, max=1` across 3 Availability Zones | $0.00 |
| **AWS SSM Parameter Store** | 3x Standard Parameters (`cert`, `key`, `sha256`) | $0.00 |
| **Linux `nftables`** | Kernel L3/L4 Geo-Firewall + Daily CIDR Cron | $0.00 |
| **Total** | | **~$8.09 / month** *(vs. ~$290+/mo with AWS Network Firewall)* |

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

*(Alternatively, if you added your IP to `allowed_test_cidrs`, run `curl -ki https://<ELASTIC_IP>` to see both your client IP in the response body and the `X-Cert-SHA256` response header).*

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
