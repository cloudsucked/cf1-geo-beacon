output "autoscaling_group_name" {
  description = "Name of the Multi-AZ Auto Scaling Group managing the beacon instance."
  value       = aws_autoscaling_group.beacon.name
}

output "instance_type" {
  description = "The EC2 instance type configured in the Launch Template."
  value       = var.instance_type
}

output "elastic_ip" {
  description = "Static public IPv4 address automatically associated with the active ASG instance."
  value       = aws_eip.beacon.public_ip
}

output "cloudflare_managed_network_endpoint" {
  description = "Host and port to configure in Cloudflare One Managed Networks (TLS Endpoint)."
  value       = "${aws_eip.beacon.public_ip}:443"
}

output "get_certificate_sha256_command" {
  description = "AWS CLI command to retrieve the persistent TLS certificate SHA-256 hex thumbprint from SSM Parameter Store."
  value       = "aws ssm get-parameter --region ${var.aws_region} --name '/${var.project_name}/tls/sha256' --query 'Parameter.Value' --output text"
}

output "curl_test_command" {
  description = "cURL command to test the HTTPS server from an allowed IP (returns client IP and X-Cert-SHA256 header)."
  value       = "curl -ki https://${aws_eip.beacon.public_ip}"
}
