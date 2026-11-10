output "instance_id" {
  description = "The ID of the EC2 beacon instance."
  value       = aws_instance.beacon.id
}

output "instance_type" {
  description = "The EC2 instance type deployed."
  value       = aws_instance.beacon.instance_type
}

output "elastic_ip" {
  description = "Static public IPv4 address of the beacon server."
  value       = aws_eip.beacon.public_ip
}

output "cloudflare_managed_network_endpoint" {
  description = "Host and port to configure in Cloudflare One Managed Networks (TLS Endpoint)."
  value       = "${aws_eip.beacon.public_ip}:443"
}

output "get_certificate_sha256_command" {
  description = "AWS CLI command to retrieve the generated TLS certificate SHA-256 thumbprint from EC2 console output (works from anywhere without needing an allowed IP)."
  value       = "aws ec2 get-console-output --region ${var.aws_region} --instance-id ${aws_instance.beacon.id} --output text | grep -A 4 'CLOUDFLARE ONE MANAGED NETWORK TLS BEACON READY'"
}

output "curl_test_command" {
  description = "cURL command to test the HTTPS server from an allowed IP (returns client IP and X-Cert-SHA256 header)."
  value       = "curl -ki https://${aws_eip.beacon.public_ip}"
}
