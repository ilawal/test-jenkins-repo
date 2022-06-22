output "Jenkins_IP" {
  value       = aws_instance.UST1_Jenkins_Server.public_ip
  description = "Jenkins public IP"
}

output "Docker_host-public-ip" {
  value       = join(",", aws_instance.UST1pap_Docker_host.*.public_ip)
  description = "Docker public IP"
}

output "Ansible_IP" {
  value       = aws_instance.UST1pap_Ansible_host.public_ip
  description = "Ansible public IP"
}

output "name_server" {
  value       = aws_route53_zone.UST1pap-zone.name_servers
  description = "name server"
}


output "db_endpoint" {
  value = aws_db_instance.US_Team1_DB.endpoint
}

output "dns" {
  value = aws_db_instance.US_Team1_DB.address
}

output "db-arn" {
  value = aws_db_instance.US_Team1_DB.arn
}

output "db-domain" {
  value = aws_db_instance.US_Team1_DB.domain
}

output "db-id" {
  value = aws_db_instance.US_Team1_DB.id
}

output "db-name" {
  value = aws_db_instance.US_Team1_DB.name
}