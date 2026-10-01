output "admin_account_id" {
  description = "Account ID designated as the GuardDuty delegated administrator."
  value       = aws_guardduty_organization_admin_account.this.admin_account_id
}

output "auto_enable_organization_members" {
  description = "Auto-enable mode applied to member accounts."
  value       = aws_guardduty_organization_configuration.this.auto_enable_organization_members
}
