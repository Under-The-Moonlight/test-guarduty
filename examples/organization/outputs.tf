output "admin_account_id" {
  description = "GuardDuty delegated administrator account ID."
  value       = module.guardduty_organization.admin_account_id
}

output "detector_id" {
  description = "Detector ID in the delegated administrator account."
  value       = module.guardduty.detector_id
}

output "sns_topic_arn" {
  description = "Organization-wide alerts SNS topic."
  value       = module.guardduty.sns_topic_arn
}
