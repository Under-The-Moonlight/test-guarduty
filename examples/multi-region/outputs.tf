output "detector_ids" {
  description = "Detector ID per region."
  value       = { for region, m in module.guardduty : region => m.detector_id }
}

output "s3_bucket_arns" {
  description = "Findings bucket ARN per region."
  value       = { for region, m in module.guardduty : region => m.s3_bucket_arn }
}

output "sns_topic_arns" {
  description = "Alerts SNS topic ARN per region."
  value       = { for region, m in module.guardduty : region => m.sns_topic_arn }
}
