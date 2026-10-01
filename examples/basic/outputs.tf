output "detector_id" {
  description = "ID of the GuardDuty detector."
  value       = module.guardduty.detector_id
}

output "s3_bucket_arn" {
  description = "ARN of the findings bucket."
  value       = module.guardduty.s3_bucket_arn
}

output "sns_topic_arn" {
  description = "ARN of the alerts SNS topic."
  value       = module.guardduty.sns_topic_arn
}

output "kms_key_arn" {
  description = "ARN of the KMS key."
  value       = module.guardduty.kms_key_arn
}
