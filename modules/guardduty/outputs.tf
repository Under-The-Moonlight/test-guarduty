output "detector_id" {
  description = "ID of the GuardDuty detector."
  value       = aws_guardduty_detector.this.id
}

output "detector_arn" {
  description = "ARN of the GuardDuty detector."
  value       = aws_guardduty_detector.this.arn
}

output "features" {
  description = "Map of managed GuardDuty features to their desired state. Can be passed to the `guardduty-organization` module."
  value       = local.features
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket that receives exported findings (null when export is disabled)."
  value       = one(values(aws_s3_bucket.findings)[*].arn)
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket that receives exported findings (null when export is disabled)."
  value       = one(values(aws_s3_bucket.findings)[*].id)
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for the findings bucket and the SNS topic (module-created or passed in)."
  value       = local.kms_key_arn
}

output "kms_key_policy_statements_json" {
  description = "Key policy statements GuardDuty and EventBridge need on the KMS key. Merge them into the policy of an externally managed key (`create_kms_key = false`)."
  value       = data.aws_iam_policy_document.kms_service_access.json
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic that receives alerts (null when alerts are disabled)."
  value       = var.enable_alerts ? local.sns_topic_arn : null
}

output "eventbridge_rule_arn" {
  description = "ARN of the EventBridge rule matching findings above the severity threshold (null when alerts are disabled)."
  value       = try(aws_cloudwatch_event_rule.findings[0].arn, null)
}

output "suppression_rule_ids" {
  description = "Map of suppression rule (filter) name to its resource ID."
  value       = { for name, filter in aws_guardduty_filter.this : name => filter.id }
}
