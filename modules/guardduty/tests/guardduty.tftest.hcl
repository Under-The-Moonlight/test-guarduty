mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "111122223333"
    }
  }

  override_data {
    target = data.aws_partition.current
    values = {
      partition  = "aws"
      dns_suffix = "amazonaws.com"
    }
  }

  override_data {
    target = data.aws_region.current
    values = {
      region = "eu-central-1"
    }
  }

  # mock provider returns random strings, policy docs need valid json
  mock_data "aws_iam_policy_document" {
    defaults = {
      json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
    }
  }

  mock_resource "aws_guardduty_detector" {
    defaults = {
      arn = "arn:aws:guardduty:eu-central-1:111122223333:detector/12abc34d567e8fa901bc2d34e56789f0"
    }
  }

  mock_resource "aws_kms_key" {
    defaults = {
      arn = "arn:aws:kms:eu-central-1:111122223333:key/11111111-2222-3333-4444-555555555555"
    }
  }

  mock_resource "aws_sns_topic" {
    defaults = {
      arn = "arn:aws:sns:eu-central-1:111122223333:guardduty-findings-alert"
    }
  }

  mock_resource "aws_s3_bucket" {
    defaults = {
      arn = "arn:aws:s3:::guardduty-findings-111122223333-eu-central-1"
    }
  }
}

run "defaults" {
  command = apply

  assert {
    condition     = aws_guardduty_detector.this.finding_publishing_frequency == "FIFTEEN_MINUTES"
    error_message = "Default publishing frequency should be FIFTEEN_MINUTES."
  }

  assert {
    condition = alltrue([
      for f in ["S3_DATA_EVENTS", "EKS_AUDIT_LOGS", "RDS_LOGIN_EVENTS", "EBS_MALWARE_PROTECTION"] :
      aws_guardduty_detector_feature.this[f].status == "ENABLED"
    ])
    error_message = "S3, EKS audit, RDS and EC2 malware protection should be enabled by default."
  }

  assert {
    condition     = aws_guardduty_detector_feature.this["RUNTIME_MONITORING"].status == "DISABLED"
    error_message = "Runtime monitoring should be opt-in."
  }

  assert {
    condition     = aws_s3_bucket.findings[0].bucket == "guardduty-findings-111122223333-eu-central-1"
    error_message = "Bucket name should be derived from name, account and region."
  }

  assert {
    condition     = one(aws_s3_bucket_server_side_encryption_configuration.findings[0].rule).apply_server_side_encryption_by_default[0].kms_master_key_id == aws_kms_key.this[0].arn
    error_message = "Bucket must be encrypted with the module-created KMS key."
  }

  assert {
    condition = alltrue([
      aws_s3_bucket_public_access_block.findings[0].block_public_acls,
      aws_s3_bucket_public_access_block.findings[0].block_public_policy,
      aws_s3_bucket_public_access_block.findings[0].ignore_public_acls,
      aws_s3_bucket_public_access_block.findings[0].restrict_public_buckets,
    ])
    error_message = "All public access must be blocked."
  }

  assert {
    condition     = aws_kms_key.this[0].enable_key_rotation
    error_message = "KMS key rotation must be enabled."
  }

  assert {
    condition     = aws_sns_topic.this[0].kms_master_key_id == aws_kms_key.this[0].arn
    error_message = "SNS topic must be encrypted with the module KMS key."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.findings[0].event_pattern).detail.severity[0].numeric[1] == 7
    error_message = "Default severity threshold should be 7 (High)."
  }

  assert {
    condition     = aws_guardduty_publishing_destination.this[0].kms_key_arn == aws_kms_key.this[0].arn
    error_message = "Publishing destination must use the module KMS key."
  }

  assert {
    condition     = output.kms_key_arn == aws_kms_key.this[0].arn && output.sns_topic_arn == aws_sns_topic.this[0].arn
    error_message = "Outputs must expose the created KMS key and SNS topic."
  }
}

run "bucket_policy_is_scoped_to_detector" {
  command = apply

  assert {
    condition = alltrue([
      for s in data.aws_iam_policy_document.findings_bucket[0].statement : anytrue([
        for c in s.condition : c.variable == "aws:SourceArn" && contains(c.values, aws_guardduty_detector.this.arn)
      ]) if s.effect == "Allow"
    ])
    error_message = "Every Allow statement in the bucket policy must be scoped to the detector ARN."
  }

  assert {
    condition     = contains([for s in data.aws_iam_policy_document.findings_bucket[0].statement : s.sid], "DenyInsecureTransport")
    error_message = "Bucket policy must deny non-TLS access."
  }

  assert {
    condition = anytrue([
      for s in data.aws_iam_policy_document.findings_bucket[0].statement : anytrue([
        for c in s.condition : contains(c.values, aws_kms_key.this[0].arn)
      ]) if s.sid == "DenyIncorrectEncryptionKey"
    ])
    error_message = "Bucket policy must deny uploads encrypted with any other key."
  }
}

run "all_features_disabled" {
  command = plan

  variables {
    enable_s3_protection                 = false
    enable_eks_audit_log_monitoring      = false
    enable_eks_runtime_monitoring        = false
    enable_rds_login_activity_monitoring = false
    enable_ec2_malware_protection        = false
  }

  assert {
    condition     = alltrue([for f in aws_guardduty_detector_feature.this : f.status == "DISABLED"])
    error_message = "All features must be explicitly disabled."
  }
}

run "runtime_monitoring_with_agent_management" {
  command = plan

  variables {
    enable_eks_runtime_monitoring = true
    runtime_monitoring_agent_management = {
      eks_addon   = true
      ecs_fargate = false
    }
  }

  assert {
    condition     = aws_guardduty_detector_feature.this["RUNTIME_MONITORING"].status == "ENABLED"
    error_message = "Runtime monitoring should be enabled."
  }

  assert {
    condition = {
      for c in aws_guardduty_detector_feature.this["RUNTIME_MONITORING"].additional_configuration : c.name => c.status
      } == {
      EKS_ADDON_MANAGEMENT         = "ENABLED"
      ECS_FARGATE_AGENT_MANAGEMENT = "DISABLED"
      EC2_AGENT_MANAGEMENT         = "DISABLED"
    }
    error_message = "Agent management must follow runtime_monitoring_agent_management."
  }
}

run "external_kms_key" {
  command = plan

  variables {
    create_kms_key = false
    kms_key_arn    = "arn:aws:kms:eu-central-1:111122223333:key/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
  }

  assert {
    condition     = length(aws_kms_key.this) == 0
    error_message = "No KMS key should be created when an external key is passed."
  }

  assert {
    condition     = aws_guardduty_publishing_destination.this[0].kms_key_arn == var.kms_key_arn
    error_message = "Publishing destination must use the external KMS key."
  }

  assert {
    condition     = length(data.aws_iam_policy_document.kms_service_access.statement) == 2
    error_message = "Required key policy statements for GuardDuty and EventBridge must be exposed."
  }
}

run "export_and_alerts_disabled" {
  command = plan

  variables {
    enable_s3_export = false
    enable_alerts    = false
  }

  assert {
    condition     = length(aws_s3_bucket.findings) == 0 && length(aws_kms_key.this) == 0 && length(aws_sns_topic.this) == 0
    error_message = "Bucket, KMS key and SNS topic must not be created."
  }

  assert {
    condition     = output.s3_bucket_arn == null && output.sns_topic_arn == null && output.kms_key_arn == null
    error_message = "Outputs must be null when the resources are disabled."
  }
}

run "suppression_rules" {
  command = plan

  variables {
    alert_severity_threshold = 4.5
    suppression_rules = [
      {
        name     = "archive-low"
        criteria = [{ field = "severity", less_than = "4" }]
      },
      {
        name     = "saved-filter"
        action   = "NOOP"
        criteria = [{ field = "type", equals = ["Recon:EC2/Portscan"] }]
      },
    ]
  }

  assert {
    condition     = aws_guardduty_filter.this["archive-low"].rank == 1 && aws_guardduty_filter.this["saved-filter"].rank == 2
    error_message = "Rank must follow list order."
  }

  assert {
    condition     = aws_guardduty_filter.this["archive-low"].action == "ARCHIVE" && aws_guardduty_filter.this["saved-filter"].action == "NOOP"
    error_message = "Action must default to ARCHIVE."
  }

  assert {
    condition     = jsondecode(aws_cloudwatch_event_rule.findings[0].event_pattern).detail.severity[0].numeric[1] == 4.5
    error_message = "Event pattern must use the configured threshold."
  }
}

run "invalid_publishing_frequency" {
  command = plan

  variables {
    finding_publishing_frequency = "DAILY"
  }

  expect_failures = [var.finding_publishing_frequency]
}

run "invalid_severity_threshold" {
  command = plan

  variables {
    alert_severity_threshold = 11
  }

  expect_failures = [var.alert_severity_threshold]
}

run "external_kms_key_required" {
  command = plan

  variables {
    create_kms_key = false
  }

  expect_failures = [var.kms_key_arn]
}

run "duplicate_suppression_rule_names" {
  command = plan

  variables {
    suppression_rules = [
      { name = "dup", criteria = [{ field = "severity", less_than = "4" }] },
      { name = "dup", criteria = [{ field = "severity", less_than = "2" }] },
    ]
  }

  expect_failures = [var.suppression_rules]
}

run "criterion_without_operator" {
  command = plan

  variables {
    suppression_rules = [
      { name = "empty", criteria = [{ field = "severity" }] },
    ]
  }

  expect_failures = [var.suppression_rules]
}

run "glacier_after_expiration" {
  command = plan

  variables {
    findings_retention_days          = 30
    findings_glacier_transition_days = 60
  }

  expect_failures = [var.findings_glacier_transition_days]
}
