data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {
  region = var.region
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  create_sns_topic = var.enable_alerts && var.create_sns_topic
  create_kms_key   = var.create_kms_key && (var.enable_s3_export || local.create_sns_topic)
  kms_key_arn      = local.create_kms_key ? aws_kms_key.this[0].arn : var.kms_key_arn

  bucket_name = coalesce(var.s3_bucket_name, "${var.name}-findings-${local.account_id}-${local.region}")
  bucket_arn  = "arn:${local.partition}:s3:::${local.bucket_name}"

  event_rule_name = "${var.name}-findings-alert"
  event_rule_arn  = "arn:${local.partition}:events:${local.region}:${local.account_id}:rule/${local.event_rule_name}"
  sns_topic_name  = "${var.name}-findings-alert"
  sns_topic_arn   = local.create_sns_topic ? aws_sns_topic.this[0].arn : var.sns_topic_arn

  features = {
    S3_DATA_EVENTS = {
      enabled                  = var.enable_s3_protection
      additional_configuration = {}
    }
    EKS_AUDIT_LOGS = {
      enabled                  = var.enable_eks_audit_log_monitoring
      additional_configuration = {}
    }
    RUNTIME_MONITORING = {
      enabled = var.eks_runtime_monitoring.enabled
      additional_configuration = {
        EKS_ADDON_MANAGEMENT         = var.eks_runtime_monitoring.manage_eks_addon
        ECS_FARGATE_AGENT_MANAGEMENT = var.eks_runtime_monitoring.manage_ecs_fargate_agent
        EC2_AGENT_MANAGEMENT         = var.eks_runtime_monitoring.manage_ec2_agent
      }
    }
    RDS_LOGIN_EVENTS = {
      enabled                  = var.enable_rds_login_activity_monitoring
      additional_configuration = {}
    }
    EBS_MALWARE_PROTECTION = {
      enabled                  = var.enable_ec2_malware_protection
      additional_configuration = {}
    }
    LAMBDA_NETWORK_LOGS = {
      enabled                  = var.enable_lambda_protection
      additional_configuration = {}
    }
  }
}

resource "aws_guardduty_detector" "this" {
  #checkov:skip=CKV2_AWS_3:Organization-wide enablement is provided by the guardduty-organization module.
  region = var.region

  enable                       = true
  finding_publishing_frequency = var.finding_publishing_frequency

  tags = var.tags

  lifecycle {
    precondition {
      condition     = var.kms_key_arn == null || try(split(":", var.kms_key_arn)[3] == local.region, false)
      error_message = "kms_key_arn must be a key in the region the module is deployed to (${local.region})."
    }

    precondition {
      condition     = var.sns_topic_arn == null || try(split(":", var.sns_topic_arn)[3] == local.region, false)
      error_message = "sns_topic_arn must be a topic in the region the module is deployed to (${local.region})."
    }
  }
}

resource "aws_guardduty_detector_feature" "this" {
  for_each = local.features

  region = var.region

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  status      = each.value.enabled ? "ENABLED" : "DISABLED"

  dynamic "additional_configuration" {
    for_each = each.value.additional_configuration

    content {
      name   = additional_configuration.key
      status = each.value.enabled && additional_configuration.value ? "ENABLED" : "DISABLED"
    }
  }
}

data "aws_iam_policy_document" "kms_service_access" {
  dynamic "statement" {
    for_each = var.enable_s3_export ? [1] : []

    content {
      sid       = "AllowGuardDutyToEncryptFindings"
      effect    = "Allow"
      actions   = ["kms:GenerateDataKey"]
      resources = ["*"]

      principals {
        type        = "Service"
        identifiers = ["guardduty.amazonaws.com"]
      }

      condition {
        test     = "StringEquals"
        variable = "aws:SourceAccount"
        values   = [local.account_id]
      }

      # only one detector per account and region, so this is ours without depending on it
      condition {
        test     = "ArnLike"
        variable = "aws:SourceArn"
        values   = ["arn:${local.partition}:guardduty:${local.region}:${local.account_id}:detector/*"]
      }
    }
  }

  dynamic "statement" {
    for_each = local.create_sns_topic ? [1] : []

    content {
      # needed for EventBridge to publish to the encrypted topic
      sid       = "AllowEventBridgeToUseKeyForSNS"
      effect    = "Allow"
      actions   = ["kms:GenerateDataKey", "kms:Decrypt"]
      resources = ["*"]

      principals {
        type        = "Service"
        identifiers = ["events.amazonaws.com"]
      }
    }
  }
}

data "aws_iam_policy_document" "kms" {
  #checkov:skip=CKV_AWS_109:Key policy: "Resource: *" refers to this key only; the root statement is the AWS default that delegates access to IAM.
  #checkov:skip=CKV_AWS_111:Key policy: "Resource: *" refers to this key only; the root statement is the AWS default that delegates access to IAM.
  #checkov:skip=CKV_AWS_356:Key policy: "Resource: *" refers to this key only.
  count = local.create_kms_key ? 1 : 0

  source_policy_documents = [data.aws_iam_policy_document.kms_service_access.json]

  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${local.partition}:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "this" {
  count = local.create_kms_key ? 1 : 0

  region = var.region

  description             = "Encrypts GuardDuty findings exported to S3 and GuardDuty alerts in SNS (${var.name})."
  enable_key_rotation     = true
  deletion_window_in_days = var.kms_key_deletion_window_in_days
  policy                  = data.aws_iam_policy_document.kms[0].json

  tags = var.tags
}

resource "aws_kms_alias" "this" {
  count = local.create_kms_key ? 1 : 0

  region = var.region

  name          = "alias/${var.name}-findings"
  target_key_id = aws_kms_key.this[0].key_id
}

resource "aws_s3_bucket" "findings" {
  #checkov:skip=CKV_AWS_18:Access logging is optional (var.s3_access_logging); it requires a separate, pre-existing log bucket.
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope; findings are already replicated to EventBridge/SNS and can be re-exported.
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed; alerting is done through EventBridge on the findings themselves.
  for_each = var.enable_s3_export ? toset(["findings"]) : toset([])

  region = var.region

  bucket        = local.bucket_name
  force_destroy = var.s3_force_destroy

  tags = var.tags
}

resource "aws_s3_bucket_public_access_block" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket                  = each.value.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket = each.value.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_logging" "findings" {
  for_each = var.s3_access_logging == null ? {} : aws_s3_bucket.findings

  region = var.region

  bucket        = each.value.id
  target_bucket = var.s3_access_logging.target_bucket
  target_prefix = var.s3_access_logging.target_prefix
}

resource "aws_s3_bucket_versioning" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket = each.value.id

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket = each.value.id

  rule {
    id     = "findings-retention"
    status = "Enabled"

    filter {}

    dynamic "transition" {
      for_each = var.findings_glacier_transition_days == null ? [] : [var.findings_glacier_transition_days]

      content {
        days          = transition.value
        storage_class = "GLACIER"
      }
    }

    expiration {
      days = var.findings_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = var.findings_noncurrent_version_retention_days
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "expired-delete-markers"
    status = "Enabled"

    filter {}

    expiration {
      expired_object_delete_marker = true
    }
  }

  depends_on = [aws_s3_bucket_versioning.findings]
}

data "aws_iam_policy_document" "findings_bucket" {
  count = var.enable_s3_export ? 1 : 0

  statement {
    sid       = "AllowGuardDutyGetBucketLocation"
    effect    = "Allow"
    actions   = ["s3:GetBucketLocation"]
    resources = [local.bucket_arn]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_guardduty_detector.this.arn]
    }
  }

  statement {
    sid       = "AllowGuardDutyPutObject"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [aws_guardduty_detector.this.arn]
    }
  }

  statement {
    sid       = "DenyUnencryptedGuardDutyUploads"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid       = "DenyIncorrectEncryptionKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${local.bucket_arn}/*"]

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [local.kms_key_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [local.bucket_arn, "${local.bucket_arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "findings" {
  for_each = aws_s3_bucket.findings

  region = var.region

  bucket = each.value.id
  policy = data.aws_iam_policy_document.findings_bucket[0].json

  depends_on = [aws_s3_bucket_public_access_block.findings]
}

resource "aws_guardduty_publishing_destination" "this" {
  for_each = aws_s3_bucket.findings

  region = var.region

  detector_id      = aws_guardduty_detector.this.id
  destination_type = "S3"
  destination_arn  = each.value.arn
  kms_key_arn      = local.kms_key_arn

  tags = var.tags

  depends_on = [
    aws_s3_bucket_policy.findings,
    aws_s3_bucket_server_side_encryption_configuration.findings,
    aws_kms_key.this,
  ]
}

resource "aws_sns_topic" "this" {
  count = local.create_sns_topic ? 1 : 0

  region = var.region

  name              = local.sns_topic_name
  kms_master_key_id = local.kms_key_arn

  tags = var.tags
}

data "aws_iam_policy_document" "sns" {
  count = local.create_sns_topic ? 1 : 0

  statement {
    sid       = "AllowEventBridgePublish"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.this[0].arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [local.event_rule_arn]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.this[0].arn]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_sns_topic_policy" "this" {
  count = local.create_sns_topic ? 1 : 0

  region = var.region

  arn    = aws_sns_topic.this[0].arn
  policy = data.aws_iam_policy_document.sns[0].json
}

resource "aws_sns_topic_subscription" "email" {
  for_each = var.enable_alerts ? toset(var.alert_email_addresses) : toset([])

  region = var.region

  topic_arn = local.sns_topic_arn
  protocol  = "email"
  endpoint  = each.value
}

resource "aws_cloudwatch_event_rule" "findings" {
  count = var.enable_alerts ? 1 : 0

  region = var.region

  name        = local.event_rule_name
  description = "GuardDuty findings with severity >= ${var.alert_severity_threshold}"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
    detail = {
      severity = [{ numeric = [">=", var.alert_severity_threshold] }]
    }
  })

  tags = var.tags
}

resource "aws_cloudwatch_event_target" "sns" {
  count = var.enable_alerts ? 1 : 0

  region = var.region

  rule      = aws_cloudwatch_event_rule.findings[0].name
  target_id = "sns"
  arn       = local.sns_topic_arn

  dynamic "dead_letter_config" {
    for_each = var.alert_dead_letter_queue_arn == null ? [] : [var.alert_dead_letter_queue_arn]

    content {
      arn = dead_letter_config.value
    }
  }

  depends_on = [aws_sns_topic_policy.this]
}

resource "aws_guardduty_filter" "this" {
  for_each = { for idx, rule in var.suppression_rules : rule.name => merge(rule, { rank = idx + 1 }) }

  region = var.region

  detector_id = aws_guardduty_detector.this.id
  name        = each.key
  description = each.value.description
  action      = each.value.action
  rank        = each.value.rank

  finding_criteria {
    dynamic "criterion" {
      for_each = each.value.criteria

      content {
        field                 = criterion.value.field
        equals                = criterion.value.equals
        not_equals            = criterion.value.not_equals
        matches               = criterion.value.matches
        not_matches           = criterion.value.not_matches
        greater_than          = criterion.value.greater_than
        greater_than_or_equal = criterion.value.greater_than_or_equal
        less_than             = criterion.value.less_than
        less_than_or_equal    = criterion.value.less_than_or_equal
      }
    }
  }

  tags = var.tags
}
