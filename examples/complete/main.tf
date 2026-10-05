provider "aws" {
  region = var.region

  default_tags {
    tags = {
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

locals {
  findings_bucket_name = "${var.name}-findings-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"
}

module "guardduty" {
  source = "../../modules/guardduty"

  name = var.name
  tags = var.tags

  finding_publishing_frequency = "FIFTEEN_MINUTES"

  enable_s3_protection                 = true
  enable_eks_audit_log_monitoring      = true
  enable_rds_login_activity_monitoring = true
  enable_ec2_malware_protection        = true
  enable_lambda_protection             = true
  eks_runtime_monitoring = {
    enabled                  = true
    manage_eks_addon         = true
    manage_ecs_fargate_agent = true
    manage_ec2_agent         = true
  }

  enable_s3_export                           = true
  s3_bucket_name                             = local.findings_bucket_name
  create_kms_key                             = true
  kms_key_deletion_window_in_days            = 30
  findings_retention_days                    = 730
  findings_noncurrent_version_retention_days = 30
  s3_access_logging = {
    target_bucket = aws_s3_bucket_policy.access_logs.bucket
    target_prefix = "guardduty-findings/"
  }

  enable_alerts               = true
  alert_severity_threshold    = 4
  alert_email_addresses       = var.alert_email_addresses
  alert_dead_letter_queue_arn = aws_sqs_queue.alerts_dlq.arn

  suppression_rules = [
    {
      name        = "archive-low-severity"
      description = "Auto-archive Low severity findings."
      criteria = [
        { field = "severity", less_than = "4" },
      ]
    },
    {
      name        = "archive-trusted-scanner"
      description = "Port probes coming from the internal vulnerability scanner."
      criteria = [
        { field = "type", equals = ["Recon:EC2/PortProbeUnprotectedPort", "Recon:EC2/Portscan"] },
        { field = "service.action.networkConnectionAction.remoteIpDetails.ipAddressV4", equals = var.trusted_scanner_ips },
      ]
    },
    {
      name        = "archive-sandbox-instances"
      description = "Findings on instances tagged Environment=sandbox."
      criteria = [
        { field = "resource.instanceDetails.tags.key", equals = ["Environment"] },
        { field = "resource.instanceDetails.tags.value", equals = ["sandbox"] },
        { field = "severity", less_than = "7" },
      ]
    },
    {
      name        = "saved-filter-eks"
      description = "Saved filter (no auto-archive) for EKS findings."
      action      = "NOOP"
      criteria = [
        { field = "resource.resourceType", equals = ["EKSCluster"] },
      ]
    },
  ]
}

resource "aws_s3_bucket" "access_logs" {
  #checkov:skip=CKV_AWS_18:This is the access log bucket itself
  #checkov:skip=CKV_AWS_145:S3 server access logging only delivers to buckets encrypted with SSE-S3
  #checkov:skip=CKV_AWS_144:Cross-region replication is out of scope for the example
  #checkov:skip=CKV2_AWS_62:Event notifications are not needed for access logs
  bucket = "${var.name}-access-logs-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"
}

resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id

  rule {
    id     = "expire-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  depends_on = [aws_s3_bucket_versioning.access_logs]
}

data "aws_iam_policy_document" "access_logs" {
  statement {
    sid       = "AllowS3ServerAccessLogs"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.access_logs.arn}/guardduty-findings/*"]

    principals {
      type        = "Service"
      identifiers = ["logging.s3.amazonaws.com"]
    }

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:s3:::${local.findings_bucket_name}"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.access_logs.arn, "${aws_s3_bucket.access_logs.arn}/*"]

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

resource "aws_s3_bucket_policy" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  policy = data.aws_iam_policy_document.access_logs.json

  depends_on = [aws_s3_bucket_public_access_block.access_logs]
}

resource "aws_sqs_queue" "alerts_dlq" {
  name                      = "${var.name}-alerts-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

data "aws_iam_policy_document" "alerts_dlq" {
  statement {
    sid       = "AllowEventBridgeDeadLetters"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.alerts_dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [module.guardduty.eventbridge_rule_arn]
    }
  }
}

resource "aws_sqs_queue_policy" "alerts_dlq" {
  queue_url = aws_sqs_queue.alerts_dlq.id
  policy    = data.aws_iam_policy_document.alerts_dlq.json
}
