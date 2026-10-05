provider "aws" {
  region = var.region

  default_tags {
    tags = {
      ManagedBy = "terraform"
    }
  }
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
  create_kms_key                             = true
  kms_key_deletion_window_in_days            = 30
  findings_retention_days                    = 730
  findings_noncurrent_version_retention_days = 30
  s3_access_logging = var.access_logs_bucket == null ? null : {
    target_bucket = var.access_logs_bucket
  }

  enable_alerts               = true
  alert_severity_threshold    = 4
  alert_email_addresses       = var.alert_email_addresses
  alert_dead_letter_queue_arn = var.alert_dead_letter_queue_arn

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
