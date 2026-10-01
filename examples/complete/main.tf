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

  # Detector
  finding_publishing_frequency = "FIFTEEN_MINUTES"

  # Protection features
  enable_s3_protection                 = true
  enable_eks_audit_log_monitoring      = true
  enable_eks_runtime_monitoring        = true
  enable_rds_login_activity_monitoring = true
  enable_ec2_malware_protection        = true
  runtime_monitoring_agent_management = {
    eks_addon   = true
    ecs_fargate = true
    ec2         = true
  }

  # Findings export
  enable_s3_export                           = true
  create_kms_key                             = true
  kms_key_deletion_window_in_days            = 30
  findings_glacier_transition_days           = 90
  findings_retention_days                    = 730
  findings_noncurrent_version_retention_days = 30
  s3_access_logging = var.access_logs_bucket == null ? null : {
    target_bucket = var.access_logs_bucket
  }

  # Alerts: Medium and above
  enable_alerts            = true
  alert_severity_threshold = 4
  alert_email_addresses    = var.alert_email_addresses

  # Suppression rules (evaluated in list order)
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
