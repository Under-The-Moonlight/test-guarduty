variable "name" {
  description = "Name prefix used for all resources created by the module (S3 bucket, KMS alias, SNS topic, EventBridge rule)."
  type        = string
  default     = "guardduty"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9-]{0,30}[a-z0-9]$", var.name))
    error_message = "name must be 2-32 characters long, contain only lowercase letters, digits and hyphens, and must not start or end with a hyphen."
  }
}

variable "region" {
  description = "AWS region to deploy into. Defaults to the region configured on the provider. Set it (together with `for_each` on the module) to deploy into several regions with a single provider."
  type        = string
  default     = null

  validation {
    condition     = var.region == null || can(regex("^[a-z]{2}(-gov|-iso[a-z]*)?-[a-z]+-[0-9]+$", var.region))
    error_message = "region must be a valid AWS region name, e.g. \"eu-central-1\"."
  }
}

variable "tags" {
  description = "Tags applied to every taggable resource created by the module."
  type        = map(string)
  default     = {}
}

variable "finding_publishing_frequency" {
  description = "How often updates to existing findings are published to EventBridge and S3. New findings are always exported within ~5 minutes."
  type        = string
  default     = "FIFTEEN_MINUTES"

  validation {
    condition     = contains(["FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"], var.finding_publishing_frequency)
    error_message = "finding_publishing_frequency must be one of FIFTEEN_MINUTES, ONE_HOUR, SIX_HOURS."
  }
}

variable "enable_s3_protection" {
  description = "Enable S3 Protection (monitoring of S3 data events, feature S3_DATA_EVENTS)."
  type        = bool
  default     = true
}

variable "enable_eks_audit_log_monitoring" {
  description = "Enable EKS Audit Log Monitoring (feature EKS_AUDIT_LOGS)."
  type        = bool
  default     = true
}

variable "enable_eks_runtime_monitoring" {
  description = "Enable EKS Runtime Monitoring (feature RUNTIME_MONITORING). Requires the GuardDuty security agent on the clusters, see `runtime_monitoring_agent_management`."
  type        = bool
  default     = false
}

variable "runtime_monitoring_agent_management" {
  description = <<-EOT
    Controls whether GuardDuty automatically deploys and manages its security agent when Runtime Monitoring is enabled.
    `eks_addon`   - manage the `aws-guardduty-agent` EKS add-on on all clusters (EKS_ADDON_MANAGEMENT).
    `ecs_fargate` - manage the sidecar agent for ECS Fargate tasks (ECS_FARGATE_AGENT_MANAGEMENT).
    `ec2`         - manage the agent on EC2 instances through SSM (EC2_AGENT_MANAGEMENT).
    Set `eks_addon = false` if you deploy the agent yourself (e.g. via Terraform/Helm per cluster).
  EOT
  type = object({
    eks_addon   = optional(bool, true)
    ecs_fargate = optional(bool, false)
    ec2         = optional(bool, false)
  })
  default  = {}
  nullable = false
}

variable "enable_rds_login_activity_monitoring" {
  description = "Enable RDS Login Activity Monitoring for Aurora / RDS databases (feature RDS_LOGIN_EVENTS)."
  type        = bool
  default     = true
}

variable "enable_ec2_malware_protection" {
  description = "Enable GuardDuty-initiated Malware Protection for EC2 (EBS volume scanning, feature EBS_MALWARE_PROTECTION)."
  type        = bool
  default     = true
}

variable "enable_s3_export" {
  description = "Export findings to a KMS-encrypted S3 bucket created by the module."
  type        = bool
  default     = true
}

variable "s3_bucket_name" {
  description = "Name of the findings bucket. Defaults to `<name>-findings-<account_id>-<region>`."
  type        = string
  default     = null

  validation {
    condition     = var.s3_bucket_name == null || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.s3_bucket_name))
    error_message = "s3_bucket_name must be a valid S3 bucket name (3-63 characters, lowercase letters, digits, dots and hyphens)."
  }
}

variable "s3_force_destroy" {
  description = "Allow Terraform to delete the findings bucket even if it still contains objects. Keep `false` outside of test environments."
  type        = bool
  default     = false
}

variable "s3_access_logging" {
  description = "Optional server access logging for the findings bucket. `target_bucket` is an existing bucket that accepts S3 server access logs."
  type = object({
    target_bucket = string
    target_prefix = optional(string, "guardduty-findings/")
  })
  default = null
}

variable "findings_retention_days" {
  description = "Number of days after which exported findings are expired from the bucket."
  type        = number
  default     = 365

  validation {
    condition     = var.findings_retention_days >= 1 && floor(var.findings_retention_days) == var.findings_retention_days
    error_message = "findings_retention_days must be a positive integer."
  }
}

variable "findings_glacier_transition_days" {
  description = "Number of days after which exported findings are transitioned to S3 Glacier Flexible Retrieval. Set to `null` to disable the transition."
  type        = number
  default     = 90

  validation {
    condition = var.findings_glacier_transition_days == null || (
      try(var.findings_glacier_transition_days >= 1 && floor(var.findings_glacier_transition_days) == var.findings_glacier_transition_days, false)
    )
    error_message = "findings_glacier_transition_days must be a positive integer or null."
  }

  validation {
    condition     = var.findings_glacier_transition_days == null || try(var.findings_glacier_transition_days < var.findings_retention_days, false)
    error_message = "findings_glacier_transition_days must be lower than findings_retention_days."
  }
}

variable "findings_noncurrent_version_retention_days" {
  description = "Number of days noncurrent (overwritten or deleted) object versions are kept before permanent deletion."
  type        = number
  default     = 30

  validation {
    condition     = var.findings_noncurrent_version_retention_days >= 1 && floor(var.findings_noncurrent_version_retention_days) == var.findings_noncurrent_version_retention_days
    error_message = "findings_noncurrent_version_retention_days must be a positive integer."
  }
}

variable "create_kms_key" {
  description = "Create a customer managed KMS key used to encrypt the findings bucket and the SNS topic. When `false`, `kms_key_arn` must be provided."
  type        = bool
  default     = true
}

variable "kms_key_arn" {
  description = "ARN of an existing KMS key to use when `create_kms_key = false`. Its key policy must contain the statements from the `kms_key_policy_statements_json` output."
  type        = string
  default     = null

  validation {
    condition     = var.kms_key_arn == null || can(regex("^arn:aws[a-z-]*:kms:[a-z0-9-]+:[0-9]{12}:key/[a-zA-Z0-9-]+$", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN (arn:<partition>:kms:<region>:<account>:key/<id>). Aliases are not supported by GuardDuty publishing destinations."
  }

  validation {
    condition     = var.create_kms_key || var.kms_key_arn != null || !(var.enable_s3_export || (var.enable_alerts && var.create_sns_topic))
    error_message = "kms_key_arn is required when create_kms_key = false and either S3 export or the module-managed SNS topic is enabled."
  }
}

variable "kms_key_deletion_window_in_days" {
  description = "Waiting period before the module-created KMS key is deleted after `terraform destroy`."
  type        = number
  default     = 30

  validation {
    condition     = var.kms_key_deletion_window_in_days >= 7 && var.kms_key_deletion_window_in_days <= 30
    error_message = "kms_key_deletion_window_in_days must be between 7 and 30."
  }
}

variable "enable_alerts" {
  description = "Create an EventBridge rule that forwards findings at or above `alert_severity_threshold` to SNS."
  type        = bool
  default     = true
}

variable "alert_severity_threshold" {
  description = "Minimum finding severity that triggers an alert. GuardDuty severity ranges: Low 1.0-3.9, Medium 4.0-6.9, High 7.0-8.9, Critical 9.0-10.0."
  type        = number
  default     = 7

  validation {
    condition     = var.alert_severity_threshold >= 1 && var.alert_severity_threshold <= 10
    error_message = "alert_severity_threshold must be between 1 and 10."
  }
}

variable "create_sns_topic" {
  description = "Create the SNS topic for alerts. When `false`, `sns_topic_arn` must be provided and its topic policy must allow `events.amazonaws.com` to publish."
  type        = bool
  default     = true
}

variable "sns_topic_arn" {
  description = "ARN of an existing SNS topic to send alerts to when `create_sns_topic = false`."
  type        = string
  default     = null

  validation {
    condition     = var.sns_topic_arn == null || can(regex("^arn:aws[a-z-]*:sns:[a-z0-9-]+:[0-9]{12}:[A-Za-z0-9_-]+(\\.fifo)?$", var.sns_topic_arn))
    error_message = "sns_topic_arn must be a valid SNS topic ARN."
  }

  validation {
    condition     = !var.enable_alerts || var.create_sns_topic || var.sns_topic_arn != null
    error_message = "sns_topic_arn is required when enable_alerts = true and create_sns_topic = false."
  }
}

variable "alert_email_addresses" {
  description = "Email addresses subscribed to the alerts SNS topic. Each address has to confirm the subscription."
  type        = list(string)
  default     = []
  nullable    = false

  validation {
    condition     = alltrue([for e in var.alert_email_addresses : can(regex("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$", e))])
    error_message = "alert_email_addresses must contain valid email addresses."
  }
}

variable "suppression_rules" {
  description = <<-EOT
    GuardDuty filters. The list order defines the filter rank (first element = rank 1).
    `action` is `ARCHIVE` (suppression rule: matching findings are auto-archived) or `NOOP` (saved filter only).
    Each `criteria` element targets one finding attribute (`field`, e.g. `type`, `severity`,
    `resource.instanceDetails.tags.value`) and sets at least one comparison operator.
    See https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_filter-findings.html for the list of fields.
  EOT
  type = list(object({
    name        = string
    description = optional(string)
    action      = optional(string, "ARCHIVE")
    criteria = list(object({
      field                 = string
      equals                = optional(list(string))
      not_equals            = optional(list(string))
      matches               = optional(list(string))
      not_matches           = optional(list(string))
      greater_than          = optional(string)
      greater_than_or_equal = optional(string)
      less_than             = optional(string)
      less_than_or_equal    = optional(string)
    }))
  }))
  default  = []
  nullable = false

  validation {
    condition     = length(var.suppression_rules) <= 100
    error_message = "GuardDuty supports at most 100 filters per detector."
  }

  validation {
    condition     = alltrue([for r in var.suppression_rules : can(regex("^[A-Za-z0-9_.-]{3,64}$", r.name))])
    error_message = "Suppression rule names must be 3-64 characters long and contain only letters, digits, '.', '_' and '-'."
  }

  validation {
    condition     = length(distinct([for r in var.suppression_rules : r.name])) == length(var.suppression_rules)
    error_message = "Suppression rule names must be unique."
  }

  validation {
    condition     = alltrue([for r in var.suppression_rules : contains(["ARCHIVE", "NOOP"], r.action)])
    error_message = "Suppression rule action must be ARCHIVE or NOOP."
  }

  validation {
    condition     = alltrue([for r in var.suppression_rules : length(r.criteria) > 0])
    error_message = "Each suppression rule must have at least one criterion."
  }

  validation {
    condition = alltrue(flatten([
      for r in var.suppression_rules : [
        for c in r.criteria : anytrue([
          for op in [c.equals, c.not_equals, c.matches, c.not_matches, c.greater_than, c.greater_than_or_equal, c.less_than, c.less_than_or_equal] : op != null
        ])
      ]
    ]))
    error_message = "Each suppression rule criterion must set at least one operator (equals, not_equals, matches, not_matches, greater_than, greater_than_or_equal, less_than, less_than_or_equal)."
  }
}
