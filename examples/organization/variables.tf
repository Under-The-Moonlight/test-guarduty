variable "region" {
  description = "AWS region to configure. Falls back to the provider default (AWS_REGION / profile) when null."
  type        = string
  default     = null
}

variable "delegated_admin_role_arn" {
  description = "ARN of the IAM role Terraform assumes in the GuardDuty delegated administrator account."
  type        = string
}

variable "alert_email_addresses" {
  description = "Email addresses subscribed to organization-wide GuardDuty alerts."
  type        = list(string)
  default     = []
}
