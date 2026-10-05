variable "region" {
  description = "AWS region to deploy into. Falls back to the provider default (AWS_REGION / profile) when null."
  type        = string
  default     = null
}

variable "name" {
  description = "Name prefix for the created resources."
  type        = string
  default     = "guardduty-complete"
}

variable "tags" {
  description = "Tags applied to all resources."
  type        = map(string)
  default = {
    Project = "security-baseline"
  }
}

variable "alert_email_addresses" {
  description = "Email addresses subscribed to GuardDuty alerts."
  type        = list(string)
  default     = ["security-alerts@example.com"]
}

variable "trusted_scanner_ips" {
  description = "Public IPs of the internal vulnerability scanner whose port probes are suppressed."
  type        = list(string)
  default     = ["198.51.100.10", "198.51.100.11"]
}
