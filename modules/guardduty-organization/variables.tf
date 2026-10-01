variable "region" {
  description = "AWS region to configure. Defaults to the region of the providers. GuardDuty organization settings are regional."
  type        = string
  default     = null
}

variable "detector_id" {
  description = "ID of the GuardDuty detector in the delegated administrator account (`detector_id` output of the `guardduty` module)."
  type        = string
}

variable "auto_enable_organization_members" {
  description = "Which member accounts GuardDuty is enabled for automatically: ALL (existing and new), NEW (only accounts joining later) or NONE."
  type        = string
  default     = "ALL"

  validation {
    condition     = contains(["ALL", "NEW", "NONE"], var.auto_enable_organization_members)
    error_message = "auto_enable_organization_members must be one of ALL, NEW, NONE."
  }
}

variable "features" {
  description = "Features to auto-enable in member accounts, in the format of the `features` output of the `guardduty` module."
  type = map(object({
    enabled                  = bool
    additional_configuration = map(bool)
  }))
}
