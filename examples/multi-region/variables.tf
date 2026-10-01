variable "home_region" {
  description = "Default region of the provider (used for API calls that are not region-scoped)."
  type        = string
  default     = null
}

variable "regions" {
  description = "Regions to enable GuardDuty in. GuardDuty is regional, so every region in use should be covered."
  type        = list(string)

  validation {
    condition     = length(var.regions) > 0 && length(distinct(var.regions)) == length(var.regions)
    error_message = "regions must be a non-empty list without duplicates."
  }
}

variable "alert_email_addresses" {
  description = "Email addresses subscribed to the alert topic in every region."
  type        = list(string)
  default     = []
}
