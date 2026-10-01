variable "region" {
  description = "AWS region to deploy into. Falls back to the provider default (AWS_REGION / profile) when null."
  type        = string
  default     = null
}
