provider "aws" {
  region = var.home_region
}

# AWS provider 6.x supports a per-resource `region` argument, so a single provider
# configuration can deploy GuardDuty into every region with a plain for_each.
module "guardduty" {
  source   = "../../modules/guardduty"
  for_each = toset(var.regions)

  region = each.key

  alert_severity_threshold = 7
  alert_email_addresses    = var.alert_email_addresses
}
