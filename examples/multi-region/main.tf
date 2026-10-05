provider "aws" {
  region = var.home_region
}

module "guardduty" {
  source   = "../../modules/guardduty"
  for_each = toset(var.regions)

  region = each.key

  alert_severity_threshold = 7
  alert_email_addresses    = var.alert_email_addresses
}
