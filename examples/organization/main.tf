# Organizations management account: only used to designate the delegated administrator.
provider "aws" {
  alias  = "management"
  region = var.region
}

# Delegated administrator (security tooling) account: owns the detector, findings export and alerts
# for the whole organization.
provider "aws" {
  region = var.region

  assume_role {
    role_arn = var.delegated_admin_role_arn
  }
}

module "guardduty" {
  source = "../../modules/guardduty"

  name = "guardduty-org"

  enable_eks_runtime_monitoring = true
  alert_email_addresses         = var.alert_email_addresses
}

module "guardduty_organization" {
  source = "../../modules/guardduty-organization"

  providers = {
    aws            = aws
    aws.management = aws.management
  }

  detector_id                      = module.guardduty.detector_id
  features                         = module.guardduty.features
  auto_enable_organization_members = "ALL"
}
