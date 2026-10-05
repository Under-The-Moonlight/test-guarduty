provider "aws" {
  region = var.region
}

module "guardduty" {
  source = "../../modules/guardduty"
}
