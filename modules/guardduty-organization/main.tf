data "aws_caller_identity" "admin" {}

# Executed in the Organizations management account.
resource "aws_guardduty_organization_admin_account" "this" {
  provider = aws.management

  region = var.region

  admin_account_id = data.aws_caller_identity.admin.account_id

  lifecycle {
    # Also makes the delegation wait for the detector in the admin account, so that
    # Terraform owns that detector instead of racing with GuardDuty creating one.
    precondition {
      condition     = var.detector_id != ""
      error_message = "detector_id of the delegated administrator account must be set."
    }
  }
}

# Executed in the delegated administrator account.
resource "aws_guardduty_organization_configuration" "this" {
  region = var.region

  detector_id                      = var.detector_id
  auto_enable_organization_members = var.auto_enable_organization_members

  depends_on = [aws_guardduty_organization_admin_account.this]
}

resource "aws_guardduty_organization_configuration_feature" "this" {
  for_each = var.features

  region = var.region

  detector_id = var.detector_id
  name        = each.key
  auto_enable = each.value.enabled ? var.auto_enable_organization_members : "NONE"

  dynamic "additional_configuration" {
    for_each = each.value.additional_configuration

    content {
      name        = additional_configuration.key
      auto_enable = each.value.enabled && additional_configuration.value ? var.auto_enable_organization_members : "NONE"
    }
  }

  depends_on = [aws_guardduty_organization_configuration.this]
}
