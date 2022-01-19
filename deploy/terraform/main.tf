terraform {
  required_providers {
    aws      = {
      source  = "hashicorp/aws"
      version = "~> 3.70.0"
    }
    lacework = {
      source = "lacework/lacework"
    }
  }
}

locals {
  lambda_handler = "main"
  name = "lw-sechub-integration"
  lw_accounts = [""]
  lw_sechub_resource = "arn:aws:securityhub:us-east-2:950194951070:product/950194951070/default"
}

provider "aws" {
  region     = "us-east-2"
}

resource "aws_iam_role" "lw-sechub-integration" {
  name = "lw-sechub-role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Action": "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "basic-lambda" {
  role = aws_iam_role.lw-sechub-integration.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "lw-sechub-integration" {
  filename          = "../../function.zip"
  function_name     = local.name
  role              = aws_iam_role.lw-sechub-integration.arn
  handler           = local.lambda_handler
  source_code_hash  = filebase64sha256("../../function.zip")
  runtime           = "go1.x"
  memory_size       = 256
  timeout           = 30
}

module "eventbridge" {
  source = "terraform-aws-modules/eventbridge/aws"

  bus_name = "lw-sechub-integration"

  #event_pattern is an array of the root Lacework account "434813966438" and your AWS accounts.
  rules = {
    lw-sechub = {
      description   = "Capture incoming Lacework events"
      event_pattern = jsonencode({ "account" : local.lw_accounts })
      enabled       = true
    }
  }

  # targets is the lambda function we created above
  targets = {
    lw-sechub = [
      {
        name = local.name
        arn  = aws_lambda_function.lw-sechub-integration.arn
      }
    ]
  }
}

resource "aws_iam_policy" "policy" {
  name        = "lw-sechub-batchimport"
  description = "allows Lacework Lambda to post events to Security Hub"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "securityhub:BatchImportFindings",
        ]
        Effect   = "Allow"
        Resource = local.lw_sechub_resource
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "policy-attach" {
  role = aws_iam_role.lw-sechub-integration.name
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_cloudwatch_event_permission" "LaceworkAccess" {
  principal    = local.lw_accounts
  statement_id = "LaceworkAccess"
  action = "events:PutEvents"
  event_bus_name = local.name

  depends_on = [
    module.eventbridge
  ]
}



resource "lacework_alert_channel_aws_cloudwatch" "all_events" {
  name            = local.name
  event_bus_arn   = module.eventbridge.eventbridge_bus_arn
  group_issues_by = "Events"
}

resource "lacework_alert_rule" "all_events" {
  name             = local.name
  description      = "This is an example alert rule"
  alert_channels   = [lacework_alert_channel_aws_cloudwatch.all_events.id]
  severities       = ["Critical", "High", "Medium", "Low", "Info"]
}
