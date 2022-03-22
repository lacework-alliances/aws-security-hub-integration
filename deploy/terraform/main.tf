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
  # <lw_instance>.lacework.net
  lw_instance = ""
  # aws_region sets the region for integration deployment (should be the same as your Security Hub instance)
  aws_region = "us-west-2"
  # default_account is the main AWS account id that unknown data sources will be mapped to in Security Hub
  default_account = ""
  # customer_accounts is the array of customer's AWS accounts that are configured in Lacework,
  customer_accounts = [local.default_account]
}

provider "aws" {
  region     = local.aws_region
  # profile    = ""
}

provider "lacework" {
  profile = "default"
  # account = local.lw_instance
  # api_key = ""
  # api_secret = ""
}

resource "aws_iam_role" "lw-sechub-role" {
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

resource "aws_sqs_queue" "lw-sechub-queue" {
  name          = "lw-sechub-queue"
  delay_seconds = 0
  message_retention_seconds = 86400
}

resource "aws_iam_role_policy_attachment" "basic-lambda" {
  role = aws_iam_role.lw-sechub-role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaSQSQueueExecutionRole"
}

resource "aws_lambda_function" "lw-sechub-integration" {
  filename          = "../../function.zip"
  function_name     = "lw-sechub-integration"
  description       = "This lambda is used to receive SQS messages from Lacework and submit findings to Security Hub"
  role              = aws_iam_role.lw-sechub-role.arn
  handler           = "main"
  source_code_hash  = filebase64sha256("../../function.zip")
  runtime           = "go1.x"
  memory_size       = 256
  timeout           = 30

  environment {
    variables = {
      DEFAULT_AWS_ACCOUNT = local.default_account
      LACEWORK_INSTANCE = local.lw_instance
    }
  }

  tags = {
    lw_instance = local.lw_instance
  }

  depends_on = [
    aws_sqs_queue.lw-sechub-queue
  ]
}

resource "aws_lambda_event_source_mapping" "lw-sechub" {
  event_source_arn = aws_sqs_queue.lw-sechub-queue.arn
  function_name    = aws_lambda_function.lw-sechub-integration.arn
}


module "eventbridge" {
  source = "terraform-aws-modules/eventbridge/aws"

  bus_name = "lw-sechub-integration"

  #event_pattern is an array of the root Lacework account "434813966438" and your AWS accounts.
  rules = {
    lw-sechub = {
      description   = "Capture incoming Lacework events"
      event_pattern = jsonencode({ "account" : local.customer_accounts })
      enabled       = true
    }
  }

  # targets is the SQS queue we created above
  targets = {
    lw-sechub = [
      {
        name = aws_sqs_queue.lw-sechub-queue.name
        arn  = aws_sqs_queue.lw-sechub-queue.arn
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
        Resource = format("arn:aws:securityhub:%s::product/lacework/lacework", local.aws_region)
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "role-policy-attach" {
  role = "lw-sechub-role"
  policy_arn = aws_iam_policy.policy.arn
}

resource "aws_iam_role_policy_attachment" "integration-policy-attach" {
  role = "lw-sechub-integration"
  policy_arn       = aws_iam_policy.policy.arn
}

resource "aws_cloudwatch_event_permission" "LaceworkAccess" {
  principal    = "434813966438"
  statement_id = "LaceworkAccess"
  action = "events:PutEvents"
  event_bus_name = "lw-sechub-integration"

  depends_on = [
    module.eventbridge
  ]
}
resource "lacework_alert_channel_aws_cloudwatch" "all_events_sechub" {
  name            = "lw-sechub-integration"
  event_bus_arn   = module.eventbridge.eventbridge_bus_arn
  group_issues_by = "Resources"
  enabled         = true

  depends_on = [
    aws_cloudwatch_event_permission.LaceworkAccess
  ]
}

resource "lacework_alert_rule" "all_severities" {
  name             = "lw-sechub-integration"
  description      = "Alert rule for Security Hub integration"
  alert_channels   = [lacework_alert_channel_aws_cloudwatch.all_events_sechub.id]
  #resource_groups requires the GUID of the Resource Group
  #use the lacework cli command 'lacework resource-group list' to get the listing of GUIDs
  #best starting point is the 'All Aws Accounts' resource group
  #resource_groups  = [""]
  severities       = ["Critical", "High", "Medium", "Low", "Info"]

  depends_on = [
    lacework_alert_channel_aws_cloudwatch.all_events_sechub
  ]
}

output "eventbridge_bus_arn" {
  description = "The EventBridge Bus ARN"
  value       = module.eventbridge.eventbridge_bus_arn
}
