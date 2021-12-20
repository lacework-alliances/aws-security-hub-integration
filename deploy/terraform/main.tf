terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.70.0"
    }
  }
}

locals {
  lambda_handler = "main"
  name = "lw-sechub-integration"
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


