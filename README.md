# Lacework AWS Security Hub Integration

![Lacework](docs/images/lacework.png)

## Overview
The Lacework integration with AWS Security Hub pushes cloud security events from the Lacework Polygraph Data Platform (PDP) to Security Hub, allowing an 
organization the capability to manage all of their AWS posture and compliance events from a single, consolidated view.

## How It Works
The Lacework AWS Security Hub integration uses multiple self-hosted AWS components that will transform a Lacework 
Cloudwatch/Eventbridge alert into a Security Hub finding. This is done by the following components: Eventbridge, SQS and 
Lambda. 


![Security Hub Integration Flow](docs/images/aws-security-hub.png)

### Event to Finding Flow

1. PDP sends an event to AWS Eventbridge via the Cloudwatch Alert Channel.
2. Eventbridge forwards the event to an SQS queue.
3. The SQS queue triggers the Lambda function.
4. The Lambda function transforms the finding(s) and sends them to Security Hub.

## Prerequisites
You need the following prerequisites to implement the Lacework AWS Security Hub integration.

- AWS Security Hub 
- An AWS Subscription to the Lacework AWS Security Hub product.
- A Lacework Polygraph Data Platform SaaS account. 

## Installing the Lacework AWS Security Hub Integration

### 1. Generate a Lacework API Access Key

1. In your console, go to **Settings > API Keys**.
2. Click on the **Create New** button in the upper right to create a new API key.
3. Provide a **name** and **description** and click Save.
4. Click the download button to download the API keys file.
5. Copy the **keyId** and **secret** from this file.

### 2. Deploy the Lacework AWS Security Hub Integration with Terraform


### 3. Deploy the Lacework AWS Security Hub Integration with CloudFormation

1. Click on the following Launch Stack button to go to your CloudFormation console and launch the AWS Control Integration template.

   [![Launch](https://user-images.githubusercontent.com/6440106/153987820-e1f32423-1e69-416d-8bca-2ee3a1e85df1.png)](https://console.aws.amazon.com/cloudformation/home?#/stacks/create/review?templateURL=https://lacework-alliances.s3.us-west-2.amazonaws.com/lacework-control-tower-cfn/templates/control-tower-integration.template.yml)

   For most deployments, you only need the Basic Configuration parameters. Use the Advanced Configuration for customization.
   ![cloudformation-basic-configuration.png](https://docs.lacework.com/assets/images/cloudformation-basic-configuration-33cb25c21212c3aae060d8f6d064bed8.png)
2. Specify the following Basic Configuration parameters:
    * Enter a **Stack name** for the stack.
    * Enter **Your Lacework URL**.
    * Enter your **Lacework Sub-Account Name** if you are using Lacework Organizations.
    * Enter your **Lacework Access Key ID** and **Secret Key** that you copied from your previous API Keys file.
    * For **Capability Type**, the recommendation is to use **CloudTrail+Config** for the best capabilities.
    * Choose whether you want to **Monitor Existing Accounts**. This will set up monitoring of ACTIVE existing AWS accounts.
    * Enter the name of your **Existing AWS Control Tower CloudTrail Name**.
    * If your CloudTrail S3 logs are encrypted, specify the **KMS Key Identifier ARN**. Ensure that KMS Key Policy is updated to allow access to the Log account cross-account role used by Lacework. Add the following to the Key Policy.
   ```
   "Sid": "Allow Lacework to decrypt logs",
   "Effect": "Allow",
   "Principal": {
   "AWS": [
   "arn:aws:iam::<log-archive-account-id>:role/<lacework-account-name>-laceworkcwssarole"
   ]
   },
   "Action": [
   "kms:Decrypt"
   ],
   "Resource": "*"
   ```
   ![control_tower_kms_key_policy.png](https://docs.lacework.com/assets/images/control_tower_kms_key_policy-ba8f68668bb3cadc57c74364a5a657d3.png)
    * Update the Control Tower **Log Account Name** and **Audit Account Name** if necessary.
3. Click **Next** through to your stack **Review**.
4. Accept the AWS CloudFormation terms and click **Create stack**.

### 4. Manually Deploy the Lacework AWS Security Hub Integration with AWS CLI
Create Lambda Execution Role
```
aws iam create-role --role-name lw-security-hub-ex --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name lw-security-hub-ex --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```
Create the Lambda Function
```
aws lambda create-function --function-name lw-sechub-integration \
--zip-file fileb://function.zip --handler main --runtime go1.x \
--memory-size 128 --package-type Zip --role arn:aws:iam::494165660702:role/lw-security-hub-ex
```
Create the EventBridge
```
aws events create-event-bus --name lw-sechub-integration
aws events put-permission --event-bus-name lw-sechub-integration --action events:PutEvents --principal 434813966438 --statement-id all_account_to_put_events
aws events put-rule --name lw-sechub-incoming --event-bus-name lw-sechub-integration --event-pattern '{"source":["434813966438", "<your account ids>"]}'
aws events put-targets --rule lw-sechub-incoming --event-bus-name lw-sechub-integration --targets "Id"="1","Arn"="<lambda-arn::>"
```

### 5. Validate the Lacework AWS Security Hub Integration

1. Login to your Lacework Cloud Security Platform console.
2. Go to **Settings > Alert Channels**.
3. You should see an alert channel with the name `lw-sechub-integration` and a status of **Success**.
4. If the status shows **Integration Pending** please click the **TEST INTEGRATION** button.

## Remove the Lacework AWS Security Hub Integration

To remove the Lacework AWS Control Tower Integration, simply delete the main stack. All CloudFormation stacksets, stack instances, and Lambda functions will be deleted. **Note:** Lacework will no longer monitor your AWS cloud environment.

## Troubleshooting
The following sections provide guidance for resolving issues with deploying the Lacework AWS Security Hub integration.

### Common Issues

### Events and Logs

#### Lambda Function CloudWatch Logs

The Lambda function that gets deployed will have a cloudwatch log associated with it in the same region it was deployed. You can use this log stream
to check the status of your integration. It will have the following naming format: `/aws/lambda/lw-sechub-integration`

#### Lacework API Access Keys
The AWS Security Hub integration requires Lacework API credentials in order to automate the creation of the Alert Channels and Alert Rules during the deployment.

#### Telemetry


## FAQ

* Do I need to subscribe all my AWS accounts to the Lacework Security Hub product ARN?


* How does the integration handle multiple regions in the same account?


## Reference Documentation