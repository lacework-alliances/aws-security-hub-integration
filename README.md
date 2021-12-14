# aws-security-hub-integration
Send Lacework events to AWS Security Hub using the 
Lacework Cloudwatch alert channel, EventBridge and Lambda. 

### Permissions Required


### Terraform

### Cloudformation


### Manual Setup
####Build from source
```
git clone https://github.com/lacework-dev/aws-security-hub-integration.git
GOOS=linux CGO_ENABLED=0 go build -o main *.go
zip function.zip main
```

####Use AWS cli to configure the Lambda function
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