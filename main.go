package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
)

const (
	ARN    = "arn:aws:securityhub:us-east-2:950194951070:product/950194951070/default"
	SCHEMA = "2018-10-08"
)

func main() {
	lambda.Start(handler)
}

func handler(ctx context.Context, e events.CloudWatchEvent) {
	var event LaceworkEvent
	batch := securityhub.BatchImportFindingsInput{}
	input, err := json.Marshal(&e)
	if err != nil {
		fmt.Println("error while unmarshal of event: ", err)
	}
	err = json.Unmarshal(input, &event)
	if err != nil {
		fmt.Println("error while unmarshal of input to event: ", err)
	}
	fmt.Printf("%s\n\n", input)
	findings := eventToASFF(event)
	batch.Findings = findings
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println("error while creating aws session: ", err)
	}
	data, err := json.Marshal(batch)
	if err != nil {
		fmt.Println("error while marshaling batch: ", err)
	}
	fmt.Printf("%s\n\n", data)
	svc := securityhub.New(sess)
	output, err := svc.BatchImportFindings(&batch)
	if err != nil {
		fmt.Println("error while importing batch: ", err)
	}
	fmt.Println(output.String())
}
