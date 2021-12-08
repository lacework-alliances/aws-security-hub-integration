package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-dev/aws-security-hub-integration/internal/findings"
	"github.com/lacework-dev/aws-security-hub-integration/pkg/types"
)

func main() {
	eventMap := findings.InitMap()
	ctx := context.WithValue(context.Background(), "eventMap", eventMap)
	lambda.StartWithContext(ctx, handler)
}

func handler(ctx context.Context, e events.CloudWatchEvent) {
	var event types.LaceworkEvent
	batch := securityhub.BatchImportFindingsInput{}
	input, err := json.Marshal(&e)
	if err != nil {
		fmt.Println("error while unmarshal of event: ", err)
	}
	err = json.Unmarshal(input, &event)
	if err != nil {
		fmt.Println("error while unmarshal of input to event: ", err)
	}
	f := findings.EventToASFF(ctx, event)
	batch.Findings = f
	sess, err := session.NewSession()
	if err != nil {
		fmt.Println("error while creating aws session: ", err)
	}
	svc := securityhub.New(sess)
	output, err := svc.BatchImportFindings(&batch)
	if err != nil {
		fmt.Println("error while importing batch: ", err)
	}
	fmt.Println(output.String())
}
