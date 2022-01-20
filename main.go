package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/findings"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
)

func main() {
	eventMap := findings.InitMap()
	ctx := context.WithValue(context.Background(), "eventMap", eventMap)
	lambda.StartWithContext(ctx, handler)
}

func handler(ctx context.Context, e events.SQSEvent) {
	var event types.LaceworkEvent
	batch := securityhub.BatchImportFindingsInput{}
	for _, message := range e.Records {
		fmt.Printf("%s \n", message.Body)

		err := json.Unmarshal([]byte(message.Body), &event)
		if err != nil {
			fmt.Printf("error while unmarshaling event message: %v\n", err)
		}

		f := findings.EventToASFF(ctx, event)
		batch.Findings = append(batch.Findings, f...)
	}

	sess, err := session.NewSession()
	if err != nil {
		fmt.Println("error while creating aws session: ", err)
	}
	svc := securityhub.New(sess)
	fmt.Printf("Sending %d findings to Security Hub\n", len(batch.Findings))
	output, err := svc.BatchImportFindings(&batch)
	if err != nil {
		fmt.Println("error while importing batch: ", err)
	}
	fmt.Println(output.String())
}
