package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/findings"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"os"
)

var (
	defaultAccount string
	instance       string
)

func init() {
	defaultAccount = os.Getenv("DEFAULT_AWS_ACCOUNT")
	if defaultAccount == "" {
		fmt.Println("Please set the environment variable DEFAULT_AWS_ACCOUNT")
	}
	instance = os.Getenv("LACEWORK_INSTANCE")
	if instance == "" {
		fmt.Println("Please set the environment variable LACEWORK_INSTANCE")
	}
}

func main() {
	cfg := types.Config{
		DefaultAccount: defaultAccount,
		Instance:       instance,
		EventMap:       findings.InitMap(),
	}
	ctx := context.WithValue(context.Background(), "config", cfg)
	lam.StartWithContext(ctx, handler)
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
	fmt.Printf("Sending %d finding(s) to Security Hub\n", len(batch.Findings))
	output, err := svc.BatchImportFindings(&batch)
	if err != nil {
		fmt.Println("error while importing batch: ", err)
	}
	if *output.FailedCount > int64(0) {
		fmt.Println(output.String())
	}
}
