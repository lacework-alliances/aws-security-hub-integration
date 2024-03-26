package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-lambda-go/events"
	lam "github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/findings"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/lacework"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"os"
)

const (
	BUILD    = "$BUILD"
	HONEYKEY = "$HONEYKEY"
	DATASET  = "$DATASET"
)

var (
	defaultAccount string
	instance       string
	version        = BUILD
	telemetry      bool
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
	if disabled := os.Getenv("LW_DISABLE_TELEMETRY"); disabled != "" {
		telemetry = false
	} else {
		telemetry = true
	}
}

func main() {
	cfg := types.Config{
		DefaultAccount: defaultAccount,
		Instance:       instance,
		EventMap:       findings.InitMap(),
		Region:         os.Getenv("AWS_REGION"),
		Telemetry:      telemetry,
		Version:        version,
		HoneyKey:       HONEYKEY,
		HoneyDataset:   DATASET,
	}
	ctx := context.WithValue(context.Background(), "config", cfg)
	lam.StartWithContext(ctx, handler)
}

func handler(ctx context.Context, e events.SQSEvent) {
	var event types.LaceworkEvent
	batch := securityhub.BatchImportFindingsInput{}
	for _, message := range e.Records {
		fmt.Printf("%s \n", message.Body)
		body := bytes.TrimPrefix([]byte(message.Body), []byte("\xef\xbb\xbf"))
		err := json.Unmarshal(body, &event)
		if err != nil {
			if telemetry {
				lacework.SendHoneycombEvent(instance, "error", "", version, err.Error(), "record", HONEYKEY, DATASET)
			}
			fmt.Printf("error while unmarshaling event message: %v\n", err)
		}

		f := findings.EventToASFF(ctx, event)
		if len(f) > 0 {
			batch.Findings = append(batch.Findings, f...)
			sess, err := session.NewSession(&aws.Config{
				CredentialsChainVerboseErrors: aws.Bool(true),
			})
			if err != nil {
				if telemetry {
					lacework.SendHoneycombEvent(instance, "error", "", version, err.Error(), "aws_session", HONEYKEY, DATASET)
				}
				fmt.Println("error while creating aws session: ", err)
			}
			svc := securityhub.New(sess)
			//fmt.Printf("Sending %d finding(s) to Security Hub\n", len(batch.Findings))
			output, err := svc.BatchImportFindings(&batch)
			if err != nil {
				if telemetry {
					lacework.SendHoneycombEvent(instance, "error", "", version, err.Error(), "BatchImportFindings", HONEYKEY, DATASET)
				}
				fmt.Println("error while importing batch: ", err)
			}
			if output != nil && *output.FailedCount > int64(0) {
				fmt.Printf("Failed Account: %s - Failed Region: %s\n", event.Account, event.Region)
				fmt.Println(output.String())
			}
		}
	}
}
