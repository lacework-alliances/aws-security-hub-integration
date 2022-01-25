package findings

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"time"
)

type Compliance types.LaceworkEvent

func (c *Compliance) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(c.Detail.Summary)
	// grab the config struct from the context
	cfg := ctx.Value("config").(types.Config)
	// determine what cloud provider
	cloud := getComplianceCloud(c.Detail.Summary)
	// loop through the Lacework event data
	for _, e := range c.Detail.EventDetails.Data {
		// create the compliance
		violation := e.EntityMap.Violationreason[0]
		recId := e.EntityMap.Recid[0]
		comp := securityhub.Compliance{
			RelatedRequirements: aws.StringSlice([]string{violation.Reason}),
			Status:              aws.String(securityhub.ComplianceStatusFailed),
			StatusReasons: []*securityhub.StatusReason{
				{
					Description: aws.String(recId.Title),
					ReasonCode:  aws.String(recId.Title),
				},
			},
		}
		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, c.Detail.Summary)),
			GeneratorId:   aws.String(cloud),
			Compliance:    &comp,
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(c.ID),
			ProductArn:    aws.String(ARN),
			Types:         getTypes(cfg.EventMap, c.Detail.EventType),
			CreatedAt:     aws.String(c.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(c.Time.Format(time.RFC3339)),
			Severity:      getSeverity(c.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(c.Detail.Summary),
			SourceUrl:     aws.String(c.Detail.Link),
			Resources:     mapToResource(c.Detail.EventDetails.Data),
		}
		fs = append(fs, &finding)
	}

	return fs
}
