package findings

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"time"
)

type Compliance struct {
	Event types.LaceworkEvent
}

func (c *Compliance) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(c.Event.Detail.Summary)
	// grab the config struct from the context
	cfg := ctx.Value("config").(types.Config)
	// determine what cloud provider
	cloud := getComplianceCloud(c.Event.Detail.Summary)
	// loop through the Lacework event data
	for _, e := range c.Event.Detail.EventDetails.Data {
		var comp securityhub.Compliance
		var reason string
		// create the compliance
		violation := e.EntityMap.Violationreason[0]

		if len(violation.Reason) >= 64 {
			reason = violation.Reason[:64]
		} else {
			reason = violation.Reason
		}
		comp = securityhub.Compliance{

			RelatedRequirements: aws.StringSlice([]string{reason}),
			Status:              aws.String(securityhub.ComplianceStatusFailed),
		}
		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, c.Event.Detail.Summary)),
			GeneratorId:   aws.String(cloud),
			Compliance:    &comp,
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(c.Event.ID),
			ProductArn:    getProductArn(cfg.Region),
			Types:         getTypes(cfg.EventMap, c.Event.Detail.EventType),
			CreatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			Severity:      getSeverity(c.Event.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(c.Event.Detail.Summary),
			SourceUrl:     aws.String(c.Event.Detail.Link),
			Resources:     mapToResource(c.Event.Detail.EventDetails.Data),
		}
		fs = append(fs, &finding)
	}

	return fs
}
