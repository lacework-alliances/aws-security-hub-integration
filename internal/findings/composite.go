package findings

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"time"
)

type Composite struct {
	Event  types.LaceworkEvent
	config types.Config
}

func (c Composite) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(c.Event.Detail.Summary)
	// grab the config struct from the context
	c.config = ctx.Value("config").(types.Config)
	for _, e := range c.Event.Detail.EventDetails.Data {
		generatorID := c.Event.Detail.EventCategory
		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(c.config.DefaultAccount),
			GeneratorId:   aws.String(generatorID),
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(c.Event.ID),
			ProductArn:    getProductArn(c.config.Region),
			Types:         getTypes(c.config.EventMap, c.Event.Detail.EventType),
			CreatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			Severity:      getSeverity(c.Event.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(c.Event.Detail.Summary),
			SourceUrl:     aws.String(c.Event.Detail.Link),
			Resources:     c.resource(e),
		}
		fs = append(fs, &finding)
	}
	return fs
}

func (c Composite) resource(data types.Data) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	var res securityhub.Resource
	// create resource of supporting facts
	res = securityhub.Resource{
		Details: &securityhub.ResourceDetails{},
		Type:    aws.String("Other"),
	}
	res.Id, res.Details.Other = c.otherDetails(data)
	resourceList = append(resourceList, &res)
	return resourceList
}

func (c Composite) otherDetails(data types.Data) (*string, map[string]*string) {
	otherMap := make(map[string]*string)
	var id *string

	d := fmt.Sprintf("%s-%s", data.EventModel, data.EventType)
	if len(d) > 64 {
		id = aws.String(d[:64])
	} else {
		id = aws.String(d)
	}
	// Supporting facts are used to describe alert rather than specific resources involved
	// AWS requires that values in OtherDetails are less than 1024 characters
	for i, fact := range c.Event.Detail.SupportingFacts {
		text := fact.Text
		if len(text) > 1024 {
			text = fact.Text[:1024]
		}
		key := fmt.Sprintf("Fact-%d", i)
		otherMap[key] = aws.String(text)
	}

	return id, otherMap
}
