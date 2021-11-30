package resources

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-dev/aws-security-hub-integration/pkg/types"
)

func MapAwsApiTracker(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Details.Other = make(map[string]*string)
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.CtUser[0].Username)
	res.Partition = aws.String("aws")
	res.Region = aws.String(d.EntityMap.Region[0].Region)
	for _, o := range d.EntityMap.API {
		if o.Service != "" || o.API != "" {
			res.Details.Other[o.API] = aws.String(o.Service)
		}
	}
	return res
}

func MapCloudTrailCep(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Details.Other = make(map[string]*string)
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.CtUser[0].Username)
	res.Partition = aws.String("aws")
	res.Region = aws.String(d.EntityMap.Region[0].Region)
	for _, o := range d.EntityMap.Resource {
		res.Details.Other[o.Name] = aws.String(o.Value)
	}
	for _, o := range d.EntityMap.RulesTriggered {
		res.Details.Other[o.RuleID] = aws.String(o.RuleTitle)
	}
	return res
}
