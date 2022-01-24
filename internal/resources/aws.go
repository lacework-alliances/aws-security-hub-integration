package resources

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"os"
	"regexp"
	"strings"
)

var defaultAccount = os.Getenv("DEFAULT_AWS_ACCOUNT")

func MapDefault(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EventActor)
	return res
}

func MapAwsCompliance(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.NewViolation[0].Resource)
	res.Partition = aws.String("aws")
	strSplit := strings.Split(d.EntityMap.NewViolation[0].Resource, ":")
	res.Region = aws.String(strSplit[2])
	for i, v := range d.EntityMap.Resource {
		if i < 50 {
			if v.Value != "" {
				res.Details.Other[v.Name] = aws.String(formatOnLength(v.Value, 1024))
			}
		}
	}
	return res
}

func MapAwsApiTracker(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Details = &securityhub.ResourceDetails{}
	res.Details.Other = make(map[string]*string)
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EntityMap.CtUser[0].Username)
	res.Partition = aws.String("aws")
	res.Region = aws.String(d.EntityMap.Region[0].Region)
	for i, o := range d.EntityMap.API {
		if i < 50 {
			if o.Service != "" || o.API != "" {
				res.Details.Other[o.API] = aws.String(formatOnLength(o.Service, 1024))
			}
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
	for i, o := range d.EntityMap.Resource {
		if i < 50 {
			res.Details.Other[o.Name] = aws.String(formatOnLength(o.Value, 1024))
		}
	}
	for i, o := range d.EntityMap.RulesTriggered {
		if i < 50 {
			res.Details.Other[o.RuleID] = aws.String(formatOnLength(o.RuleTitle, 1024))
		}
	}
	return res
}

func GetIncomingAccount(data string) string {
	fmt.Printf("GetIncomingAccount Data: %s\n", data)
	re := regexp.MustCompile("\\d{12}")
	match := re.FindStringSubmatch(data)
	if len(match) == 0 || match[0] == "" {
		return defaultAccount
	}
	return match[0]
}

func formatOnLength(input string, length int) string {
	var output string
	l := len(input)
	if l < length {
		output = input
	} else {
		output = input[:length]
	}
	return output
}
