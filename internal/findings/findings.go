package findings

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"regexp"
	"strings"
	"time"
)

const (
	TtpInitialAccess      = "TTPs/Initial Access"
	TtpDiscovery          = "TTPs/Discovery"
	NewViolation          = "Industry and Regulatory Standards"
	TtpPrivilege          = "TTPs/Privilege Escalation"
	TtpCredential         = "TTPs/Credential Access"
	TtpCollection         = "TTPs/Collection"
	TtpError              = "TTPs/Error"
	UnusualIP             = "Unusual Behaviors/IP address"
	UnusualNetwork        = "Unusual Behaviors/Network Flow"
	UnusualApplication    = "Unusual Behaviors/Application"
	SensitiveSecurity     = "Sensitive Data Identifications/Security"
	SoftwareVulnerability = "Software and Configuration Checks/Vulnerabilities"
	SoftwareCVE           = "Software and Configuration Checks/Vulnerabilities/CVE"
	SoftwarePolicy        = "Software and Configuration Checks/Policy"
	AWSCompliance         = "Software and Configuration Checks/Industry and Regulatory Standards/CIS AWS Foundations Benchmark"
	TtpDefault            = "TTPs/Default"

	ArnFormat = "arn:aws:securityhub:%s::product/lacework/lacework"

	SCHEMA = "2018-10-08"
)

func EventToASFF(ctx context.Context, le types.LaceworkEvent) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	var category string
	// get the category to determine finding
	category = le.Detail.EventCategory
	switch category {
	case "App":
		fmt.Println("source is App")
		app := App{Event: le}
		findings := app.Findings(ctx)
		fs = append(fs, findings...)
	case "Compliance":
		fmt.Println("source is Compliance")
		comp := Compliance{Event: le}
		findings := comp.Findings(ctx)
		fs = append(fs, findings...)
	case "Aws":
		fmt.Println("source is AWS")
		a := Aws{Event: le}
		findings := a.Findings(ctx)
		fs = append(fs, findings...)
	case "GcpAuditTrail":
		finding := mapDefault(ctx, le)
		fs = append(fs, &finding)
	case "User":
		finding := mapDefault(ctx, le)
		fs = append(fs, &finding)
	case "TestEvent":
		return fs
	default:
		fmt.Printf("Unknown category: %s\n", category)
		finding := mapDefault(ctx, le)
		fs = append(fs, &finding)
	}

	return fs
}

func getProductArn(region string) *string {
	arn := fmt.Sprintf(ArnFormat, region)
	return aws.String(arn)
}

func mapDefault(ctx context.Context, le types.LaceworkEvent) securityhub.AwsSecurityFinding {
	var desc string
	cfg := ctx.Value("config").(types.Config)
	if len(le.Detail.Summary) >= 255 {
		desc = le.Detail.Summary[:255]
	} else {
		desc = le.Detail.Summary
	}
	finding := securityhub.AwsSecurityFinding{
		AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, le.Detail.Summary)),
		GeneratorId:   aws.String(le.Detail.EventCategory),
		SchemaVersion: aws.String(SCHEMA),
		Id:            aws.String(le.ID),
		ProductArn:    getProductArn(cfg.Region),
		Types:         getTypes(cfg.EventMap, le.Detail.EventType),
		CreatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		UpdatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		Severity:      getSeverity(le.Detail.Severity),
		Title:         aws.String(desc),
		Description:   aws.String(le.Detail.Summary),
		SourceUrl:     aws.String(le.Detail.Link),
		Resources:     mapToResource(le.Detail.EventDetails.Data),
	}
	return finding
}

func mapToResource(data []types.Data) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	// loop through data slice
	for _, d := range data {
		var res securityhub.Resource
		switch d.EventModel {
		case "AwsApiTracker":
			res = MapAwsApiTracker(d, res)
		case "CloudTrailCep":
			res = MapCloudTrailCep(d, res)
		case "NewViolation", "ComplianceChanged":
			res = MapAwsCompliance(d, res)
		default:
			res = MapDefault(d, res)
		}
		resourceList = append(resourceList, &res)
	}
	return resourceList
}

func getSeverity(s int) *securityhub.Severity {
	var severity securityhub.Severity
	switch s {
	case 1:
		severity.Label = aws.String(securityhub.SeverityLabelCritical)
	case 2:
		severity.Label = aws.String(securityhub.SeverityLabelHigh)
	case 3:
		severity.Label = aws.String(securityhub.SeverityLabelMedium)
	case 4:
		severity.Label = aws.String(securityhub.SeverityLabelLow)
	case 5:
		severity.Label = aws.String(securityhub.SeverityLabelInformational)
	}
	return &severity
}

func getTypes(m map[string]string, t string) []*string {
	var tList []*string

	tList = append(tList, aws.String(m[t]))

	return tList
}

func getAwsAccount(defaultAccount, data string) string {
	re := regexp.MustCompile("\\d{12}")
	match := re.FindStringSubmatch(data)
	if len(match) == 0 || match[0] == "" {
		return defaultAccount
	}
	return match[0]
}

func MapDefault(d types.Data, res securityhub.Resource) securityhub.Resource {
	res.Type = aws.String("Other")
	res.Id = aws.String(d.EventActor)
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

func getDescription(input string) string {
	if len(input) >= 255 {
		return input[:255]
	} else {
		return input
	}
}

// getComplianceCloud returns the public cloud of the event (aws, gcp, azure) based on the event summary
func getComplianceCloud(input string) string {
	var cloud string
	if strings.Contains(strings.ToLower(input), "aws") {
		cloud = "aws"
	} else if strings.Contains(strings.ToLower(input), "gcp") {
		cloud = "gcp"
	} else if strings.Contains(strings.ToLower(input), "azure") {
		cloud = "azure"
	}
	return cloud
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

func lastString(ss []string) string {
	return ss[len(ss)-1]
}

func isActive(value int) string {
	active := "false"
	if value > 0 {
		active = "true"
	}
	return active
}
