package main

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"time"
)

func eventToASFF(le LaceworkEvent) []*securityhub.AwsSecurityFinding {
	fs := []*securityhub.AwsSecurityFinding{}

	finding := securityhub.AwsSecurityFinding{
		AwsAccountId:  aws.String(le.Account),
		GeneratorId:   aws.String(le.Detail.EventCategory),
		SchemaVersion: aws.String(SCHEMA),
		Id:            aws.String(le.ID),
		ProductArn:    aws.String(ARN),
		Types:         getTypes(le.Detail.EventType),
		CreatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		UpdatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		Severity:      getSeverity(le.Detail.Severity),
		Title:         aws.String(le.Detail.Summary),
		Description:   aws.String(le.Detail.Summary),
		SourceUrl:     aws.String(le.Detail.Link),
		Resources:     mapToResource(le.Detail.EventDetails.Data),
	}
	fs = append(fs, &finding)

	return fs
}

func mapToResource(data []Data) []*securityhub.Resource {
	var resources []*securityhub.Resource
	// loop through data slice
	for _, d := range data {
		var res securityhub.Resource
		res.Details = &securityhub.ResourceDetails{}
		res.Details.Other = make(map[string]*string)
		if d.EventModel == "AwsApiTracker" {
			res.Type = aws.String("Other")
			res.Id = aws.String(d.EntityMap.CtUser[0].Username)
			res.Partition = aws.String("aws")
			res.Region = aws.String(d.EntityMap.Region[0].Region)
			for _, o := range d.EntityMap.API {
				if o.Service != "" || o.API != "" {
					res.Details.Other[o.API] = aws.String(o.Service)
				}
			}
		}
		resources = append(resources, &res)
	}
	return resources
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

func getTypes(t string) []*string {
	var tList []*string
	switch t {
	case "NewService":
		tList = append(tList, aws.String("Unusual Behavior/Application/CloudTrail"))
	case "UnauthorizedAPICall":
		tList = append(tList, aws.String("TTPs/Credential Access/Unauthorized"))
	}

	return tList
}
