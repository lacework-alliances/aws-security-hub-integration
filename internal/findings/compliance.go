package findings

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"strings"
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

		switch cloud {
		case "aws":
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

		default:
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
		}

		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, c.Event.Detail.Summary)),
			GeneratorId:   aws.String(cloud),
			Compliance:    &comp,
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(c.Event.ID),
			ProductArn:    getProductArn(cfg.Region),
			Types:         c.getTypes(),
			CreatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(c.Event.Time.Format(time.RFC3339)),
			Severity:      getSeverity(c.Event.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(c.Event.Detail.Summary),
			SourceUrl:     aws.String(c.Event.Detail.Link),
			Resources:     c.mapCompliance(ctx),
		}
		fs = append(fs, &finding)
	}
	return fs
}

func (c *Compliance) mapCompliance(ctx context.Context) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	if strings.Contains(strings.ToLower(c.Event.Detail.Summary), "aws") {
		for _, data := range c.Event.Detail.EventDetails.Data {
			for _, v := range data.EntityMap.NewViolation {
				if v.RecID != "" {
					res := &securityhub.Resource{
						Id:           aws.String(v.Resource),
						Partition:    aws.String("aws"),
						ResourceRole: aws.String("Target"),
					}
					// get the type
					if strings.Contains(v.Reason, "SecurityGroup") || strings.Contains(strings.ToLower(v.Resource), "security-group") {
						res.Type = aws.String("AwsEc2SecurityGroup")
					} else if strings.Contains(v.Reason, "S3") {
						res.Type = aws.String("AwsS3Bucket")
					} else if strings.Contains(v.Reason, "ACL") {
						res.Type = aws.String("AwsEc2NetworkAcl")
					} else if strings.Contains(strings.ToLower(v.Reason), "iam") {
						res.Type = aws.String("AwsIamUser")
					}
					details := c.mapRecID()
					res.Details = &securityhub.ResourceDetails{
						Other: details,
					}
					resourceList = append(resourceList, res)
				}
			}
		}
	}
	return resourceList
}

func (c *Compliance) getTypes() []*string {
	tList := []*string{aws.String(AWSCompliance)}
	t := fmt.Sprintf("Software and Configuration Checks/Lacework/%s", c.Event.Detail.EventDetails.Data[0].EntityMap.Violationreason[0].Reason)
	tList = append(tList, aws.String(t))
	return tList
}

func (c *Compliance) mapRecID() map[string]*string {
	detail := make(map[string]*string)
	detail["REC_ID"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].RecID)
	detail["EVAL_TYPE"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].EvalType)
	detail["EVAL_GUID"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].EvalGUID)
	detail["ACCOUNT_ID"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].AccountID)
	detail["ACCOUNT_ALIAS"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].AccountAlias)
	detail["TITLE"] = aws.String(c.Event.Detail.EventDetails.Data[0].EntityMap.Recid[0].Title)
	detail["EVENT_MODEL"] = aws.String(c.Event.Detail.EventDetails.Data[0].EventModel)
	detail["EVENT_TYPE"] = aws.String(c.Event.Detail.EventDetails.Data[0].EventType)
	return detail
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
