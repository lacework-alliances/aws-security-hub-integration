package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/lacework"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"strings"
	"time"
)

type Compliance struct {
	Event  types.LaceworkEvent
	config types.Config
}

func (c *Compliance) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(c.Event.Detail.Summary)
	// grab the config struct from the context
	c.config = ctx.Value("config").(types.Config)
	// determine what cloud provider
	cloud := getComplianceCloud(c.Event.Detail.Summary)
	// loop through the Lacework event data
	for _, e := range c.Event.Detail.EventDetails.Data {
		var comp securityhub.Compliance
		var reason string

		switch cloud {
		case "aws":
			// create the compliance
			if len(e.EntityMap.Violationreason) > 0 {
				violation := e.EntityMap.Violationreason[0]
				if len(violation.Reason) >= 64 {
					reason = violation.Reason[:64]
				} else {
					reason = violation.Reason
				}
			} else {
				reason = e.EventType
			}

			comp = securityhub.Compliance{
				RelatedRequirements: aws.StringSlice([]string{reason}),
				Status:              aws.String(securityhub.ComplianceStatusFailed),
			}
		default:
			// create the compliance
			if len(e.EntityMap.Violationreason) > 0 {
				violation := e.EntityMap.Violationreason[0]
				if len(violation.Reason) >= 64 {
					reason = violation.Reason[:64]
				} else {
					reason = violation.Reason
				}
			} else {
				reason = e.EventType
			}

			comp = securityhub.Compliance{
				RelatedRequirements: aws.StringSlice([]string{reason}),
				Status:              aws.String(securityhub.ComplianceStatusFailed),
			}
		}
		finding := securityhub.AwsSecurityFinding{
			//AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, c.Event.Detail.Summary)),
			AwsAccountId:  aws.String(c.config.DefaultAccount),
			GeneratorId:   aws.String(cloud),
			Region:        aws.String(c.Event.Region),
			Compliance:    &comp,
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(c.Event.ID),
			ProductArn:    getProductArn(c.config.Region),
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
			if len(data.EntityMap.NewViolation) > 0 {
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
						} else if strings.Contains(v.Reason, "S3") || strings.Contains(v.Reason, "LoggingNotEnabled") {
							res.Type = aws.String("AwsS3Bucket")
						} else if strings.Contains(v.Reason, "ACL") {
							res.Type = aws.String("AwsEc2NetworkAcl")
						} else if strings.Contains(strings.ToLower(v.Reason), "iam") || strings.Contains(v.Reason, "AccessKey") ||
							strings.Contains(v.Reason, "AWS_CIS_1_16") || strings.Contains(v.Reason, "MFANotActive") || strings.Contains(v.Reason, "AWS_CIS_1_23") ||
							strings.Contains(v.Reason, "PasswordUsed") {
							res.Type = aws.String("AwsIamUser")
						} else if strings.Contains(v.Reason, "LW_AWS_NETWORKING_47") {
							res.Type = aws.String("AwsEc2Instance")
						} else if strings.Contains(strings.ToLower(v.Reason), "flowlogging") || strings.Contains(v.Reason, "VPC") {
							res.Type = aws.String("AwsEc2Vpc")
						} else if strings.Contains(v.Reason, "AWS_CIS_2_8") || strings.Contains(v.Reason, "KMSKey") { // KMS
							res.Type = aws.String("AwsKmsKey")
						} else if strings.Contains(v.Reason, "AWS_CIS_2_7") {
							res.Type = aws.String("AwsCloudTrailTrail")
						} else if strings.Contains(v.Reason, "Ec2Instance") {
							res.Type = aws.String("AwsEc2Instance")
						} else if strings.Contains(v.Reason, "LogFileValidation") || strings.Contains(v.Reason, "CloudTrailLogsNotEncrypted") ||
							strings.Contains(v.Reason, "CloudWatchLog") {
							res.Type = aws.String("AwsCloudTrailTrail")
						} else if strings.Contains(v.Reason, "RDSDatabase") {
							res.Type = aws.String("AwsRdsDbInstance")
						} else if strings.Contains(v.Reason, "ElasticSearch") {
							res.Type = aws.String("AwsElasticSearchDomain")
						} else if strings.Contains(v.Reason, "NoLogFilterAndAlarm") || strings.Contains(v.Reason, "RegionInAccountWithoutAccess") ||
							strings.Contains(v.Reason, "RootAccountMFANotEnabled") || strings.Contains(v.Reason, "PasswordPolicyHasWeakMinimumLength") {
							res.Type = aws.String("Other")
						} else {
							res.Type = aws.String("Other")
							t, _ := json.Marshal(data)
							if c.config.Telemetry {
								lacework.SendHoneycombEvent(c.config.Instance, "compliance_type_not_found", "", c.config.Version, string(t), "mapCompliance", c.config.HoneyKey, c.config.HoneyDataset)
							}
						}
						details := c.mapRecID()
						res.Details = &securityhub.ResourceDetails{
							Other: details,
						}
						resourceList = append(resourceList, res)
					}
				}
			} else {
				res := &securityhub.Resource{
					Id:           aws.String(c.Event.Detail.EventType),
					Partition:    aws.String("aws"),
					ResourceRole: aws.String("Target"),
					Type:         aws.String("Other"),
				}

				resourceList = append(resourceList, res)
			}
		}
	} else if strings.Contains(strings.ToLower(c.Event.Detail.Summary), "gcp") {
		for _, data := range c.Event.Detail.EventDetails.Data {
			if len(data.EntityMap.NewViolation) > 0 {
				for index, v := range data.EntityMap.NewViolation {
					if v.RecID != "" {
						res := &securityhub.Resource{
							Id:           aws.String(v.Resource),
							ResourceRole: aws.String("Target"),
						}

						if len(data.EntityMap.Resource) > index {
							res.Id = aws.String(data.EntityMap.Resource[index].Value)
							res.Type = aws.String(data.EntityMap.Resource[index].Name)
						}

						resourceList = append(resourceList, res)
					}
				}
			} else {
				res := &securityhub.Resource{
					Id:           aws.String(c.Event.Detail.EventType),
					ResourceRole: aws.String("Target"),
					Type:         aws.String("Other"),
				}
				resourceList = append(resourceList, res)
			}
		}
	}
	return resourceList
}

func (c *Compliance) getTypes() []*string {
	var reason string
	tList := []*string{aws.String(AWSCompliance)}
	if len(c.Event.Detail.EventDetails.Data[0].EntityMap.Violationreason) > 0 {
		violation := c.Event.Detail.EventDetails.Data[0].EntityMap.Violationreason[0]
		if len(violation.Reason) >= 64 {
			reason = violation.Reason[:64]
		} else {
			reason = violation.Reason
		}
	} else {
		reason = c.Event.Detail.EventType
	}

	t := fmt.Sprintf("Software and Configuration Checks/Lacework/%s", reason)
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
