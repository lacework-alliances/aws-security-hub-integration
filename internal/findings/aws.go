package findings

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/lacework"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"strconv"
	"time"
)

type Aws struct {
	Event  types.LaceworkEvent
	config types.Config
}

func (a Aws) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(a.Event.Detail.Summary)
	// grab the config struct from the context
	a.config = ctx.Value("config").(types.Config)
	for _, e := range a.Event.Detail.EventDetails.Data {
		generatorID := a.Event.Detail.EventCategory
		finding := securityhub.AwsSecurityFinding{
			//AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, a.Event.Detail.Summary)),
			AwsAccountId:  aws.String(a.config.DefaultAccount),
			GeneratorId:   aws.String(generatorID),
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(a.Event.ID),
			ProductArn:    getProductArn(a.config.Region),
			Types:         getTypes(a.config.EventMap, a.Event.Detail.EventType),
			CreatedAt:     aws.String(a.Event.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(a.Event.Time.Format(time.RFC3339)),
			Severity:      getSeverity(a.Event.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(a.Event.Detail.Summary),
			SourceUrl:     aws.String(a.Event.Detail.Link),
			Resources:     a.resource(e),
		}
		fs = append(fs, &finding)
	}
	return fs
}

func (a Aws) resource(data types.Data) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	var res securityhub.Resource
	// create the basic resource
	switch data.EventType {
	case "NewUser", "NewAccount":
		res = securityhub.Resource{
			ResourceRole: aws.String("Target"),
			Type:         aws.String("AwsIamUser"),
			Partition:    aws.String("aws"),
			Id:           aws.String(data.EntityMap.CtUser[0].PrincipalID),
			Region:       aws.String(data.EntityMap.Region[0].Region),
			Details: &securityhub.ResourceDetails{AwsIamUser: &securityhub.AwsIamUserDetails{
				UserId:   aws.String(data.EntityMap.CtUser[0].PrincipalID),
				UserName: aws.String(data.EntityMap.CtUser[0].Username),
			}},
		}
	default:
		res = securityhub.Resource{
			Details: &securityhub.ResourceDetails{},
			Type:    aws.String("Other"),
		}
		res.Id, res.Details.Other = a.otherDetails(data)
	}

	resourceList = append(resourceList, &res)
	return resourceList
}

func (a Aws) otherDetails(data types.Data) (*string, map[string]*string) {
	otherMap := make(map[string]*string)
	var id *string
	// Check the EVENT_TYPE and make decisions

	switch data.EventType {
	case "UserUsedServiceInRegion", "ServiceAccessedInRegion", "NewService", "NewCustomerMasterKey", "CustomerMasterKeyScheduledForDeletion",
		"UsageOfRootAccount", "FailedConsoleLogin", "CLoudTrailDefaultAlert":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].Username[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].Username)
		}

		ipMap := a.ipAddress(data.EntityMap.SourceIpAddress)
		for k, v := range ipMap {
			otherMap[k] = v
		}
		apiMap := a.API(data.EntityMap.API)
		for k, v := range apiMap {
			otherMap[k] = v
		}
	case "UnauthorizedAPICall", "IAMPolicyChanged", "NetworkGatewayChange", "RouteTableChange", "SecurityGroupChange":
		rule := fmt.Sprintf("%s(s)-%s", data.EntityMap.RulesTriggered[0].RuleTitle, data.EntityMap.RulesTriggered[0].RuleID)
		if len(rule) > 64 {
			id = aws.String(rule[:64])
		} else {
			id = aws.String(rule)
		}

		ruleMap := a.rule(data.EntityMap.RulesTriggered)
		for k, v := range ruleMap {
			otherMap[k] = v
		}
	case "SuccessfulConsoleLoginWithoutMFA", "ServiceCalledApi", "S3BucketPolicyChanged", "S3BucketACLChanged",
		"LoginFromSourceUsingCalltype", "ApiFailedWithError", "AwsAccountFailedApi", "NewCustomerMasterKeyAlias",
		"NewGrantAddedToCustomerMasterKey":
		rule := fmt.Sprintf("%s-%s", data.EntityMap.CtUser[0].PrincipalID, data.EntityMap.CtUser[0].Username)
		if len(rule) > 64 {
			id = aws.String(rule[:64])
		} else {
			id = aws.String(rule)
		}
		ctUserMap := a.ctUser(data.EntityMap.CtUser)
		for k, v := range ctUserMap {
			otherMap[k] = v
		}
	case "NewUser", "VPCChange":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].Username[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].Username)
		}

	case "IAMAccessKeyChanged":
		if len(data.EntityMap.CtUser[0].PrincipalID) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].PrincipalID[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].PrincipalID)
		}
	case "NewRegion", "NewVPC":
		if len(data.EntityMap.Region[0].Region) > 64 {
			id = aws.String(data.EntityMap.Region[0].Region[:64])
		} else {
			id = aws.String(data.EntityMap.Region[0].Region)
		}

	case "NewS3Bucket", "S3BucketDeleted":
		for _, resource := range data.EntityMap.Resource {
			if resource.Name == "bucketName" {
				if len(resource.Value) > 64 {
					id = aws.String(resource.Value[:64])
				} else {
					id = aws.String(resource.Value)
				}
			}
		}
	case "CloudTrailChanged", "CloudTrailDeleted":
		for _, resource := range data.EntityMap.Resource {
			if resource.Name == "name" {
				if len(resource.Value) > 64 {
					id = aws.String(resource.Value[:64])
				} else {
					id = aws.String(resource.Value)
				}
			}
		}
	case "CloudTrailDefaultAlert":
		if len(data.EntityMap.CtUser) > 0 {
			if len(data.EntityMap.CtUser[0].PrincipalID) > 64 {
				id = aws.String(data.EntityMap.CtUser[0].PrincipalID[:64])
			} else {
				id = aws.String(data.EntityMap.CtUser[0].PrincipalID)
			}
			ctUserMap := a.ctUser(data.EntityMap.CtUser)
			for k, v := range ctUserMap {
				otherMap[k] = v
			}
		}
	default:
		d := fmt.Sprintf("%s-%s", data.EventModel, data.EventType)
		if len(d) > 64 {
			id = aws.String(d[:64])
		} else {
			id = aws.String(d)
		}

		fmt.Printf("EventType has no rule: %s\n", data.EventType)
		t, _ := json.Marshal(data)
		if a.config.Telemetry {
			lacework.SendHoneycombEvent(a.config.Instance, "cloudtrail_event_type_not_found", "", a.config.Version, string(t), "otherDetails")
		}
	}
	return id, otherMap
}

func (a Aws) rule(rules []types.Rule) map[string]*string {
	other := make(map[string]*string)
	for i, p := range rules {
		if p.RuleTitle != "" {
			other["RULE_TITLE-"+strconv.Itoa(i)] = aws.String(p.RuleTitle)
		}
		if p.RuleID != "" {
			other["RULE_ID-"+strconv.Itoa(i)] = aws.String(p.RuleID)
		}
		if p.RuleDescription != "" {
			other["RULE_DESCRIPTION-"+strconv.Itoa(i)] = aws.String(p.RuleDescription)
		}
	}
	return other
}

func (a Aws) ctUser(ctUsers []types.CtUser) map[string]*string {
	other := make(map[string]*string)
	for i, p := range ctUsers {
		if p.Username != "" {
			other["CT_USER-"+strconv.Itoa(i)] = aws.String(p.Username)
		}
		if p.AccountID != "" {
			other["ACCOUNT_ID-"+strconv.Itoa(i)] = aws.String(p.AccountID)
		}
		if p.PrincipalID != "" {
			other["PRINCIPAL_ID-"+strconv.Itoa(i)] = aws.String(p.PrincipalID)
		}
	}
	return other
}

func (a Aws) ipAddress(ips []types.SourceIpAddress) map[string]*string {
	other := make(map[string]*string)
	for i, p := range ips {
		if p.Region != "" {
			other["IP-REGION-"+strconv.Itoa(i)] = aws.String(p.Region)
		}
		if p.IPAddress != "" {
			other["IP_ADDRESS-"+strconv.Itoa(i)] = aws.String(p.IPAddress)
		}
		if p.Country != "" {
			other["IP-COUNTRY-"+strconv.Itoa(i)] = aws.String(p.Country)
		}
	}
	return other
}

func (a Aws) API(apis []types.API) map[string]*string {
	other := make(map[string]*string)
	for i, p := range apis {
		if p.Service != "" {
			other["API-SERVICE-"+strconv.Itoa(i)] = aws.String(p.Service)
		}
	}
	return other
}
