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
	// Modifies rapid alerts EventTtpe, which includes spaces, to the originol EventType format in PascalCase
	a.Event.Detail.EventType = a.replaceEventType(a.Event.Detail.EventType)
	a.Event.Detail.EventDetails.Data[0].EventType = a.Event.Detail.EventType
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
	

	// Helper function to safely add items to otherMap
	addToMap := func(newItems map[string]*string) {
		for k, v := range newItems {
			if len(otherMap) >= 50 {
				return // Stop adding if we've reached 50 items as anything over 50 violates accepted schema
			}
			otherMap[k] = v
		}
	}

	// Check the EVENT_TYPE and make decisions
	switch data.EventType {
	case "UserUsedServiceInRegion", "ServiceAccessedInRegion", "NewService", "NewCustomerMasterKey", "CustomerMasterKeyScheduledForDeletion",
		"UsageOfRootAccount", "FailedConsoleLogin", "CLoudTrailDefaultAlert", "CloudTrailStopped":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].Username[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].Username)
		}
		addToMap(a.ipAddress(data.EntityMap.SourceIpAddress))
		addToMap(a.API(data.EntityMap.API))

	case "UnauthorizedAPICall", "IAMPolicyChanged", "NetworkGatewayChange", "RouteTableChange", "SecurityGroupChange":
		rule := fmt.Sprintf("%s(s)-%s", data.EntityMap.RulesTriggered[0].RuleTitle, data.EntityMap.RulesTriggered[0].RuleID)
		if len(rule) > 64 {
			id = aws.String(rule[:64])
		} else {
			id = aws.String(rule)
		}
		addToMap(a.rule(data.EntityMap.RulesTriggered))

	case "SuccessfulConsoleLoginWithoutMFA", "ServiceCalledApi", "S3BucketPolicyChanged", "S3BucketACLChanged",
		"LoginFromSourceUsingCalltype", "ApiFailedWithError", "AwsAccountFailedApi", "NewCustomerMasterKeyAlias",
		"NewGrantAddedToCustomerMasterKey", "CloudTrailChanged":
		rule := fmt.Sprintf("%s-%s", data.EntityMap.CtUser[0].PrincipalID, data.EntityMap.CtUser[0].Username)
		if len(rule) > 64 {
			id = aws.String(rule[:64])
		} else {
			id = aws.String(rule)
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))

	case "NewUser", "VPCChange":
		if len(data.EntityMap.CtUser[0].Username) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].Username[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].Username)
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))

	case "IAMAccessKeyChanged":
		if len(data.EntityMap.CtUser[0].PrincipalID) > 64 {
			id = aws.String(data.EntityMap.CtUser[0].PrincipalID[:64])
		} else {
			id = aws.String(data.EntityMap.CtUser[0].PrincipalID)
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))

	case "NewRegion", "NewVPC":
		if len(data.EntityMap.Region[0].Region) > 64 {
			id = aws.String(data.EntityMap.Region[0].Region[:64])
		} else {
			id = aws.String(data.EntityMap.Region[0].Region)
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))

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
		addToMap(a.ctUser(data.EntityMap.CtUser))

	case "CloudTrailDeleted":
		for _, resource := range data.EntityMap.Resource {
			if resource.Name == "name" {
				if len(resource.Value) > 64 {
					id = aws.String(resource.Value[:64])
				} else {
					id = aws.String(resource.Value)
				}
			}
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))

	case "CloudTrailDefaultAlert":
		if len(data.EntityMap.CtUser) > 0 {
			user := data.EntityMap.CtUser[0]
			identifier := user.PrincipalID
			if identifier == "" {
				identifier = user.Username
			}
			if len(identifier) > 64 {
				id = aws.String(identifier[:64])
			} else {
				id = aws.String(identifier)
			}
			addToMap(a.ctUser(data.EntityMap.CtUser))
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
			lacework.SendHoneycombEvent(a.config.Instance, "cloudtrail_event_type_not_found", "", a.config.Version, string(t), "otherDetails", a.config.HoneyKey, a.config.HoneyDataset)
		}
		addToMap(a.ctUser(data.EntityMap.CtUser))
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

// checks for low latency alert, changes event type to supported versionm
func (a Aws) replaceEventType(etype string) string {
	if strings.Contains(a.Event.Detail.EventType, " ") {
		if mappedType, exists := a.config.AlertMap[a.Event.Detail.EventType]; exists {
			etype = mappedType
		} else {
			fmt.Println("Found unmapped alert: ", a.Event.Detail.EventType)
			etype = "LowLatencyUncategorized"
		}
	}
	return etype
}
