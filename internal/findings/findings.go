package findings

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/internal/resources"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
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

	ARN    = "arn:aws:securityhub:us-east-2:950194951070:product/950194951070/default"
	SCHEMA = "2018-10-08"
)

func EventToASFF(ctx context.Context, le types.LaceworkEvent) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	var desc string
	eventMap := ctx.Value("eventMap")
	m, ok := eventMap.(map[string]string)
	if !ok {
		// Do error stuff
	}

	if len(le.Detail.Summary) >= 255 {
		desc = le.Detail.Summary[:255]
	} else {
		desc = le.Detail.Summary
	}
	finding := securityhub.AwsSecurityFinding{
		AwsAccountId:  aws.String(resources.GetIncomingAccount(le.Detail.Summary)),
		GeneratorId:   aws.String(le.Detail.EventCategory),
		SchemaVersion: aws.String(SCHEMA),
		Id:            aws.String(le.ID),
		ProductArn:    aws.String(ARN),
		Types:         getTypes(m, le.Detail.EventType),
		CreatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		UpdatedAt:     aws.String(le.Time.Format(time.RFC3339)),
		Severity:      getSeverity(le.Detail.Severity),
		Title:         aws.String(desc),
		Description:   aws.String(le.Detail.Summary),
		SourceUrl:     aws.String(le.Detail.Link),
		Resources:     mapToResource(le.Detail.EventDetails.Data),
	}
	fs = append(fs, &finding)

	return fs
}

func mapToResource(data []types.Data) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	// loop through data slice
	for _, d := range data {
		var res securityhub.Resource
		switch d.EventModel {
		case "AwsApiTracker":
			res = resources.MapAwsApiTracker(d, res)
		case "CloudTrailCep":
			res = resources.MapCloudTrailCep(d, res)
		case "NewViolation", "ComplianceChanged":
			res = resources.MapAwsCompliance(d, res)
		default:
			res = resources.MapDefault(d, res)
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

// InitMap initializes maps based on the event type to an AWS Finding Type
func InitMap() map[string]string {
	// map[EVENT_TYPE]SEC_HUB_TYPE{}
	var eventMap = map[string]string{}

	eventMap["NewExternalServerDns"] = TtpInitialAccess
	eventMap["NewExternalServerIp"] = TtpInitialAccess
	eventMap["NewExternalDnsServer"] = TtpInitialAccess
	eventMap["NewExternalServerDNSConn"] = TtpInitialAccess
	eventMap["NewExternalServerIPConn"] = TtpInitialAccess
	eventMap["NewExternalServerBadDns"] = UnusualIP
	eventMap["NewExternalServerBadIp"] = UnusualIP
	eventMap["NewExternalServerBadIPConn"] = UnusualIP
	eventMap["NewExternalServerBadDNSConn"] = UnusualIP
	eventMap["NewExternalBadDnsServer"] = UnusualIP
	eventMap["NewExternalClientIp"] = TtpInitialAccess
	eventMap["NewExternalClientDns"] = TtpInitialAccess
	eventMap["NewExternalClientConn"] = TtpInitialAccess
	eventMap["NewExternalClientBadIpConn"] = UnusualIP
	eventMap["NewExternalClientBadIp"] = UnusualIP
	eventMap["NewExternalClientBadDns"] = UnusualIP
	eventMap["NewInternalServerIP"] = TtpInitialAccess
	eventMap["NewInternalClientIP"] = TtpInitialAccess
	eventMap["NewInternalConnection"] = TtpInitialAccess
	eventMap["NewErrorDns"] = UnusualNetwork
	eventMap["NewDnsQueryToCountry"] = TtpInitialAccess
	eventMap["NewBinaryType"] = TtpDiscovery
	eventMap["NewMachineServerCluster"] = TtpDiscovery
	eventMap["NewUser"] = TtpDiscovery
	eventMap["NewPrivilegeEscalation"] = TtpPrivilege
	eventMap["NewChildLaunched"] = TtpInitialAccess
	eventMap["MachineClusterLaunchedNewBinary"] = TtpInitialAccess
	eventMap["UserLaunchedNewBinary"] = TtpInitialAccess
	eventMap["UserLoggedInFromNewIp"] = TtpCredential
	eventMap["UserLoggedInFromNewLocation"] = TtpCredential

	eventMap["NewK8Cluster"] = TtpDiscovery
	eventMap["NewK8Namespace"] = TtpDiscovery
	eventMap["NewK8Pod"] = TtpDiscovery

	eventMap["NewAccount"] = TtpDiscovery
	eventMap["AwsUserLoggedInFromSource"] = TtpCredential
	eventMap["UserCalltypeMfa"] = TtpCredential
	eventMap["NewService"] = TtpDiscovery
	eventMap["NewRegion"] = TtpDiscovery
	eventMap["UserUsedServiceInRegion"] = TtpCredential
	eventMap["NewErrorCode"] = UnusualApplication
	eventMap["LoginFromBadSourceUsingCalltype"] = UnusualApplication
	eventMap["LoginFromSourceUsingCalltype"] = TtpCredential
	eventMap["UserAccessingRegion"] = TtpCredential
	eventMap["ServiceAccessedInRegion"] = TtpCredential
	eventMap["ServiceCalledApi"] = TtpCredential
	eventMap["ApiFailedWithError"] = UnusualApplication

	eventMap["SuspiciousLogin"] = UnusualIP
	eventMap["BadIpServerConn"] = UnusualIP
	eventMap["MaliciousFile"] = SensitiveSecurity

	eventMap["NewVPC"] = TtpDiscovery
	eventMap["VPCChange"] = TtpDiscovery
	eventMap["SecurityGroupChange"] = TtpDiscovery
	eventMap["NACLChange"] = TtpDiscovery
	eventMap["NewVPNConnection"] = TtpDiscovery
	eventMap["VPNGatewayChange"] = TtpDiscovery
	eventMap["NetworkGatewayChange"] = TtpDiscovery
	eventMap["RouteTableChange"] = TtpDiscovery
	eventMap["NewS3Bucket"] = TtpDiscovery
	eventMap["S3BucketDeleted"] = TtpDiscovery
	eventMap["S3BucketPolicyChanged"] = TtpDiscovery
	eventMap["S3BucketACLChanged"] = TtpDiscovery
	eventMap["IAMAccessKeyChanged"] = TtpDiscovery
	eventMap["IAMPolicyChanged"] = TtpDiscovery
	eventMap["NewAccessKey"] = TtpDiscovery
	eventMap["AccessKeyDeleted"] = TtpCredential
	eventMap["CloudTrailChanged"] = TtpCollection
	eventMap["CloudTrailStopped"] = TtpCollection
	eventMap["CloudTrailDeleted"] = TtpCollection
	eventMap["NewCustomerMasterKey"] = TtpCredential
	eventMap["NewCustomerMasterKeyAlias"] = TtpCredential
	eventMap["CustomerMasterKeyDisabled"] = TtpCredential
	eventMap["NewGrantAddedToCustomerMasterKey"] = TtpCredential
	eventMap["CustomerMasterKeyScheduledForDeletion"] = TtpCredential
	eventMap["SuccessfulConsoleLoginWithoutMFA"] = TtpCredential
	eventMap["FailedConsoleLogin"] = TtpCredential
	eventMap["UsageOfRootAccount"] = TtpPrivilege
	eventMap["UnauthorizedAPICall"] = TtpCredential
	eventMap["ConfigServiceChange"] = TtpDiscovery
	eventMap["CloudTrailDefaultAlert"] = TtpCollection

	eventMap["ComplianceChanged"] = NewViolation
	eventMap["NewViolations"] = NewViolation

	eventMap["SuspiciousApplicationLaunched"] = SensitiveSecurity
	eventMap["SuspiciousUserLoginMultiGEOs"] = SensitiveSecurity
	eventMap["SuspiciousUserFailedLogin"] = SensitiveSecurity
	eventMap["ChangedFile"] = TtpDiscovery
	eventMap["DeletedFile"] = TtpDiscovery
	eventMap["NewFile"] = TtpInitialAccess
	eventMap["SuspiciousFile"] = SensitiveSecurity

	eventMap["NewCveDiscovered"] = SoftwareCVE
	eventMap["ExistingCveNewInDatacenter"] = SoftwareCVE
	eventMap["ExistingCveNewInRepo"] = SoftwareCVE
	eventMap["ExistingCveSeverityEscalated"] = SoftwareCVE
	eventMap["ExistingCveFixAvailable"] = SoftwareCVE

	eventMap["NewHostCveDiscovered"] = SoftwareCVE
	eventMap["KnownHostCveDiscovered"] = SoftwareCVE
	eventMap["ExistingHostCveSeverityEscalated"] = SoftwareCVE
	eventMap["ExistingHostCveFixAvailable"] = SoftwareCVE

	eventMap["PolicyAssignmentCreated"] = TtpDiscovery
	eventMap["NetworkSecurityGroupCreatedOrUpdated"] = TtpDiscovery
	eventMap["NetworkSecurityGroupDeleted"] = TtpDiscovery
	eventMap["NetworkSecurityGroupRuleCreatedOrUpdated"] = TtpDiscovery
	eventMap["NetworkSecurityGroupRuleDeleted"] = TtpDiscovery
	eventMap["SecuritySolutionCreatedOrUpdated"] = TtpDiscovery
	eventMap["SecuritySolutionDeleted"] = TtpDiscovery
	eventMap["SQLServerFirewallRuleCreatedOrUpdated"] = TtpDiscovery
	eventMap["SQLServerFirewallRuleDeleted"] = TtpDiscovery
	eventMap["SecurityPolicyUpdated"] = TtpDiscovery

	eventMap["ProjectOwnershipAssignmentsChanged"] = TtpDiscovery
	eventMap["AuditConfigurationChanged"] = TtpDiscovery
	eventMap["CustomRoleChanged"] = TtpDiscovery
	eventMap["VPCNetworkFirewallRuleChanged"] = TtpDiscovery
	eventMap["VPCNetworkRouteChanged"] = TtpDiscovery
	eventMap["VPCNetworkChanged"] = TtpDiscovery
	eventMap["CloudStorageIAMPermissionChanged"] = TtpDiscovery
	eventMap["SQLInstanceConfigurationChanged"] = TtpDiscovery

	eventMap["NewPolicyViolation"] = SoftwarePolicy
	eventMap["PolicyViolationChanged"] = SoftwarePolicy

	eventMap["CloudActivityLogIngestionFailed"] = TtpCollection

	eventMap["NewOrganization"] = TtpDiscovery
	eventMap["NewGcpSource"] = TtpDiscovery
	eventMap["NewGcpUser"] = TtpDiscovery
	eventMap["NewGcpRegion"] = TtpDiscovery
	eventMap["NewGcpService"] = TtpDiscovery
	eventMap["NewGcpApiCall"] = TtpDiscovery
	eventMap["GcpUserLoggedInFromSource"] = TtpDiscovery
	eventMap["GcpUserLoggedInFromBadSource"] = TtpDiscovery
	eventMap["GcpUserAccessingRegion"] = TtpDiscovery
	eventMap["GcpServiceAccessedInRegion"] = TtpDiscovery
	eventMap["ServiceCalledGcpApi"] = TtpDiscovery
	eventMap["GcpApiFailedWithError"] = TtpError

	eventMap["NewK8sAuditLogClusterRole"] = TtpDiscovery
	eventMap["NewK8sAuditLogClusterRoleBinding"] = TtpDiscovery
	eventMap["NewK8sAuditLogRole"] = TtpDiscovery
	eventMap["NewK8sAuditLogRoleBinding"] = TtpDiscovery
	eventMap["NewK8sAuditLogNamespace"] = TtpDiscovery
	eventMap["NewK8sAuditLogWorkload"] = TtpDiscovery
	eventMap["NewK8sAuditLogImageRepository"] = TtpDiscovery
	eventMap["NewK8sAuditLogUser"] = TtpDiscovery
	eventMap["NewK8sAuditLogIngress"] = TtpDiscovery

	return eventMap
}
