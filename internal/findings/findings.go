package findings

import (
	"context"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-dev/aws-security-hub-integration/internal/resources"
	"github.com/lacework-dev/aws-security-hub-integration/pkg/types"
	"log"
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
	log.Printf("Account: %s | Category: %s\n", le.Detail.Account, le.Detail.EventCategory)
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

/*
//GBM based events
        NewExternalServerDns("NewExternalServerDns", 2.0, true),
        NewExternalDnsServer("NewExternalDnsServer", 2.0, true),
        NewExternalServerDNSConn("NewExternalServerDNSConn", 2.0, false),
        NewExternalServerIp("NewExternalServerIp", 2.0, true),
        NewExternalServerIPConn("NewExternalServerIPConn", 2.0, false),
        NewExternalServerBadDns("NewExternalServerBadDns", 1.0, true),
        NewExternalServerBadIp("NewExternalServerBadIp", 1.0, true),
        NewExternalServerBadIPConn("NewExternalServerBadIPConn", 1.0, false),
        NewExternalServerBadDNSConn("NewExternalServerBadDNSConn", 1.0, false),
        NewExternalBadDnsServer("NewExternalBadDnsServer", 1.0, true),
        NewExternalClientIp("NewExternalClientIp", 3.0, true),
        NewExternalClientDns("NewExternalClientDns", 3.0, true),
        NewExternalClientConn("NewExternalClientConn", 2.0, false),
        NewExternalClientBadIpConn("NewExternalClientBadIpConn", 1.0, false),
        NewExternalClientBadIp("NewExternalClientBadIp", 1.0, true),
        NewExternalClientBadDns("NewExternalClientBadDns", 1.0, true),
        NewInternalServerIP("NewInternalServerIP", 3.0, true),
        NewInternalClientIP("NewInternalClientIP", 3.0, true),
        NewInternalConnection("NewInternalConnection", 3.0, false),
        NewErrorDns("NewErrorDns", 2.0, true),
        NewDnsQueryToCountry("NewDnsQueryToCountry", 2.0, true),
        NewBinaryType("NewBinaryType", 2.0, true),
        NewMachineServerCluster("NewMachineServerCluster", 2.0, true),
        NewUser("NewUser", 2.0, true),
        NewPrivilegeEscalation("NewPrivilegeEscalation", 2.0, false),
        NewChildLaunched("NewChildLaunched", 3.0, false),
        MachineClusterLaunchedNewBinary("MachineClusterLaunchedNewBinary", 3.0, false),
        UserLaunchedNewBinary("UserLaunchedNewBinary", 2.0, false),
        UserLoggedInFromNewIp("UserLoggedInFromNewIp", 2.0, false),
        UserLoggedInFromNewLocation("UserLoggedInFromNewLocation", 2.0, false),

        //K8 Launch -- agent data

        NewK8Cluster("NewK8Cluster", 3.0, true),
        NewK8Namespace("NewK8Namespace", 2.0, true),
        NewK8Pod("NewK8Pod", 3.0, true),

        //AwsApiTracker events
        NewAccount("NewAccount", 2.0, true),
        AwsUserLoggedInFromSource("AwsUserLoggedInFromSource", 3.0, true),
        UserCalltypeMfa("UserCalltypeMfa", 3.0, true),
        NewService("NewService", 3.0, true),
        NewRegion("NewRegion", 2.0, true),
        UserUsedServiceInRegion("UserUsedServiceInRegion", 2.0, true),
        NewErrorCode("NewErrorCode", 3.0, true),
        LoginFromBadSourceUsingCalltype("LoginFromBadSourceUsingCalltype", 1.0, true),
        LoginFromSourceUsingCalltype("LoginFromSourceUsingCalltype", 2.0, true),
        UserAccessingRegion("UserAccessingRegion",2.0, true),
        ServiceAccessedInRegion("ServiceAccessedInRegion", 2.0, true),
        ServiceCalledApi("ServiceCalledApi", 3.0, true),
        ApiFailedWithError("ApiFailedWithError", 3.0, true),

        //SQL based events: Login
        SuspiciousLogin("SuspiciousLoginFromBadIp", 1.0, false),
        BadIpServerConn("BadIpServerConn", 1.0, true),
        MaliciousFile("MaliciousFile", 1.0, true),

        //SQL based events: Aws Cloud Trail
        NewVPC("NewVPC", 3.0, true),
        VPCChange("VPCChange", 3.0, true),
        SecurityGroupChange("SecurityGroupChange", 3.0, true),
        NACLChange("NACLChange", 3.0, true),
        NewVPNConnection("NewVPNConnection", 3.0, true),
        VPNGatewayChange("VPNGatewayChange", 3.0, true),
        NetworkGatewayChange("NetworkGatewayChange", 3.0, true),
        RouteTableChange("RouteTableChange", 3.0, true),
        NewS3Bucket("NewS3Bucket", 3.0, true),
        S3BucketDeleted("S3BucketDeleted", 3.0, true),
        S3BucketPolicyChanged("S3BucketPolicyChanged", 3.0, true),
        S3BucketACLChanged("S3BucketACLChanged", 3.0, true),
        IAMAccessKeyChanged("IAMAccessKeyChanged", 2.0, true),
        IAMPolicyChanged("IAMPolicyChanged", 3.0, true),
        NewAccessKey("NewAccessKey", 3.0, true),
        AccessKeyDeleted("AccessKeyDeleted", 3.0, true),
        CloudTrailChanged("CloudTrailChanged", 3.0, true),
        CloudTrailStopped("CloudTrailStopped", 3.0, true),
        CloudTrailDeleted("CloudTrailDeleted", 3.0, true),
        NewCustomerMasterKey("NewCustomerMasterKey", 3.0, true),
        NewCustomerMasterKeyAlias("NewCustomerMasterKeyAlias", 3.0, true),
        CustomerMasterKeyDisabled("CustomerMasterKeyDisabled", 3.0, true),
        NewGrantAddedToCustomerMasterKey("NewGrantAddedToCustomerMasterKey", 3.0, true),
        CustomerMasterKeyScheduledForDeletion("CustomerMasterKeyScheduledForDeletion", 3.0, true),
        SuccessfulConsoleLoginWithoutMFA("SuccessfulConsoleLoginWithoutMFA", 2.0, true),
        FailedConsoleLogin("FailedConsoleLogin", 3.0, true),
        UsageOfRootAccount("UsageOfRootAccount", 3.0, true),
        UnauthorizedAPICall("UnauthorizedAPICall", 3.0, true),
        ConfigServiceChange("ConfigServiceChange", 3.0, true),
        CloudTrailDefaultAlert("CloudTrailDefaultAlert", 3.0, true),

        //Sql Compliance events
        ComplianceChanged("ComplianceChanged", 2.0, true),
        NewViolations("NewViolations", 2.0, true),


        //Custom Rules
        SuspiciousApplicationLaunched("SuspiciousApplicationLaunched", 3.0, true),
        SuspiciousUserLoginMultiGEOs("SuspiciousUserLoginMultiGEOs", 3.0, true),
        SuspiciousUserFailedLogin("SuspiciousUserFailedLogin", 3.0, true),
        ChangedFile("ChangedFile", 3.0, true),
        DeletedFile("DeletedFile", 3.0, true),
        NewFile("NewFile", 3.0, true),
        SuspiciousFile("SuspiciousFile", 3.0, true),

        // Vulnerability events
        NewCveDiscovered("NewCveDiscovered", 3.0, true),
        ExistingCveNewInDatacenter("ExistingCveNewInDatacenter", 2.0, true),
        ExistingCveNewInRepo("ExistingCveNewInRepo", 3.0, true),
        ExistingCveSeverityEscalated("ExistingCveSeverityEscalated", 3.0, true),
        ExistingCveFixAvailable("ExistingCveFixAvailable", 4.0, true),

        // Host vulnerability events
        NewHostCveDiscovered("NewHostCveDiscovered", 3.0, true),
        KnownHostCveDiscovered("KnownHostCveDiscovered", 2.0, true),
        ExistingHostCveSeverityEscalated("ExistingHostCveSeverityEscalated", 3.0, true),
        ExistingHostCveFixAvailable("ExistingHostCveFixAvailable", 4.0, true),

        //Azure Activity Log Cep events
        PolicyAssignmentCreated("PolicyAssignmentCreated", 3.0, true),
        NetworkSecurityGroupCreatedOrUpdated("NetworkSecurityGroupCreatedOrUpdated", 3.0, true),
        NetworkSecurityGroupDeleted("NetworkSecurityGroupDeleted", 3.0, true),
        NetworkSecurityGroupRuleCreatedOrUpdated("NetworkSecurityGroupRuleCreatedOrUpdated", 3.0, true),
        NetworkSecurityGroupRuleDeleted("NetworkSecurityGroupRuleDeleted", 3.0, true),
        SecuritySolutionCreatedOrUpdated("SecuritySolutionCreatedOrUpdated", 3.0, true),
        SecuritySolutionDeleted("SecuritySolutionDeleted", 3.0, true),
        SQLServerFirewallRuleCreatedOrUpdated("SQLServerFirewallRuleCreatedOrUpdated", 3.0, true),
        SQLServerFirewallRuleDeleted("SQLServerFirewallRuleDeleted", 3.0, true),
        SecurityPolicyUpdated("SecurityPolicyUpdated", 3.0, true),

        //GCP Audit Trail Cep events
        ProjectOwnershipAssignmentsChanged("ProjectOwnershipAssignmentsChanged", 3.0, true),
        AuditConfigurationChanged("AuditConfigurationChanged", 3.0, true),
        CustomRoleChanged("CustomRoleChanged", 3.0, true),
        VPCNetworkFirewallRuleChanged("VPCNetworkFirewallRuleChanged", 3.0, true),
        VPCNetworkRouteChanged("VPCNetworkRouteChanged", 3.0, true),
        VPCNetworkChanged("VPCNetworkChanged", 3.0, true),
        CloudStorageIAMPermissionChanged("CloudStorageIAMPermissionChanged", 3.0, true),
        SQLInstanceConfigurationChanged("SQLInstanceConfigurationChanged", 3.0, true),

        // lql-policy violation related events
        NewPolicyViolation("NewPolicyViolation", 2.0, true),
        PolicyViolationChanged("PolicyViolationChanged", 2.0, true),

        // platform alerts
        CloudActivityLogIngestionFailed("CloudActivityLogIngestionFailed", 2.0, true),

        // GCP Api Tracker alerts
        NewOrganization("NewOrganization", 2.0, true),
        NewGcpSource("NewGcpSource", 3.0, true),
        NewGcpUser("NewGcpUser", 2.0, true),
        NewGcpRegion("NewGcpRegion", 2.0, true),
        NewGcpService("NewGcpService", 3.0, true),
        NewGcpApiCall("NewGcpApiCall", 3.0, true),
        GcpUserLoggedInFromSource("GcpUserLoggedInFromSource", 2.0, true),
        GcpUserLoggedInFromBadSource("GcpUserLoggedInFromBadSource", 1.0, true),
        GcpUserAccessingRegion("GcpUserAccessingRegion",2.0, true),
        GcpServiceAccessedInRegion("GcpServiceAccessedInRegion", 2.0, true),
        ServiceCalledGcpApi("ServiceCalledGcpApi", 2.0, true),
        GcpApiFailedWithError("GcpApiFailedWithError", 3.0, true),

        // K8s Audit Log alerts
        NewK8sAuditLogClusterRole("NewK8sAuditLogClusterRole", 3.0, true),
        NewK8sAuditLogClusterRoleBinding("NewK8sAuditLogClusterRoleBinding", 3.0, true),
        NewK8sAuditLogRole("NewK8sAuditLogRole", 2.0, true),
        NewK8sAuditLogRoleBinding("NewK8sAuditLogRoleBinding", 3.0, true),
        NewK8sAuditLogNamespace("NewK8sAuditLogNamespace", 4.0, true),
        NewK8sAuditLogWorkload("NewK8sAuditLogWorkload", 2.0, true),
        NewK8sAuditLogImageRepository("NewK8sAuditLogImageRepository", 2.0, true),
        NewK8sAuditLogUser("NewK8sAuditLogUser", 3.0, true),
        NewK8sAuditLogIngress("NewK8sAuditLogIngress", 3.0, true);


The following information describes the first three levels of the Types path. In the list, the top-level bullets are namespaces, the second-level bullets are categories, and the third-level bullets are classifiers. Only the Software and Configuration Checks namespace has defined classifiers.

Namespaces

Categories

Classifiers

Finding providers must use the defined namespaces. The defined categories and classifiers are recommended for use, but are not required.

A finding provider might define a partial path for namespace/category/classifier. For example, the following finding types are all valid.

TTPs

TTPs/Defense Evasion

TTPs/Defense Evasion/CloudTrailStopped

TTPs stands for tactics, techniques, and procedures. The TTP categories in the following list align to the MITRE ATT&CK MatrixTM. Unusual Behaviors reflect general unusual behavior, such as general statistical anomalies, and are not aligned with a specific TTP. However, you could classify a finding with both Unusual Behaviors and TTPs finding types.

Software and Configuration Checks

	Vulnerabilities

		CVE

	AWS Security Best Practices

		Network Reachability

		Runtime Behavior Analysis

	Industry and Regulatory Standards

		CIS Host Hardening Benchmarks

		CIS AWS Foundations Benchmark

		PCI-DSS Controls

		Cloud Security Alliance Controls

		ISO 90001 Controls

		ISO 27001 Controls

		ISO 27017 Controls

		ISO 27018 Controls

		SOC 1

		SOC 2

		HIPAA Controls (USA)

		NIST 800-53 Controls (USA)

		NIST CSF Controls (USA)

		IRAP Controls (Australia)

		K-ISMS Controls (Korea)

		MTCS Controls (Singapore)

		FISC Controls (Japan)

		My Number Act Controls (Japan)

		ENS Controls (Spain)

		Cyber Essentials Plus Controls (UK)

		G-Cloud Controls (UK)

		C5 Controls (Germany)

		IT-Grundschutz Controls (Germany)

		GDPR Controls (Europe)

		TISAX Controls (Europe)

	Patch Management

TTPs

	Initial Access

	Execution

	Persistence

	Privilege Escalation

	Defense Evasion

	Credential Access

	Discovery

	Lateral Movement

	Collection

	Command and Control

Effects

	Data Exposure

	Data Exfiltration

	Data Destruction

	Denial of Service

	Resource Consumption

Unusual Behaviors

	Application

	Network Flow

	IP address

	User

	VM

	Container

	Serverless

	Process

	Database

	Data

Sensitive Data Identifications

	PII

	Passwords

	Legal

	Financial

	Security

	Business

*/
