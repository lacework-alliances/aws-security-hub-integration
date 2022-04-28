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

type App struct {
	Event  types.LaceworkEvent
	config types.Config
}

func (a App) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
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

func (a App) resource(data types.Data) []*securityhub.Resource {
	var resourceList []*securityhub.Resource
	var res securityhub.Resource
	// create the basic resource
	switch data.EventType {
	case "":
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

func (a App) otherDetails(data types.Data) (*string, map[string]*string) {
	otherMap := make(map[string]*string)
	var id *string
	switch data.EventType {
	case "NewExternalClientBadIp", "NewExternalClientConn", "NewExternalServerIp", "NewChildLaunched",
		"NewExternalServerDNSConn":
		if len(data.EntityMap.Container) > 0 {
			image := fmt.Sprintf("%s:%s", data.EntityMap.Container[0].IMAGEREPO, data.EntityMap.Container[0].IMAGETAG)
			id = aws.String(image)
		} else {
			id = aws.String(data.EntityMap.Machine[0].Hostname)
		}
		if len(data.EntityMap.Container) > 0 {
			containerMap := a.container(data.EntityMap.Container)
			for k, v := range containerMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.Machine) > 0 {
			machineMap := a.machine(data.EntityMap.Machine)
			for k, v := range machineMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.Application) > 0 {
			appMap := a.application(data.EntityMap.Application)
			for k, v := range appMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.Process) > 0 {
			procMap := a.process(data.EntityMap.Process)
			for k, v := range procMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.FileExePath) > 0 {
			fileMap := a.fileExePath(data.EntityMap.FileExePath)
			for k, v := range fileMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.User) > 0 {
			userMap := a.user(data.EntityMap.User)
			for k, v := range userMap {
				otherMap[k] = v
			}
		}
		if len(data.EntityMap.DnsName) > 0 {
			dnsMap := a.dns(data.EntityMap.DnsName)
			for k, v := range dnsMap {
				otherMap[k] = v
			}
		}
	case "KnownHostCveDiscovered", "ExistingHostCveSeverityEscalated", "ExistingHostCveFixAvailable":
		var s string
		for _, cve := range data.EntityMap.Cve {
			s = s + " " + cve.CveID
		}
		id = aws.String(s)
		cveMap := a.cve(data.EntityMap.Cve)
		for k, v := range cveMap {
			otherMap[k] = v
		}
		ruleMap := a.customRule(data.EntityMap.CustomRule)
		for k, v := range ruleMap {
			otherMap[k] = v
		}
		featureMap := a.imageFeature(data.EntityMap.ImageFeature)
		for k, v := range featureMap {
			otherMap[k] = v
		}
		machineMap := a.machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			otherMap[k] = v
		}
	default:
		d := fmt.Sprintf("%s-%s", data.EventModel, data.EventType)
		id = aws.String(d)
		fmt.Printf("EventType has no rule: %s\n", data.EventType)
		t, _ := json.Marshal(data)
		if a.config.Telemetry {
			lacework.SendHoneycombEvent(a.config.Instance, "cloudtrail_event_type_not_found", "", a.config.Version, string(t), "otherDetails")
		}
	}
	return id, otherMap
}

func (a App) machine(machines []types.Machine) map[string]*string {
	other := make(map[string]*string)
	for i, m := range machines {
		if m.ExternalIP != "" {
			other["MACHINE-EXTERNAL_IP-"+strconv.Itoa(i)] = aws.String(m.ExternalIP)
		}
		if m.InternalIPAddr != "" {
			other["MACHINE-INTERNAL_IP_ADDR-"+strconv.Itoa(i)] = aws.String(m.InternalIPAddr)
		}
		if m.Hostname != "" {
			other["MACHINE-HOSTNAME-"+strconv.Itoa(i)] = aws.String(m.Hostname)
		}
		if m.InstanceID != "" {
			other["MACHINE-INSTANCE_ID-"+strconv.Itoa(i)] = aws.String(m.InstanceID)
		}
	}
	return other
}

func (a App) application(apps []types.Application) map[string]*string {
	other := make(map[string]*string)
	for i, app := range apps {
		if app.APPLICATION != "" {
			other["APPLICATION-"+strconv.Itoa(i)] = aws.String(app.APPLICATION)
		}
		if app.EARLIESTKNOWNTIME.String() != "" {
			other["APPLICATION-EARLIEST_KNOWN_TIME-"+strconv.Itoa(i)] = aws.String(app.EARLIESTKNOWNTIME.String())
		}
	}
	return other
}

func (a App) fileExePath(fileExePaths []types.FileExePath) map[string]*string {
	other := make(map[string]*string)
	for i, f := range fileExePaths {
		if f.EXEPATH != "" {
			other["FILE_EXE_PATH-"+strconv.Itoa(i)] = aws.String(f.EXEPATH)
		}
		if f.LASTFILEOWNER != "" {
			other["LAST_FILE_OWNER-"+strconv.Itoa(i)] = aws.String(f.LASTFILEOWNER)
		}
	}
	return other
}

func (a App) process(processes []types.Process) map[string]*string {
	other := make(map[string]*string)
	for i, p := range processes {
		if p.HOSTNAME != "" {
			other["PROCESS-HOSTNAME-"+strconv.Itoa(i)] = aws.String(p.HOSTNAME)
		}
		if p.CMDLINE != "" {
			other["PROCESS_CMDLINE-"+strconv.Itoa(i)] = aws.String(p.CMDLINE)
		}
		if p.PROCESSSTARTTIME.String() != "" {
			other["PROCESS_START_TIME-"+strconv.Itoa(i)] = aws.String(p.PROCESSSTARTTIME.String())
		}
		if p.PROCESSID > 0 {
			other["PROCESS_ID-"+strconv.Itoa(i)] = aws.String(strconv.Itoa(p.PROCESSID))
		}
		if p.CPUPERCENTAGE >= 0 {
			cpu := fmt.Sprintf("%f", p.CPUPERCENTAGE)
			other["PROCESS-CPU_PERCENTAGE-"+strconv.Itoa(i)] = aws.String(cpu)
		}
	}
	return other
}

func (a App) user(users []types.User) map[string]*string {
	other := make(map[string]*string)
	for i, u := range users {
		if u.MACHINEHOSTNAME != "" {
			other["USER-MACHINE_HOSTNAME-"+strconv.Itoa(i)] = aws.String(u.MACHINEHOSTNAME)
		}
		if u.USERNAME != "" {
			other["USER-MACHINE-USERNAME-"+strconv.Itoa(i)] = aws.String(u.USERNAME)
		}
	}
	return other
}

func (a App) ipAddress(ips []types.IpAddress) map[string]*string {
	other := make(map[string]*string)
	for i, p := range ips {
		if p.Region != "" {
			other["IP-REGION-"+strconv.Itoa(i)] = aws.String(p.Region)
		}
		if p.IPAddress != "" {
			other["IP_ADDRESS-"+strconv.Itoa(i)] = aws.String(p.IPAddress)
		}
		if p.ThreatTags != "" {
			other["IP-THREAT-TAGS-"+strconv.Itoa(i)] = aws.String(p.ThreatTags)
		}
		if p.Country != "" {
			other["IP-COUNTRY-"+strconv.Itoa(i)] = aws.String(p.Country)
		}
		if p.TotalOutBytes != 0 {
			other["IP-TOTAL-OUT-BYTES-"+strconv.Itoa(i)] = aws.String(strconv.Itoa(p.TotalOutBytes))
		}
		if p.TotalInBytes != 0 {
			other["IP-TOTAL-IN-BYTES-"+strconv.Itoa(i)] = aws.String(strconv.Itoa(p.TotalInBytes))
		}
		if len(p.PortList) > 0 {
			var ports string
			for _, port := range p.PortList {
				ports = ports + " " + strconv.Itoa(port)
			}
			other["PORT-LIST-"+strconv.Itoa(i)] = aws.String(ports)
		}
		if len(p.ThreatSource) > 0 {
			for j, threat := range p.ThreatSource {
				other["THREAT-SOURCE-DATE-"+strconv.Itoa(j)] = aws.String(threat.Date)
				other["THREAT-SOURCE-TAG-"+strconv.Itoa(i)] = aws.String(threat.PrimaryThreatTag)
				other["THREAT-SOURCE-"+strconv.Itoa(i)] = aws.String(threat.Source)
			}
		}
	}
	return other
}

func (a App) dns(dns []types.DnsName) map[string]*string {
	other := make(map[string]*string)
	for i, p := range dns {
		if p.HOSTNAME != "" {
			other["DNS-HOSTNAME-"+strconv.Itoa(i)] = aws.String(p.HOSTNAME)
		}
		out := fmt.Sprintf("%f", p.TOTALOUTBYTES)
		in := fmt.Sprintf("%f", p.TOTALINBYTES)
		other["DNS-TOTAL_OUT_BYTES-"+strconv.Itoa(i)] = aws.String(out)
		other["DNS-TOTAL_IN_BYTES-"+strconv.Itoa(i)] = aws.String(in)
		if len(p.PORTLIST) > 0 {
			var ports string
			for _, port := range p.PORTLIST {
				ports = ports + " " + strconv.Itoa(port)
			}
			other["PORT_LIST-"+strconv.Itoa(i)] = aws.String(ports)
		}
	}
	return other
}

func (a App) imageId(images []types.Imageid) map[string]*string {
	other := make(map[string]*string)
	img := fmt.Sprintf("%s:%s", images[0].ImageRepo, images[0].ImageID)
	other["IMAGE"] = aws.String(img)
	other["IMAGE_ACTIVE"] = aws.String(isActive(images[0].ImageActive))
	for i, tag := range images[0].ImageTag {
		other["TAG-"+strconv.Itoa(i)] = aws.String(tag)

	}
	return other
}

func (a App) imageFeature(features []types.ImageFeature) map[string]*string {
	other := make(map[string]*string)
	for _, f := range features {
		if f.FeatureName != "" {
			other["FEATURE_NAME"] = aws.String(f.FeatureName)
		}
		if f.FeatureNamespace != "" {
			other["FEATURE_NAMESPACE"] = aws.String(f.FeatureNamespace)
		}
		for i, cve := range f.Cve {
			other[f.FeatureName+"-CVE-"+strconv.Itoa(i)] = aws.String(cve)
		}
		if f.FixedVersion != "" {
			other["FEATURE-FIXED-VERSION"] = aws.String(f.FixedVersion)
		}
	}
	return other
}

func (a App) customRule(cr []types.CustomRule) map[string]*string {
	other := make(map[string]*string)
	for i, r := range cr {
		if r.RuleGUID != "" {
			other["RULE_GUID-"+strconv.Itoa(i)] = aws.String(r.RuleGUID)
		}
		if r.LastUpdatedUser != "" {
			other["LAST_UPDATED_USER-"+strconv.Itoa(i)] = aws.String(r.LastUpdatedUser)
		}
		if r.LastUpdatedTime.String() != "" {
			other["LAST_UPDATED_TIME-"+strconv.Itoa(i)] = aws.String(r.LastUpdatedTime.String())
		}
		if r.DisplayFilter != "" {
			other["DISPLAY_FILTER-"+strconv.Itoa(i)] = aws.String(r.DisplayFilter)
		}
	}
	return other
}

func (a App) cve(cves []types.Cve) map[string]*string {
	other := make(map[string]*string)
	for _, c := range cves {
		if c.FeatureName != "" {
			other[c.CveID+"-FEATURE_NAME"] = aws.String(c.FeatureName)
			other[c.CveID+"-INFO"] = aws.String(c.Info)
			s := getSeverity(c.Severity)
			other[c.CveID+"-SEVERITY"] = s.Label
		}
	}
	return other
}

func (a App) container(containers []types.Container) map[string]*string {
	other := make(map[string]*string)
	public := "no"
	client := "no"
	server := "no"
	for i, c := range containers {
		if c.HASEXTERNALCONNS == 1 {
			public = "yes"
		}
		other["CONTAINER-PUBLIC-"+strconv.Itoa(i)] = aws.String(public)
		if c.ISCLIENT == 1 {
			client = "yes"
		}
		other["CONTAINER-CLIENT-"+strconv.Itoa(i)] = aws.String(client)
		if c.ISSERVER == 1 {
			server = "yes"
		}
		other["CONTAINER-SERVER-"+strconv.Itoa(i)] = aws.String(server)
		if c.FIRSTSEENTIME != "" {
			other["CONTAINER-FIRST-SEEN-"+strconv.Itoa(i)] = aws.String(c.FIRSTSEENTIME)
		}
		if c.CLUSTERNAME != "" {
			other["CONTAINER-CLUSTER-"+strconv.Itoa(i)] = aws.String(c.CLUSTERNAME)
		}
		img := fmt.Sprintf("%s:%s", c.IMAGEREPO, c.IMAGETAG)
		other["CONTAINER-IMAGE-"+strconv.Itoa(i)] = aws.String(img)
	}
	return other
}

func (a App) getGenerator(category, source, eventType, eventModel string) string {
	return fmt.Sprintf("Category: %s - Source: %s - Type: %s - Model: %s", category, source, eventType, eventModel)
}
