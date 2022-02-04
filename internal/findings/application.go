package findings

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/securityhub"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"strconv"
	"time"
)

type App struct {
	Event types.LaceworkEvent
}

func (a App) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(a.Event.Detail.Summary)
	// grab the config struct from the context
	cfg := ctx.Value("config").(types.Config)
	for _, e := range a.Event.Detail.EventDetails.Data {
		generatorID := a.getGenerator(a.Event.Detail.EventCategory, a.Event.Source, e.EventType, e.EventModel)
		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, a.Event.Detail.Summary)),
			GeneratorId:   aws.String(generatorID),
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(a.Event.ID),
			ProductArn:    getProductArn(cfg.Region),
			Types:         getTypes(cfg.EventMap, a.Event.Detail.EventType),
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
	// create the basic resource
	res := securityhub.Resource{
		Details: &securityhub.ResourceDetails{},
		Type:    aws.String("Other"),
	}
	res.Id, res.Details.Other = a.otherDetails(data)
	resourceList = append(resourceList, &res)
	return resourceList
}

func (a App) otherDetails(data types.Data) (*string, map[string]*string) {
	otherMap := make(map[string]*string)
	var id *string
	// Check the EVENT_TYPE and make decisions
	switch data.EventType {
	case "NewChildLaunched":
		// Machine Key
		machineMap := a.machine(data.EntityMap.Machine)

		for k, v := range machineMap {
			if k == "MACHINE-HOSTNAME-0" {
				id = v
			}
			otherMap[k] = v
		}
		// Process Key
		processMap := a.process(data.EntityMap.Process)
		for k, v := range processMap {
			otherMap[k] = v
		}
		// Application
		applicationMap := a.application(data.EntityMap.Application)
		for k, v := range applicationMap {
			otherMap[k] = v
		}
		// FileExePath
		fileExeMap := a.fileExePath(data.EntityMap.FileExePath)
		for k, v := range fileExeMap {
			otherMap[k] = v
		}
	case "NewExternalServerIp":
		// User, IpAddress, Process, Application, FileExePath, Machine
		userMap := a.user(data.EntityMap.User)
		for k, v := range userMap {
			otherMap[k] = v
		}
		ipMap := a.ipAddress(data.EntityMap.IpAddress)
		for k, v := range ipMap {
			otherMap[k] = v
		}
		machineMap := a.machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			otherMap[k] = v
		}
		processMap := a.process(data.EntityMap.Process)
		for k, v := range processMap {
			otherMap[k] = v
		}
		applicationMap := a.application(data.EntityMap.Application)
		for k, v := range applicationMap {
			if k == "APPLICATION-0" {
				id = v
			}
			otherMap[k] = v
		}
		fileExeMap := a.fileExePath(data.EntityMap.FileExePath)
		for k, v := range fileExeMap {
			otherMap[k] = v
		}
	case "NewBinaryType":
		// User, Process, Application, FileExePath, Machine
		userMap := a.user(data.EntityMap.User)
		for k, v := range userMap {
			otherMap[k] = v
		}
		machineMap := a.machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			if k == "MACHINE-HOSTNAME-0" {
				id = v
			}
			otherMap[k] = v
		}
		processMap := a.process(data.EntityMap.Process)
		for k, v := range processMap {
			otherMap[k] = v
		}
		applicationMap := a.application(data.EntityMap.Application)
		for k, v := range applicationMap {
			otherMap[k] = v
		}
		fileExeMap := a.fileExePath(data.EntityMap.FileExePath)
		for k, v := range fileExeMap {
			otherMap[k] = v
		}
	case "ExistingCveNewInDatacenter":
		// ImageFeature, ImageId, CVE, CustomRule
		imageIdMap := a.imageId(data.EntityMap.Imageid)
		for k, v := range imageIdMap {
			if k == "IMAGE" {
				id = v
			}
			otherMap[k] = v
		}
		imageFeatureMap := a.imageFeature(data.EntityMap.Imagefeature)
		for k, v := range imageFeatureMap {
			otherMap[k] = v
		}
		customRuleMap := a.customRule(data.EntityMap.Customrule)
		for k, v := range customRuleMap {
			otherMap[k] = v
		}
		cveMap := a.cve(data.EntityMap.Cve)
		for k, v := range cveMap {
			otherMap[k] = v
		}
	case "NewExternalServerDNSConn":
		// DNS, User, Process, Application, FileExePath, Machine
		id = aws.String(data.EntityMap.DnsName[0].HOSTNAME)
		dnsMap := a.dns(data.EntityMap.DnsName)
		for k, v := range dnsMap {
			otherMap[k] = v
		}
		userMap := a.user(data.EntityMap.User)
		for k, v := range userMap {
			otherMap[k] = v
		}
		machineMap := a.machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			if k == "MACHINE-HOSTNAME-0" {
				id = v
			}
			otherMap[k] = v
		}
		processMap := a.process(data.EntityMap.Process)
		for k, v := range processMap {
			otherMap[k] = v
		}
		applicationMap := a.application(data.EntityMap.Application)
		for k, v := range applicationMap {
			otherMap[k] = v
		}
		fileExeMap := a.fileExePath(data.EntityMap.FileExePath)
		for k, v := range fileExeMap {
			otherMap[k] = v
		}
	case "NewInternalConnection":
		machineMap := a.machine(data.EntityMap.Machine)
		for k, v := range machineMap {
			if k == "MACHINE-HOSTNAME-0" {
				id = v
			}
			otherMap[k] = v
		}
	default:
		fmt.Printf("EventType: %s\n", data.EventType)
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
		if p.COUNTRY != "" {
			other["IP-COUNTRY-"+strconv.Itoa(i)] = aws.String(p.COUNTRY)
		}
		if p.IPADDRESS != "" {
			other["IP_ADDRESS-"+strconv.Itoa(i)] = aws.String(p.IPADDRESS)
		}
		if p.REGION != "" {
			other["IP_REGION-"+strconv.Itoa(i)] = aws.String(p.REGION)
		}
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

func (a App) imageFeature(features []types.Imagefeature) map[string]*string {
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
	}
	return other
}

func (a App) customRule(cr []types.Customrule) map[string]*string {
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

func (a App) getGenerator(category, source, eventType, eventModel string) string {
	return fmt.Sprintf("Category: %s - Source: %s - Type: %s - Model: %s", category, source, eventType, eventModel)
}
