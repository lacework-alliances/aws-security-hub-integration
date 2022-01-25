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

type App types.LaceworkEvent

func (a App) Findings(ctx context.Context) []*securityhub.AwsSecurityFinding {
	var fs []*securityhub.AwsSecurityFinding
	// format the finding description
	desc := getDescription(a.Detail.Summary)
	// grab the config struct from the context
	cfg := ctx.Value("config").(types.Config)

	for _, e := range a.Detail.EventDetails.Data {
		generatorID := a.getGenerator(a.Detail.EventCategory, a.Source, e.EventType, e.EventModel)
		finding := securityhub.AwsSecurityFinding{
			AwsAccountId:  aws.String(getAwsAccount(cfg.DefaultAccount, a.Detail.Summary)),
			GeneratorId:   aws.String(generatorID),
			SchemaVersion: aws.String(SCHEMA),
			Id:            aws.String(a.ID),
			ProductArn:    aws.String(ARN),
			Types:         getTypes(cfg.EventMap, a.Detail.EventType),
			CreatedAt:     aws.String(a.Time.Format(time.RFC3339)),
			UpdatedAt:     aws.String(a.Time.Format(time.RFC3339)),
			Severity:      getSeverity(a.Detail.Severity),
			Title:         aws.String(desc),
			Description:   aws.String(a.Detail.Summary),
			SourceUrl:     aws.String(a.Detail.Link),
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
		mId, machineMap := a.machine(data.EntityMap.Machine[0])
		id = aws.String(mId)
		for k, v := range machineMap {
			otherMap[k] = v
		}
		// Process Key
		processMap := a.process(data.EntityMap.Process)
		for k, v := range processMap {
			otherMap[k] = v
		}
		// Application
		applicationMap := a.application(data.EntityMap.Application[0])
		for k, v := range applicationMap {
			otherMap[k] = v
		}
		// FileExePath
		fileExeMap := a.fileExePath(data.EntityMap.FileExePath)
		for k, v := range fileExeMap {
			otherMap[k] = v
		}
	}

	return id, otherMap
}

func (a App) machine(m types.Machine) (string, map[string]*string) {
	other := make(map[string]*string)
	if m.ExternalIP != "" {
		other["EXTERNAL_IP"] = aws.String(m.ExternalIP)
	}
	if m.InternalIPAddr != "" {
		other["INTERNAL_IP_ADDR"] = aws.String(m.InternalIPAddr)
	}
	return m.Hostname, other
}

func (a App) application(application types.Application) map[string]*string {
	other := make(map[string]*string)
	if application.APPLICATION != "" {
		other["APPLICATION"] = aws.String(application.APPLICATION)
	}
	if application.EARLIESTKNOWNTIME.String() != "" {
		other["EARLIEST_KNOWN_TIME"] = aws.String(application.EARLIESTKNOWNTIME.String())
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
			other["FILE_EXE_PATH-"+strconv.Itoa(i)] = aws.String(f.LASTFILEOWNER)
		}
	}
	return other
}

func (a App) process(processes []types.Process) map[string]*string {
	other := make(map[string]*string)
	for i, p := range processes {
		if p.CMDLINE != "" {
			other["CMDLINE-"+strconv.Itoa(i)] = aws.String(p.CMDLINE)
		}
		if p.PROCESSSTARTTIME.String() != "" {
			other["PROCESS_START_TIME-"+strconv.Itoa(i)] = aws.String(p.PROCESSSTARTTIME.String())
		}
		if p.PROCESSID > 0 {
			other["PROCESS_ID-"+strconv.Itoa(i)] = aws.String(strconv.Itoa(p.PROCESSID))
		}
		if p.CPUPERCENTAGE >= 0 {
			other["CPU_PERCENTAGE-"+strconv.Itoa(i)] = aws.String(strconv.Itoa(p.CPUPERCENTAGE))
		}
	}
	return other
}

func (a App) getGenerator(category, source, eventType, eventModel string) string {
	return fmt.Sprintf("Category: %s - Source: %s - Type: %s - Model: %s", category, source, eventType, eventModel)
}
