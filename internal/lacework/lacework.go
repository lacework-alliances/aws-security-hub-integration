package lacework

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/lacework-alliances/aws-security-hub-integration/pkg/types"
	"net/http"
)

const (
	techPartner     = "AWS"
	integrationName = "lacework-aws-security-hub"
	service         = "AWS Security Hub"
	installMethod   = "terraform"
)

func SendHoneycombEvent(account, event, subAccountName, version, eventData, f string, honeyKey string, honeyDataset string) {
	if eventData == "" {
		eventData = "{}"
	}

	requestPayload := types.Honeyvent{
		Account:         account,
		SubAccount:      subAccountName,
		TechPartner:     techPartner,
		IntegrationName: integrationName,
		Version:         version,
		Service:         service,
		InstallMethod:   installMethod,
		Function:        f,
		Event:           event,
		EventData:       eventData,
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		url := fmt.Sprintf("https://api.honeycomb.io/1/events/%s", honeyDataset)
		if request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(payloadBytes)); err == nil {
			request.Header.Add("X-Honeycomb-Team", honeyKey)
			request.Header.Add("content-type", "application/json")
			if resp, err := http.DefaultClient.Do(request); err == nil {
				fmt.Printf("Sent event to Honeycomb: %s %d\n", event, resp.StatusCode)
			} else {
				fmt.Printf("Unable to send event to Honeycomb: %s\n", err)
			}
		}
	}
}
