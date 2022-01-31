package lacework

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type PostHoneycombRequest struct {
	Account         string `json:"account"`
	SubAccount      string `json:"sub-account"`
	TechPartner     string `json:"tech-partner"`
	IntegrationName string `json:"integration-name"`
	Version         string `json:"version"`
	Service         string `json:"service"`
	InstallMethod   string `json:"install-method"`
	Function        string `json:"function"`
	Event           string `json:"event"`
	EventData       string `json:"event-data"`
}

func SendHoneycombEvent(account string, event string, subAccountName string, build string, eventData string) {
	if eventData == "" {
		eventData = "{}"
	}
	requestPayload := PostHoneycombRequest{
		Account:         account,
		SubAccount:      subAccountName,
		TechPartner:     "AWS",
		IntegrationName: "lacework-aws-security-hub-terraform",
		Version:         build,
		Service:         "AWS Security Hub",
		InstallMethod:   "terraform",
		Function:        "setup",
		Event:           event,
		EventData:       eventData,
	}
	if payloadBytes, err := json.Marshal(requestPayload); err == nil {
		if request, err := http.NewRequest(http.MethodPost, "https://api.honeycomb.io/1/events/$DATASET", bytes.NewBuffer(payloadBytes)); err == nil {
			request.Header.Add("X-Honeycomb-Team", "$HONEY_KEY")
			request.Header.Add("content-type", "application/json")
			if resp, err := http.DefaultClient.Do(request); err == nil {
				fmt.Printf("Set event to Honeycomb: %s %d", event, resp.StatusCode)
			} else {
				fmt.Printf("Unable to send event to Honeycomb: %s", err)
			}
		}
	}
}
