package types

import "time"

type Config struct {
	DefaultAccount string
	Instance       string
	EventMap       map[string]string
}

type LaceworkEvent struct {
	Version    string    `json:"version"`
	ID         string    `json:"id"`
	DetailType string    `json:"detail-type"`
	Source     string    `json:"source"`
	Account    string    `json:"account"`
	Time       time.Time `json:"time"`
	Region     string    `json:"region"`
	Resources  []string  `json:"resources"`
	Detail     Detail    `json:"detail"`
}

type Cve struct {
	FeatureName string `json:"FEATURE_NAME"`
	CveID       string `json:"CVE_ID"`
	Info        string `json:"INFO"`
	Severity    int    `json:"SEVERITY"`
}

type Customrule struct {
	LastUpdatedTime time.Time `json:"LAST_UPDATED_TIME"`
	LastUpdatedUser string    `json:"LAST_UPDATED_USER"`
	DisplayFilter   string    `json:"DISPLAY_FILTER"`
	RuleGUID        string    `json:"RULE_GUID"`
}

type Imageid struct {
	ImageTag        []string `json:"IMAGE_TAG"`
	Cve             []string `json:"CVE"`
	ImageID         string   `json:"IMAGE_ID"`
	ImageRepo       string   `json:"IMAGE_REPO"`
	ImagePrivileged int      `json:"IMAGE_PRIVILEGED"`
	ImageActive     int      `json:"IMAGE_ACTIVE"`
}

type Imagefeature struct {
	Cve              []string `json:"CVE"`
	FeatureName      string   `json:"FEATURE_NAME"`
	FeatureNamespace string   `json:"FEATURE_NAMESPACE"`
	FixedVersion     string   `json:"FIXED_VERSION"`
}

type CtUser struct {
	AccountID   string   `json:"ACCOUNT_ID"`
	RegionList  []string `json:"REGION_LIST"`
	Username    string   `json:"USERNAME"`
	Mfa         int      `json:"MFA"`
	APIList     []string `json:"API_LIST"`
	PrincipalID string   `json:"PRINCIPAL_ID"`
}

type Region struct {
	AccountList []string `json:"ACCOUNT_LIST"`
	Region      string   `json:"REGION"`
}

type API struct {
	Service string `json:"SERVICE"`
	API     string `json:"API"`
}

type Resource struct {
	Value string `json:"VALUE"`
	Name  string `json:"NAME"`
}

type Rule struct {
	RuleTitle       string `json:"RULES_TITLE"`
	RuleID          string `json:"RULE_ID"`
	RuleDescription string `json:"RULE_DESCRIPTION"`
	RuleSeverity    int    `json:"RULE_SEVERITY"`
}

type Sourceipaddress struct {
	IPAddress string `json:"IP_ADDRESS"`
}

type Machine struct {
	ExternalIP     string  `json:"EXTERNAL_IP"`
	Hostname       string  `json:"HOSTNAME"`
	Mid            int     `json:"MID"`
	IsExternal     int     `json:"IS_EXTERNAL"`
	CPUPercentage  float64 `json:"CPU_PERCENTAGE"`
	InternalIPAddr string  `json:"INTERNAL_IP_ADDR"`
	InstanceID     string  `json:"INSTANCE_ID"`
}

type NewViolation struct {
	RecID    string `json:"REC_ID"`
	Reason   string `json:"REASON"`
	Resource string `json:"RESOURCE"`
}

type EntityMap struct {
	Cve             []Cve             `json:"Cve,omitempty"`
	Customrule      []Customrule      `json:"CustomRule,omitempty"`
	Imageid         []Imageid         `json:"ImageId,omitempty"`
	Imagefeature    []Imagefeature    `json:"ImageFeature,omitempty"`
	CtUser          []CtUser          `json:"CT_User,omitempty"`
	Region          []Region          `json:"Region,omitempty"`
	API             []API             `json:"API,omitempty"`
	Sourceipaddress []Sourceipaddress `json:"SourceIpAddress,omitempty"`
	Machine         []Machine         `json:"Machine,omitempty"`
	Resource        []Resource        `json:"Resource,omitempty"`
	RulesTriggered  []Rule            `json:"RulesTriggered,omitempty"`
	NewViolation    []NewViolation    `json:"NewViolation,omitempty"`
}

type Data struct {
	StartTime  time.Time `json:"START_TIME"`
	EndTime    time.Time `json:"END_TIME"`
	EventModel string    `json:"EVENT_MODEL"`
	EventType  string    `json:"EVENT_TYPE"`
	EntityMap  EntityMap `json:"ENTITY_MAP"`
	EventActor string    `json:"EVENT_ACTOR"`
	EventID    string    `json:"EVENT_ID"`
}

type EventDetails struct {
	Data []Data `json:"data"`
}

type Detail struct {
	EventID       string       `json:"EVENT_ID"`
	EventName     string       `json:"EVENT_NAME"`
	EventType     string       `json:"EVENT_TYPE"`
	Summary       string       `json:"SUMMARY"`
	StartTime     string       `json:"START_TIME"`
	EventCategory string       `json:"EVENT_CATEGORY"`
	Link          string       `json:"LINK"`
	EventDetails  EventDetails `json:"EVENT_DETAILS"`
	Severity      int          `json:"SEVERITY"`
	Account       string       `json:"ACCOUNT"`
	Source        string       `json:"SOURCE"`
}
