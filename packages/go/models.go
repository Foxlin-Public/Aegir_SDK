package aegirsecurity

type IdentityGraphScores struct {
	ExposureScore          float64 `json:"exposureScore"`
	TrustScore             float64 `json:"trustScore"`
	ConnectionClarityScore float64 `json:"connectionClarityScore"`
}

type IdentityGraphNode struct {
	NodeID            string              `json:"nodeId"`
	NodeType          string              `json:"nodeType"`
	DisplayName       string              `json:"displayName"`
	Status            string              `json:"status"`
	TrustTier         string              `json:"trustTier"`
	ObservedAtUTC     string              `json:"observedAtUtc"`
	LastVerifiedAtUTC *string             `json:"lastVerifiedAtUtc"`
	Metadata          map[string]*string  `json:"metadata"`
}

type IdentityGraphEdge struct {
	EdgeID            string              `json:"edgeId"`
	EdgeType          string              `json:"edgeType"`
	FromNodeID        string              `json:"fromNodeId"`
	ToNodeID          string              `json:"toNodeId"`
	Status            string              `json:"status"`
	TrustWeight       float64             `json:"trustWeight"`
	EvidenceType      string              `json:"evidenceType"`
	Reason            string              `json:"reason"`
	ObservedAtUTC     string              `json:"observedAtUtc"`
	LastVerifiedAtUTC *string             `json:"lastVerifiedAtUtc"`
	Metadata          map[string]*string  `json:"metadata"`
}

type IdentityGraphSnapshot struct {
	GraphID        string               `json:"graphId"`
	GeneratedAtUTC string               `json:"generatedAtUtc"`
	Scores         IdentityGraphScores  `json:"scores"`
	Nodes          []IdentityGraphNode  `json:"nodes"`
	Edges          []IdentityGraphEdge  `json:"edges"`
	Metadata       map[string]*string   `json:"metadata"`
}

type ExposureFinding struct {
	FindingID string             `json:"findingId"`
	Category  string             `json:"category"`
	Severity  string             `json:"severity"`
	Summary   string             `json:"summary"`
	NodeID    *string            `json:"nodeId"`
	EdgeID    *string            `json:"edgeId"`
	Metadata  map[string]*string `json:"metadata"`
}

type ExposureSummary struct {
	GraphID        string            `json:"graphId"`
	GeneratedAtUTC string            `json:"generatedAtUtc"`
	ExposureScore  float64           `json:"exposureScore"`
	Findings       []ExposureFinding `json:"findings"`
	SummaryText    string            `json:"summaryText"`
}

type PerformIdentityActionRequest struct {
	SubjectID    string  `json:"subjectId"`
	ActionType   string  `json:"actionType"`
	TargetNodeID *string `json:"targetNodeId,omitempty"`
	Reason       *string `json:"reason,omitempty"`
}

type IdentityActionRecord struct {
	ActionID       string             `json:"actionId"`
	SubjectID      string             `json:"subjectId"`
	ActionType     string             `json:"actionType"`
	Status         string             `json:"status"`
	TargetNodeID   *string            `json:"targetNodeId"`
	Reason         *string            `json:"reason"`
	RequestedAtUTC string             `json:"requestedAtUtc"`
	ReversedAtUTC  *string            `json:"reversedAtUtc"`
	ReverseReason  *string            `json:"reverseReason"`
	Metadata       map[string]*string `json:"metadata"`
}

type ScanIdentityResult struct {
	SubjectID     string                 `json:"subjectId"`
	Graph         IdentityGraphSnapshot  `json:"graph"`
	Exposure      ExposureSummary        `json:"exposure"`
	ActionHistory []IdentityActionRecord `json:"actionHistory"`
}

type BudgetEnvelope struct {
	ControlType        string `json:"controlType"`
	SubjectKey         string `json:"subjectKey"`
	WindowStartedAtUTC string `json:"windowStartedAtUtc"`
	WindowEndsAtUTC    string `json:"windowEndsAtUtc"`
	Limit              int    `json:"limit"`
	Consumed           int    `json:"consumed"`
	Remaining          int    `json:"remaining"`
	IsExhausted        bool   `json:"isExhausted"`
}
