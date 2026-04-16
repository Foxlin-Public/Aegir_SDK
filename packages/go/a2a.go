package aegirsecurity

import (
	"errors"
	"sort"
	"sync"
	"time"
)

// AgentToAgentMessageRecord is the Beta-1 point-to-point A2A message contract.
type AgentToAgentMessageRecord struct {
	MessageID        string             `json:"messageId"`
	SenderAgentID    string             `json:"senderAgentId"`
	RecipientAgentID string             `json:"recipientAgentId"`
	MessageType      string             `json:"messageType"`
	CorrelationID    string             `json:"correlationId"`
	Envelope         SafeEnvelopeRecord `json:"envelope"`
	SentAtUTC        string             `json:"sentAtUtc"`
	ReceivedAtUTC    *string            `json:"receivedAtUtc,omitempty"`
}

// AgentToAgentReceiveResult reports whether a message was accepted.
type AgentToAgentReceiveResult struct {
	Accepted bool                     `json:"accepted"`
	Reason   string                   `json:"reason"`
	Message  *AgentToAgentMessageRecord `json:"message,omitempty"`
}

// InMemoryAgentToAgentProtocol is the Beta-1 in-memory A2A runtime for the Go binding.
type InMemoryAgentToAgentProtocol struct {
	mutex  sync.Mutex
	inbox  map[string][]AgentToAgentMessageRecord
}

// NewInMemoryAgentToAgentProtocol creates an empty in-memory A2A protocol runtime.
func NewInMemoryAgentToAgentProtocol() *InMemoryAgentToAgentProtocol {
	return &InMemoryAgentToAgentProtocol{
		inbox: make(map[string][]AgentToAgentMessageRecord),
	}
}

// Send stores a message for the recipient agent after wrapping it in a safe envelope.
func (p *InMemoryAgentToAgentProtocol) Send(senderAgentID, recipientAgentID, messageType, canonicalPayload string, correlationID *string, signatureEnvelope *TrustCoreSignatureEnvelope) (*AgentToAgentMessageRecord, error) {
	if senderAgentID == "" {
		return nil, errors.New("sender agent id is required")
	}

	if recipientAgentID == "" {
		return nil, errors.New("recipient agent id is required")
	}

	if messageType == "" {
		return nil, errors.New("message type is required")
	}

	envelope, err := CreateSafeEnvelope("agent:"+messageType, canonicalPayload, signatureEnvelope)
	if err != nil {
		return nil, err
	}

	resolvedCorrelationID := generateRuntimeID("corr")
	if correlationID != nil && *correlationID != "" {
		resolvedCorrelationID = *correlationID
	}

	message := AgentToAgentMessageRecord{
		MessageID:        generateRuntimeID("msg"),
		SenderAgentID:    senderAgentID,
		RecipientAgentID: recipientAgentID,
		MessageType:      messageType,
		CorrelationID:    resolvedCorrelationID,
		Envelope:         *envelope,
		SentAtUTC:        time.Now().UTC().Format(time.RFC3339),
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.inbox[recipientAgentID] = append(p.inbox[recipientAgentID], message)
	return &message, nil
}

// GetInbox returns the recipient inbox ordered by sent time.
func (p *InMemoryAgentToAgentProtocol) GetInbox(recipientAgentID string) []AgentToAgentMessageRecord {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	items := append([]AgentToAgentMessageRecord(nil), p.inbox[recipientAgentID]...)
	sort.Slice(items, func(i, j int) bool {
		return items[i].SentAtUTC < items[j].SentAtUTC
	})
	return items
}

// Receive validates the stored safe envelope and marks the message as received when valid.
func (p *InMemoryAgentToAgentProtocol) Receive(recipientAgentID, messageID string) AgentToAgentReceiveResult {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	for idx, message := range p.inbox[recipientAgentID] {
		if message.MessageID != messageID {
			continue
		}

		validation := ValidateSafeEnvelope(message.Envelope)
		if !validation.IsValid {
			return AgentToAgentReceiveResult{
				Accepted: false,
				Reason:   validation.Reason,
				Message:  &message,
			}
		}

		receivedAtUTC := time.Now().UTC().Format(time.RFC3339)
		message.ReceivedAtUTC = &receivedAtUTC
		p.inbox[recipientAgentID][idx] = message
		return AgentToAgentReceiveResult{
			Accepted: true,
			Reason:   "accepted",
			Message:  &message,
		}
	}

	return AgentToAgentReceiveResult{
		Accepted: false,
		Reason:   "message_not_found",
	}
}
