package aegirsecurity

import "testing"

func TestAgentToAgentSendStoresMessage(t *testing.T) {
	protocol := NewInMemoryAgentToAgentProtocol()

	message, err := protocol.Send("agent_a", "agent_b", "kyc.result", `{"status":"pass"}`, nil, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	inbox := protocol.GetInbox("agent_b")
	if len(inbox) != 1 {
		t.Fatalf("expected 1 message, got %d", len(inbox))
	}
	if inbox[0].MessageID != message.MessageID {
		t.Fatalf("expected stored message id %s, got %s", message.MessageID, inbox[0].MessageID)
	}
}

func TestAgentToAgentReceiveAcceptsUntamperedMessage(t *testing.T) {
	protocol := NewInMemoryAgentToAgentProtocol()

	message, err := protocol.Send("agent_a", "agent_b", "kyc.result", `{"status":"pass"}`, nil, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	result := protocol.Receive("agent_b", message.MessageID)
	if !result.Accepted {
		t.Fatalf("expected accepted result, got %s", result.Reason)
	}
	if result.Message == nil || result.Message.ReceivedAtUTC == nil {
		t.Fatalf("expected received timestamp to be set")
	}
}

func TestAgentToAgentReceiveRejectsTamperedMessage(t *testing.T) {
	protocol := NewInMemoryAgentToAgentProtocol()

	message, err := protocol.Send("agent_a", "agent_b", "kyc.result", `{"status":"pass"}`, nil, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	protocol.inbox["agent_b"][0].Envelope.CanonicalPayload = `{"status":"fail"}`
	result := protocol.Receive("agent_b", message.MessageID)
	if result.Accepted {
		t.Fatalf("expected rejected result")
	}
	if result.Reason != "payload_hash_mismatch" {
		t.Fatalf("expected payload_hash_mismatch, got %s", result.Reason)
	}
}
