package aegirsecurity

import "testing"

func TestBudgetEnvelopeConsumeDecrementsRemaining(t *testing.T) {
	service := NewInMemoryBudgetEnvelopeService()
	service.limits["IdentityScan"] = 2

	envelope, err := service.Consume("IdentityScan", "subject-1")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	if envelope.Consumed != 1 || envelope.Remaining != 1 || envelope.IsExhausted {
		t.Fatalf("unexpected envelope state: %+v", envelope)
	}
}

func TestBudgetEnvelopeConsumeReturnsExhaustedError(t *testing.T) {
	service := NewInMemoryBudgetEnvelopeService()
	service.limits["IdentityScan"] = 1

	if _, err := service.Consume("IdentityScan", "subject-1"); err != nil {
		t.Fatalf("expected initial consume to succeed, got %v", err)
	}

	envelope, err := service.Consume("IdentityScan", "subject-1")
	if err == nil {
		t.Fatal("expected error")
	}

	typed, ok := err.(*BudgetExhaustedError)
	if !ok {
		t.Fatalf("expected BudgetExhaustedError, got %T", err)
	}

	if !typed.Envelope.IsExhausted || envelope.Limit != 1 {
		t.Fatalf("unexpected exhausted envelope: %+v", typed.Envelope)
	}
}
