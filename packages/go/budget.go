package aegirsecurity

import (
	"fmt"
	"strings"
	"time"
)

type BudgetExhaustedError struct {
	Envelope BudgetEnvelope
}

func (e *BudgetExhaustedError) Error() string {
	return fmt.Sprintf("Budget exhausted for %s on '%s'.", e.Envelope.ControlType, e.Envelope.SubjectKey)
}

type InMemoryBudgetEnvelopeService struct {
	window time.Duration
	limits map[string]int
	state  map[string]budgetCounterState
}

type budgetCounterState struct {
	windowStartedAt time.Time
	consumed        int
}

func NewInMemoryBudgetEnvelopeService() *InMemoryBudgetEnvelopeService {
	return &InMemoryBudgetEnvelopeService{
		window: time.Minute,
		limits: map[string]int{
			"IdentityScan":           10,
			"ExternalLookup":         5,
			"ConnectionGraphRebuild": 3,
		},
		state: make(map[string]budgetCounterState),
	}
}

func (s *InMemoryBudgetEnvelopeService) GetEnvelope(controlType, subjectKey string) BudgetEnvelope {
	key := buildBudgetKey(controlType, subjectKey)
	current, ok := s.state[key]
	if !ok {
		current = budgetCounterState{windowStartedAt: time.Now().UTC(), consumed: 0}
	}
	return s.toEnvelope(controlType, strings.TrimSpace(subjectKey), current)
}

func (s *InMemoryBudgetEnvelopeService) Consume(controlType, subjectKey string) (BudgetEnvelope, error) {
	key := buildBudgetKey(controlType, subjectKey)
	now := time.Now().UTC()
	current, ok := s.state[key]
	if !ok || now.Sub(current.windowStartedAt) >= s.window {
		current = budgetCounterState{windowStartedAt: now, consumed: 0}
	}

	current.consumed++
	s.state[key] = current

	envelope := s.toEnvelope(controlType, strings.TrimSpace(subjectKey), current)
	if current.consumed > envelope.Limit {
		return envelope, &BudgetExhaustedError{Envelope: envelope}
	}

	return envelope, nil
}

func (s *InMemoryBudgetEnvelopeService) toEnvelope(controlType, subjectKey string, state budgetCounterState) BudgetEnvelope {
	limit := s.limits[controlType]
	remaining := limit - state.consumed
	if remaining < 0 {
		remaining = 0
	}

	return BudgetEnvelope{
		ControlType:        controlType,
		SubjectKey:         subjectKey,
		WindowStartedAtUTC: state.windowStartedAt.Format(time.RFC3339),
		WindowEndsAtUTC:    state.windowStartedAt.Add(s.window).Format(time.RFC3339),
		Limit:              limit,
		Consumed:           state.consumed,
		Remaining:          remaining,
		IsExhausted:        state.consumed >= limit,
	}
}

func buildBudgetKey(controlType, subjectKey string) string {
	trimmed := strings.TrimSpace(subjectKey)
	if trimmed == "" {
		panic("subjectKey is required")
	}

	return controlType + ":" + trimmed
}
