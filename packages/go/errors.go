package aegirsecurity

import "fmt"

type AegirSecurityError struct {
	Status        int
	Code          string
	CorrelationID string
	Body          string
}

func (e *AegirSecurityError) Error() string {
	return fmt.Sprintf("Aegir request failed with status %d.", e.Status)
}
