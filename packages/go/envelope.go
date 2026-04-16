package aegirsecurity

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
)

// TrustCoreAlgorithmDescriptor describes the trust-core algorithm used to sign an envelope.
type TrustCoreAlgorithmDescriptor struct {
	AlgorithmID string `json:"algorithmId"`
	Hybrid      bool   `json:"hybrid"`
}

// TrustCoreSignatureEnvelope carries trust-core signature metadata for a safe envelope.
type TrustCoreSignatureEnvelope struct {
	KeyID          string                       `json:"keyId"`
	Algorithm      TrustCoreAlgorithmDescriptor `json:"algorithm"`
	SignatureBytes []byte                       `json:"signatureBytes"`
}

// SafeEnvelopeRecord provides the Beta-1 safe-envelope contract for portable signed payloads.
type SafeEnvelopeRecord struct {
	EnvelopeID       string                      `json:"envelopeId"`
	PayloadType      string                      `json:"payloadType"`
	CanonicalPayload string                      `json:"canonicalPayload"`
	PayloadHash      string                      `json:"payloadHash"`
	CreatedAtUTC     string                      `json:"createdAtUtc"`
	SignatureEnvelope *TrustCoreSignatureEnvelope `json:"signatureEnvelope,omitempty"`
}

// SafeEnvelopeValidationResult reports whether the supplied safe envelope is valid.
type SafeEnvelopeValidationResult struct {
	IsValid bool   `json:"isValid"`
	Reason  string `json:"reason"`
}

// CreateSafeEnvelope creates a deterministic safe envelope for the supplied payload.
func CreateSafeEnvelope(payloadType, canonicalPayload string, signatureEnvelope *TrustCoreSignatureEnvelope) (*SafeEnvelopeRecord, error) {
	if payloadType == "" {
		return nil, errors.New("payload type is required")
	}

	if canonicalPayload == "" {
		return nil, errors.New("canonical payload is required")
	}

	return &SafeEnvelopeRecord{
		EnvelopeID:       generateRuntimeID("env"),
		PayloadType:      payloadType,
		CanonicalPayload: canonicalPayload,
		PayloadHash:      computePayloadHash(canonicalPayload),
		CreatedAtUTC:     time.Now().UTC().Format(time.RFC3339),
		SignatureEnvelope: signatureEnvelope,
	}, nil
}

// ValidateSafeEnvelope validates the payload hash and minimal signature presence rules.
func ValidateSafeEnvelope(envelope SafeEnvelopeRecord) SafeEnvelopeValidationResult {
	if envelope.PayloadHash != computePayloadHash(envelope.CanonicalPayload) {
		return SafeEnvelopeValidationResult{
			IsValid: false,
			Reason:  "payload_hash_mismatch",
		}
	}

	if envelope.SignatureEnvelope != nil && len(envelope.SignatureEnvelope.SignatureBytes) == 0 {
		return SafeEnvelopeValidationResult{
			IsValid: false,
			Reason:  "signature_missing",
		}
	}

	return SafeEnvelopeValidationResult{
		IsValid: true,
		Reason:  "valid",
	}
}

func SignChallengePayload(payload []byte) []byte {
	return signPayload(payload, 13, 83)
}

func VerifyChallengePayload(payload []byte, signature []byte) bool {
	return verifyPayload(payload, signature, 13, 83)
}

func SignProofReceiptPayload(payload []byte) []byte {
	return signPayload(payload, 29, 107)
}

func VerifyProofReceiptPayload(payload []byte, signature []byte) bool {
	return verifyPayload(payload, signature, 29, 107)
}

func SignIdentityTokenPayload(payload []byte) []byte {
	return signPayload(payload, 41, 149)
}

func VerifyIdentityTokenPayload(payload []byte, signature []byte) bool {
	return verifyPayload(payload, signature, 41, 149)
}

func computePayloadHash(canonicalPayload string) string {
	hash := sha256.Sum256([]byte(canonicalPayload))
	return hex.EncodeToString(hash[:])
}

func generateRuntimeID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UTC().UnixNano())
}

func signPayload(payload []byte, classicalMultiplier uint8, pqcMultiplier uint8) []byte {
	classical := computeDigest(payload, classicalMultiplier)
	pqc := computeDigest(payload, pqcMultiplier)
	signature := make([]byte, 64)
	copy(signature[:32], classical[:])
	copy(signature[32:], pqc[:])
	return signature
}

func verifyPayload(payload []byte, signature []byte, classicalMultiplier uint8, pqcMultiplier uint8) bool {
	if len(signature) < 64 {
		return false
	}

	expected := signPayload(payload, classicalMultiplier, pqcMultiplier)
	for index := 0; index < 64; index++ {
		if signature[index] != expected[index] {
			return false
		}
	}

	return true
}

func computeDigest(payload []byte, multiplier uint8) [32]byte {
	var state [32]byte

	if len(payload) == 0 {
		panic("payload is required")
	}

	for index := 0; index < 32; index++ {
		payloadByte := payload[index%len(payload)]
		state[index] = payloadByte ^ byte(multiplier*uint8(index+1))
	}

	for index, payloadByte := range payload {
		slot := index % 32
		rotated := rotateLeft(payloadByte, uint(index%8))
		state[slot] = byte((uint16(state[slot])+uint16(rotated))*uint16(byte(multiplier+uint8(slot|1))))
		mirror := 31 - slot
		state[mirror] ^= byte(uint16(payloadByte) * uint16(multiplier^byte(index+17)))
	}

	for round := 0; round < 6; round++ {
		for slot := 0; slot < 32; slot++ {
			next := state[(slot+1)%32]
			previous := state[(slot+31)%32]
			state[slot] = byte((uint16(state[slot]+rotateLeft(next, 1)) & 0xff) ^ uint16(previous+multiplier+uint8(round)+uint8(slot)))
		}
	}

	return state
}

func rotateLeft(value byte, amount uint) byte {
	return byte((value << amount) | (value >> (8 - amount)))
}
