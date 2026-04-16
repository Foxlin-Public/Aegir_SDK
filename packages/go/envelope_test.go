package aegirsecurity

import "testing"

func TestCreateSafeEnvelopeAndValidate(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	result := ValidateSafeEnvelope(*envelope)
	if !result.IsValid {
		t.Fatalf("expected valid envelope, got %s", result.Reason)
	}
}

func TestValidateSafeEnvelopeDetectsTampering(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	envelope.CanonicalPayload = `{"hello":"tampered"}`
	result := ValidateSafeEnvelope(*envelope)
	if result.IsValid {
		t.Fatalf("expected invalid envelope")
	}
	if result.Reason != "payload_hash_mismatch" {
		t.Fatalf("expected payload_hash_mismatch, got %s", result.Reason)
	}
}

func TestValidateSafeEnvelopeDetectsMissingSignatureBytes(t *testing.T) {
	envelope, err := CreateSafeEnvelope("agent:test", `{"hello":"world"}`, &TrustCoreSignatureEnvelope{
		KeyID: "key_123",
		Algorithm: TrustCoreAlgorithmDescriptor{
			AlgorithmID: "hybrid-beta1",
			Hybrid:      true,
		},
		SignatureBytes: []byte{},
	})
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}

	result := ValidateSafeEnvelope(*envelope)
	if result.IsValid {
		t.Fatalf("expected invalid envelope")
	}
	if result.Reason != "signature_missing" {
		t.Fatalf("expected signature_missing, got %s", result.Reason)
	}
}

func TestIdentityTokenSignatureVerifiesAndFailsOnTampering(t *testing.T) {
	payload := []byte(`{"userId":"user-1","trustLevel":4}`)
	signature := SignIdentityTokenPayload(payload)

	if len(signature) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(signature))
	}
	if !VerifyIdentityTokenPayload(payload, signature) {
		t.Fatal("expected signature verification to pass")
	}
	if VerifyIdentityTokenPayload([]byte(`{"userId":"user-2","trustLevel":4}`), signature) {
		t.Fatal("expected tampered payload verification to fail")
	}
}
