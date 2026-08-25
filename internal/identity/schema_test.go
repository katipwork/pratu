package identity

import (
	"reflect"
	"testing"
)

func mustParse(t *testing.T) *Schema {
	t.Helper()
	s, err := ParseSchema("sid", "default", []byte(DefaultSchemaJSON))
	if err != nil {
		t.Fatalf("ParseSchema: %v", err)
	}
	return s
}

func TestValidateTraits(t *testing.T) {
	s := mustParse(t)

	if msgs := s.ValidateTraits([]byte(`{"email":"alice@example.com","name":"Alice"}`)); msgs != nil {
		t.Errorf("valid traits rejected: %v", msgs)
	}
	for name, traits := range map[string]string{
		"missing email":    `{"name":"Alice"}`,
		"bad email format": `{"email":"not-an-email"}`,
		"unknown property": `{"email":"alice@example.com","admin":true}`,
		"wrong type":       `{"email":42}`,
		"invalid json":     `{`,
	} {
		if msgs := s.ValidateTraits([]byte(traits)); msgs == nil {
			t.Errorf("%s: expected validation errors, got none", name)
		}
	}
}

func TestIdentifiers(t *testing.T) {
	s := mustParse(t)
	got := s.Identifiers([]byte(`{"email":"  Alice@Example.COM ","name":"Alice"}`))
	want := []string{"alice@example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Identifiers = %v, want %v", got, want)
	}
	if ids := s.Identifiers([]byte(`{"name":"Alice"}`)); ids != nil {
		t.Errorf("Identifiers without email = %v, want none", ids)
	}
}

func TestAddresses(t *testing.T) {
	s := mustParse(t)
	got := s.Addresses([]byte(`{"email":" Alice@Example.COM ","name":"Alice"}`))
	want := []AddressSpec{{Channel: ChannelEmail, Value: "alice@example.com", Verification: true, Recovery: true}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Addresses = %v, want %v", got, want)
	}

	if _, err := ParseSchema("sid", "bad", []byte(
		`{"type":"object","properties":{"x":{"type":"string","pratu":{"verification":{"via":"pigeon"}}}}}`,
	)); err == nil {
		t.Error("expected error for unknown address channel")
	}
	if _, err := ParseSchema("sid", "bad", []byte(
		`{"type":"object","properties":{"x":{"type":"string","pratu":{"verification":{"via":"email"},"recovery":{"via":"sms"}}}}}`,
	)); err == nil {
		t.Error("expected error for conflicting channels on one property")
	}
}

func TestFields(t *testing.T) {
	s := mustParse(t)
	want := []Field{
		{Name: "email", Type: "string", Title: "Email", Required: true},
		{Name: "name", Type: "string", Title: "Name", Required: false},
	}
	if !reflect.DeepEqual(s.Fields(), want) {
		t.Errorf("Fields = %+v, want %+v", s.Fields(), want)
	}
}

func TestParseSchemaRejectsInvalid(t *testing.T) {
	if _, err := ParseSchema("sid", "bad", []byte(`{"type": 42}`)); err == nil {
		t.Error("expected error for invalid schema")
	}
}
