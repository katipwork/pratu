// Package identity holds identities and the per-tenant Identity Schemas
// (JSON Schema) that validate their traits. Schema annotations under the
// "pratu" keyword declare which traits act as login identifiers.
package identity

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

var errPrinter = message.NewPrinter(language.English)

// DefaultSchemaJSON seeds every new tenant: email as the login identifier,
// optional display name.
const DefaultSchemaJSON = `{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "email": {
      "type": "string",
      "format": "email",
      "title": "Email",
      "pratu": {
        "identifier": true,
        "verification": {"via": "email"},
        "recovery": {"via": "email"}
      }
    },
    "name": {
      "type": "string",
      "title": "Name"
    }
  },
  "required": ["email"],
  "additionalProperties": false
}`

// Field describes one top-level trait for flow UIs.
type Field struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Title    string `json:"title,omitempty"`
	Required bool   `json:"required"`
}

// Schema is a compiled Identity Schema.
type Schema struct {
	ID          string
	Name        string
	Raw         json.RawMessage
	compiled    *jsonschema.Schema
	identifiers []string // top-level property names annotated as identifiers
	addresses   []addressProp
	fields      []Field
}

type addressProp struct {
	prop         string
	via          string // 'email' | 'sms'
	verification bool
	recovery     bool
}

// ParseSchema compiles the raw JSON Schema and extracts the pratu
// annotations. Only top-level properties may be identifiers for now.
func ParseSchema(id, name string, raw []byte) (*Schema, error) {
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("identity schema %s: %w", name, err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource("schema.json", doc); err != nil {
		return nil, fmt.Errorf("identity schema %s: %w", name, err)
	}
	compiled, err := c.Compile("schema.json")
	if err != nil {
		return nil, fmt.Errorf("identity schema %s: %w", name, err)
	}

	var meta struct {
		Properties map[string]struct {
			Type  string `json:"type"`
			Title string `json:"title"`
			Pratu struct {
				Identifier   bool `json:"identifier"`
				Verification struct {
					Via string `json:"via"`
				} `json:"verification"`
				Recovery struct {
					Via string `json:"via"`
				} `json:"recovery"`
			} `json:"pratu"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, fmt.Errorf("identity schema %s: %w", name, err)
	}
	required := make(map[string]bool, len(meta.Required))
	for _, r := range meta.Required {
		required[r] = true
	}

	s := &Schema{ID: id, Name: name, Raw: raw, compiled: compiled}
	for prop, p := range meta.Properties {
		if p.Pratu.Identifier {
			s.identifiers = append(s.identifiers, prop)
		}
		vVia, rVia := p.Pratu.Verification.Via, p.Pratu.Recovery.Via
		if vVia != "" && rVia != "" && vVia != rVia {
			return nil, fmt.Errorf("identity schema %s: property %s: verification and recovery declare different channels",
				name, prop)
		}
		if via := cmp.Or(vVia, rVia); via != "" {
			if via != ChannelEmail && via != ChannelSMS {
				return nil, fmt.Errorf("identity schema %s: property %s: address channel %q is not %q or %q",
					name, prop, via, ChannelEmail, ChannelSMS)
			}
			s.addresses = append(s.addresses, addressProp{
				prop:         prop,
				via:          via,
				verification: vVia != "",
				recovery:     rVia != "",
			})
		}
		s.fields = append(s.fields, Field{
			Name:     prop,
			Type:     p.Type,
			Title:    p.Title,
			Required: required[prop],
		})
	}
	sort.Strings(s.identifiers)
	sort.Slice(s.addresses, func(i, j int) bool { return s.addresses[i].prop < s.addresses[j].prop })
	sort.Slice(s.fields, func(i, j int) bool { return s.fields[i].Name < s.fields[j].Name })
	return s, nil
}

// ValidateTraits checks traits against the schema, returning one message
// per violation.
func (s *Schema) ValidateTraits(traits []byte) []string {
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(traits))
	if err != nil {
		return []string{"traits: invalid JSON"}
	}
	err = s.compiled.Validate(v)
	if err == nil {
		return nil
	}
	var ve *jsonschema.ValidationError
	if !errors.As(err, &ve) {
		return []string{err.Error()}
	}
	var msgs []string
	for _, cause := range leafCauses(ve) {
		loc := "traits"
		if len(cause.InstanceLocation) > 0 {
			loc += "/" + strings.Join(cause.InstanceLocation, "/")
		}
		msgs = append(msgs, fmt.Sprintf("%s: %s", loc, cause.ErrorKind.LocalizedString(errPrinter)))
	}
	return msgs
}

// Identifiers extracts the normalized (trimmed, lowercased) values of all
// identifier-annotated traits.
func (s *Schema) Identifiers(traits []byte) []string {
	var m map[string]any
	if err := json.Unmarshal(traits, &m); err != nil {
		return nil
	}
	var out []string
	for _, prop := range s.identifiers {
		if v, ok := m[prop].(string); ok {
			if n := Normalize(v); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

// Addresses extracts the normalized values of all address-annotated
// traits, with the channel and purposes each carries.
func (s *Schema) Addresses(traits []byte) []AddressSpec {
	var m map[string]any
	if err := json.Unmarshal(traits, &m); err != nil {
		return nil
	}
	var out []AddressSpec
	for _, ap := range s.addresses {
		if v, ok := m[ap.prop].(string); ok {
			if n := Normalize(v); n != "" {
				out = append(out, AddressSpec{
					Channel:      ap.via,
					Value:        n,
					Verification: ap.verification,
					Recovery:     ap.recovery,
				})
			}
		}
	}
	return out
}

// Fields lists the top-level traits for building flow UIs.
func (s *Schema) Fields() []Field {
	return s.fields
}

// Normalize canonicalizes a login identifier for storage and lookup.
func Normalize(identifier string) string {
	return strings.ToLower(strings.TrimSpace(identifier))
}

func leafCauses(ve *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(ve.Causes) == 0 {
		return []*jsonschema.ValidationError{ve}
	}
	var out []*jsonschema.ValidationError
	for _, c := range ve.Causes {
		out = append(out, leafCauses(c)...)
	}
	return out
}
