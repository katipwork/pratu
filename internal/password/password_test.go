package password

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeChecker struct {
	count int
	err   error
}

func (f fakeChecker) BreachCount(context.Context, string) (int, error) { return f.count, f.err }

func TestValidate(t *testing.T) {
	ctx := context.Background()
	pol := Policy{MinLength: 10, BreachCheck: true}

	cases := []struct {
		name      string
		pw        string
		pol       Policy
		checker   BreachChecker
		wantMsgs  bool
		wantCheck bool // non-nil checkErr
	}{
		{"ok", "a-fine-password", pol, fakeChecker{}, false, false},
		{"too short", "short", pol, fakeChecker{}, true, false},
		{"length counts runes not bytes", "ปีศาจรหัสผ่าน", pol, fakeChecker{}, false, false},
		{"too long", strings.Repeat("a", MaxLength+1), pol, fakeChecker{}, true, false},
		{"breached", "a-fine-password", pol, fakeChecker{count: 42}, true, false},
		{"checker down fails open", "a-fine-password", pol, fakeChecker{err: errors.New("down")}, false, true},
		{"breach check disabled", "a-fine-password", Policy{MinLength: 10}, fakeChecker{count: 42}, false, false},
		{"zero min uses default", strings.Repeat("a", DefaultMinLength-1), Policy{}, nil, true, false},
	}
	for _, c := range cases {
		msgs, checkErr := Validate(ctx, c.pw, c.pol, c.checker)
		if (msgs != nil) != c.wantMsgs {
			t.Errorf("%s: violations = %v, want present=%v", c.name, msgs, c.wantMsgs)
		}
		if (checkErr != nil) != c.wantCheck {
			t.Errorf("%s: checkErr = %v, want present=%v", c.name, checkErr, c.wantCheck)
		}
	}
}
