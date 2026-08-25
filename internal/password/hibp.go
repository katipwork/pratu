package password

import (
	"bufio"
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultHIBPBaseURL is the Pwned Passwords range API.
const DefaultHIBPBaseURL = "https://api.pwnedpasswords.com/range/"

// HIBP checks passwords against the Pwned Passwords corpus using the
// k-anonymity range API: only the first five hex characters of the SHA-1
// ever leave the process.
type HIBP struct {
	baseURL string
	client  *http.Client
}

func NewHIBP(baseURL string) *HIBP {
	if baseURL == "" {
		baseURL = DefaultHIBPBaseURL
	}
	if !strings.HasSuffix(baseURL, "/") {
		baseURL += "/"
	}
	// The timeout doubles as the fail-open bound: a slow corpus mirror
	// delays registration by at most this much.
	return &HIBP{baseURL: baseURL, client: &http.Client{Timeout: 3 * time.Second}}
}

func (h *HIBP) BreachCount(ctx context.Context, candidate string) (int, error) {
	sum := fmt.Sprintf("%X", sha1.Sum([]byte(candidate)))
	prefix, suffix := sum[:5], sum[5:]

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.baseURL+prefix, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "pratu")
	req.Header.Set("Add-Padding", "true") // response includes decoy zero-count rows

	resp, err := h.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("pwned passwords range API returned %s", resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		rest, ok := strings.CutPrefix(line, suffix+":")
		if !ok {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(rest))
		if err != nil {
			return 0, fmt.Errorf("malformed range API line %q: %w", line, err)
		}
		return count, nil
	}
	return 0, scanner.Err()
}
