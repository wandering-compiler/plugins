// Package brevo is the plugin's client of the Brevo API: the calls it makes
// (a batch of events, a contact upsert, update, listing and deletion, an
// attribute), paced to the account's rate limit.
package brevo

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MaxBatchEvents and MaxBatchBytes are Brevo's limits on one
// POST /events/batch: 200 events and 512 KB of body.
const (
	MaxBatchEvents = 200
	MaxBatchBytes  = 512 << 10
)

// Client calls one Brevo account.
type Client struct {
	base string
	key  string
	http *http.Client

	mu   sync.Mutex
	next time.Time // the earliest the next request may leave
	gap  time.Duration

	// sleep waits d or until ctx ends (replaced in tests).
	sleep func(ctx context.Context, d time.Duration) error
}

// New builds a client for base (https://api.brevo.com/v3) with key, sending
// at most rps requests per second.
func New(base, key string, rps int) (*Client, error) {
	if strings.TrimSpace(key) == "" {
		return nil, errors.New("brevo: an API key is required")
	}
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("brevo: base URL %q is not an http(s) URL", base)
	}
	if rps <= 0 {
		return nil, fmt.Errorf("brevo: requests per second must be positive, got %d", rps)
	}
	return &Client{
		base:  u.String(),
		key:   key,
		http:  &http.Client{Timeout: 30 * time.Second},
		gap:   time.Second / time.Duration(rps),
		sleep: sleepCtx,
	}, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// Error is a refusal Brevo answered.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("brevo: %d %s: %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("brevo: %d: %s", e.Status, e.Message)
}

// Retryable reports whether a call that failed with err may succeed later:
// the network, a rate limit, or Brevo's own failure. A 4xx other than 429
// fails the same way until something changes.
func Retryable(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status == http.StatusTooManyRequests || e.Status >= 500
	}
	return err != nil && !errors.Is(err, context.Canceled)
}

// Refused reports whether Brevo refused the call for what it said — a value
// it does not accept (400, 422) — so sending the same again is refused again,
// and the call is dropped rather than retried. Any other failure keeps it: a
// key Brevo does not know, or a server address the account does not allow
// (401, 403, "unrecognised IP address"), is fixed by its operator, and what
// was sent meanwhile must reach Brevo then, from the dead letters.
func Refused(err error) bool {
	var e *Error
	return errors.As(err, &e) && (e.Status == http.StatusBadRequest || e.Status == http.StatusUnprocessableEntity)
}

// Identifiers names the contact an event belongs to. The plugin keys contacts
// by the user's id (ext_id), which outlives an address change.
type Identifiers struct {
	ExtID string `json:"ext_id,omitempty"`
}

// Event is one event of a batch.
type Event struct {
	EventName         string         `json:"event_name"`
	EventDate         string         `json:"event_date,omitempty"`
	Identifiers       Identifiers    `json:"identifiers"`
	ContactProperties map[string]any `json:"contact_properties,omitempty"`
	EventProperties   map[string]any `json:"event_properties,omitempty"`
}

// BatchResult says which events of a batch Brevo refused, by index, with its
// reason. Empty when all were accepted.
type BatchResult struct {
	Failed map[int]string
}

// SendEvents posts one batch (at most MaxBatchEvents, MaxBatchBytes). A 207 is
// a partial success: the refused events are in the result, and the call does
// not fail.
func (c *Client) SendEvents(ctx context.Context, events []Event) (BatchResult, error) {
	if len(events) > MaxBatchEvents {
		return BatchResult{}, fmt.Errorf("brevo: %d events in one batch, at most %d", len(events), MaxBatchEvents)
	}
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return BatchResult{}, err
	}
	if len(body) > MaxBatchBytes {
		return BatchResult{}, fmt.Errorf("brevo: a batch of %d bytes, at most %d", len(body), MaxBatchBytes)
	}
	status, resp, err := c.do(ctx, http.MethodPost, "/events/batch", body)
	if err != nil {
		return BatchResult{}, err
	}
	if status != http.StatusMultiStatus {
		return BatchResult{}, nil
	}
	var partial struct {
		Errors []struct {
			EventIndex []int  `json:"eventIndex"`
			Message    string `json:"message"`
		} `json:"errors"`
	}
	if err := json.Unmarshal(resp, &partial); err != nil {
		return BatchResult{}, fmt.Errorf("brevo: a partial batch answer that does not parse: %w", err)
	}
	out := BatchResult{Failed: map[int]string{}}
	for _, e := range partial.Errors {
		for _, i := range e.EventIndex {
			out.Failed[i] = e.Message
		}
	}
	return out, nil
}

// UpdateContact sets attributes of the contact keyed by extID (EMAIL among
// them changes its address) and, when emailBlacklisted is not nil, whether
// campaigns may reach it (Brevo's "Email campaigns: Subscribed" is false).
// A contact that does not exist answers 404: an upsert by POST cannot change
// an address — Brevo resolves it by the new email, finds none, and refuses
// the ext_id as taken (duplicate_parameter).
func (c *Client) UpdateContact(ctx context.Context, extID string, attributes map[string]any, emailBlacklisted *bool) error {
	payload := map[string]any{}
	if len(attributes) > 0 {
		payload["attributes"] = attributes
	}
	if emailBlacklisted != nil {
		payload["emailBlacklisted"] = *emailBlacklisted
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, http.MethodPut, "/contacts/"+url.PathEscape(extID)+"?identifierType=ext_id", body)
	return err
}

// EnsureAttribute creates a contact attribute of typ (boolean, text, …);
// one that exists already is fine. Brevo drops an attribute a call names
// that the account has not created, silently.
func (c *Client) EnsureAttribute(ctx context.Context, name, typ string) error {
	body, err := json.Marshal(map[string]any{"type": typ})
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, http.MethodPost, "/contacts/attributes/normal/"+url.PathEscape(name), body)
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusBadRequest && strings.Contains(e.Message, "must be unique") {
		return nil
	}
	return err
}

// IsNotFound reports whether Brevo answered that the thing does not exist.
func IsNotFound(err error) bool {
	var e *Error
	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// UpsertContact creates the contact keyed by extID, or updates it: its email
// (when given), attributes, and whether campaigns may reach it (when
// emailBlacklisted is not nil). A contact Brevo creates without
// emailBlacklisted is subscribed to campaigns.
func (c *Client) UpsertContact(ctx context.Context, extID, email string, attributes map[string]any, emailBlacklisted *bool) error {
	payload := map[string]any{"ext_id": extID, "updateEnabled": true}
	if email != "" {
		payload["email"] = email
	}
	if len(attributes) > 0 {
		payload["attributes"] = attributes
	}
	if emailBlacklisted != nil {
		payload["emailBlacklisted"] = *emailBlacklisted
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, _, err = c.do(ctx, http.MethodPost, "/contacts", body)
	return err
}

// MaxListContacts is the most contacts one GET /contacts answers.
const MaxListContacts = 1000

// Contact is one contact of the account, as a listing answers it. ExtID is
// the EXT_ID attribute — the id a contact is keyed by when the plugin wrote
// it (ext_id), empty for a contact something else created.
type Contact struct {
	ID               int64          `json:"id"`
	Email            string         `json:"email,omitempty"`
	EmailBlacklisted bool           `json:"emailBlacklisted"`
	Attributes       map[string]any `json:"attributes,omitempty"`
	ExtID            string         `json:"-"`
}

// ListContacts answers one page of the account's contacts, oldest first (so
// a contact created meanwhile lands on a later page instead of shifting this
// one), and how many there are in all.
func (c *Client) ListContacts(ctx context.Context, offset, limit int) ([]Contact, int, error) {
	if limit <= 0 || limit > MaxListContacts {
		return nil, 0, fmt.Errorf("brevo: a page of %d contacts, 1 to %d", limit, MaxListContacts)
	}
	q := url.Values{"limit": {strconv.Itoa(limit)}, "offset": {strconv.Itoa(offset)}, "sort": {"asc"}}
	_, raw, err := c.do(ctx, http.MethodGet, "/contacts?"+q.Encode(), nil)
	if err != nil {
		return nil, 0, err
	}
	var page struct {
		Contacts []Contact `json:"contacts"`
		Count    int       `json:"count"`
	}
	if err := json.Unmarshal(raw, &page); err != nil {
		return nil, 0, fmt.Errorf("brevo: a contact listing that does not parse: %w", err)
	}
	for i := range page.Contacts {
		if v, ok := page.Contacts[i].Attributes["EXT_ID"].(string); ok {
			page.Contacts[i].ExtID = v
		}
	}
	return page.Contacts, page.Count, nil
}

// GetContact reads the contact keyed by extID — whether campaigns may reach
// it as Brevo holds it now (a person who unsubscribed in Brevo is
// blacklisted there). A contact that does not exist answers 404 (IsNotFound).
func (c *Client) GetContact(ctx context.Context, extID string) (Contact, error) {
	_, raw, err := c.do(ctx, http.MethodGet, "/contacts/"+url.PathEscape(extID)+"?identifierType=ext_id", nil)
	if err != nil {
		return Contact{}, err
	}
	var got Contact
	if err := json.Unmarshal(raw, &got); err != nil {
		return Contact{}, fmt.Errorf("brevo: a contact that does not parse: %w", err)
	}
	if v, ok := got.Attributes["EXT_ID"].(string); ok {
		got.ExtID = v
	}
	return got, nil
}

// DeleteContact deletes the contact keyed by extID with its history. A
// contact that does not exist is already deleted.
func (c *Client) DeleteContact(ctx context.Context, extID string) error {
	_, _, err := c.do(ctx, http.MethodDelete, "/contacts/"+url.PathEscape(extID)+"?identifierType=ext_id", nil)
	var e *Error
	if errors.As(err, &e) && e.Status == http.StatusNotFound {
		return nil
	}
	return err
}

// maxRateLimitWaits bounds how often one call waits out a 429 before it
// gives up and lets the caller's own retry take over.
const maxRateLimitWaits = 3

// do sends one request, paced, and waits out a 429 for as long as Brevo
// says (x-sib-ratelimit-reset), a few times.
func (c *Client) do(ctx context.Context, method, path string, body []byte) (int, []byte, error) {
	for attempt := 0; ; attempt++ {
		if err := c.pace(ctx); err != nil {
			return 0, nil, err
		}
		req, err := http.NewRequestWithContext(ctx, method, c.base+path, bytes.NewReader(body))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("api-key", c.key)
		req.Header.Set("accept", "application/json")
		if body != nil {
			req.Header.Set("content-type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			// The URL carries no secret, but the transport's error repeats it
			// whole; the method and path say enough.
			return 0, nil, fmt.Errorf("brevo: %s %s: %w", method, strings.SplitN(path, "?", 2)[0], unwrapURLError(err))
		}
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitWaits {
			if err := c.sleep(ctx, resetAfter(resp.Header)); err != nil {
				return 0, nil, err
			}
			continue
		}
		if resp.StatusCode >= 300 {
			return resp.StatusCode, raw, apiError(resp.StatusCode, raw)
		}
		return resp.StatusCode, raw, nil
	}
}

// pace holds the request until the account's share of its rate limit allows
// it.
func (c *Client) pace(ctx context.Context) error {
	c.mu.Lock()
	now := time.Now()
	at := c.next
	if at.Before(now) {
		at = now
	}
	c.next = at.Add(c.gap)
	c.mu.Unlock()
	return c.sleep(ctx, time.Until(at))
}

// resetAfter is how long Brevo says to wait, a little more, and at least a
// second when it says nothing usable.
func resetAfter(h http.Header) time.Duration {
	if s, err := strconv.ParseFloat(strings.TrimSpace(h.Get("x-sib-ratelimit-reset")), 64); err == nil && s >= 0 {
		return time.Duration(s*float64(time.Second)) + 100*time.Millisecond
	}
	return time.Second
}

func apiError(status int, raw []byte) error {
	var body struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	_ = json.Unmarshal(raw, &body)
	if body.Message == "" {
		body.Message = http.StatusText(status)
	}
	return &Error{Status: status, Code: body.Code, Message: body.Message}
}

func unwrapURLError(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}
