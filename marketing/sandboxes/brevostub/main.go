// Command brevostub is a dev-only stand-in for the Brevo API, for the
// marketing plugin's brevo feature: it answers the calls the plugin makes and
// keeps what they said, so a project's suite can read back what would have
// reached Brevo — emailBlacklisted included.
//
//	POST   /v3/events/batch                         → 204 (207 for an event named *Refused*)
//	POST   /v3/contacts                             → 201 / 204, upsert by ext_id (updateEnabled false: 400 duplicate_parameter when it exists)
//	PUT    /v3/contacts/{id}?identifierType=ext_id  → 204, 404 when unknown
//	GET    /v3/contacts?limit=&offset=              → the contacts, oldest first, EXT_ID among the attributes
//	GET    /v3/contacts/{id}?identifierType=ext_id  → the contact (emailBlacklisted), 404 when unknown
//	POST   /_stub/contacts/{ext_id}/unsubscribe     → 204: the person unsubscribes in Brevo (blacklisted)
//	DELETE /v3/contacts/{id}?identifierType=ext_id  → 204, 404 when unknown
//	POST   /v3/contacts/attributes/normal/{name}    → 201, 400 when it exists
//	GET    /_stub/contacts/{ext_id}                 → the contact and its events, 404 when none
//	GET    /_stub/events                            → every event received, in order
//
// Every /v3 call needs the `api-key` header to equal API_KEY (default
// stub-key). Never shipped to production.
//
// It behaves as Brevo was measured to: an event for an unknown
// ext_id creates the contact, blacklisted (emailBlacklisted: true); a contact
// created by POST without emailBlacklisted is subscribed (false); an attribute the account has not created is
// dropped silently; an upsert by POST that names a known ext_id with another
// email is refused (duplicate_parameter) — an address changes by PUT.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type event struct {
	EventName         string         `json:"event_name"`
	EventDate         string         `json:"event_date,omitempty"`
	Identifiers       map[string]any `json:"identifiers"`
	ContactProperties map[string]any `json:"contact_properties,omitempty"`
	EventProperties   map[string]any `json:"event_properties,omitempty"`
}

type contact struct {
	ID               int            `json:"id"`
	ExtID            string         `json:"ext_id"`
	Email            string         `json:"email,omitempty"`
	EmailBlacklisted bool           `json:"emailBlacklisted"`
	Attributes       map[string]any `json:"attributes"`
	Events           []event        `json:"events"`
}

type stub struct {
	key        string
	mu         sync.Mutex
	nextID     int
	contacts   map[string]*contact
	events     []event
	attributes map[string]bool
}

// set copies the attributes the account knows; the others are dropped, as
// Brevo drops them.
func (s *stub) set(c *contact, attrs map[string]any) {
	for k, v := range attrs {
		if k == "EMAIL" {
			if e, _ := v.(string); e != "" {
				c.Email = e
			}
			continue
		}
		if s.attributes[k] {
			c.Attributes[k] = v
		}
	}
}

// contact is the contact keyed by ext, created when unknown — subscribed, as
// Brevo creates a contact it is told nothing about.
func (s *stub) contact(ext string) *contact {
	c := s.contacts[ext]
	if c == nil {
		s.nextID++
		c = &contact{ID: s.nextID, ExtID: ext, Attributes: map[string]any{}}
		s.contacts[ext] = c
	}
	return c
}

// listing is a contact as GET /v3/contacts answers it: the ext_id is the
// EXT_ID attribute.
func listing(c *contact) map[string]any {
	attrs := map[string]any{"EXT_ID": c.ExtID}
	for k, v := range c.Attributes {
		attrs[k] = v
	}
	return map[string]any{"id": c.ID, "email": c.Email, "emailBlacklisted": c.EmailBlacklisted, "attributes": attrs}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("content-type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, code int, c, msg string) {
	writeJSON(w, code, map[string]string{"code": c, "message": msg})
}

func (s *stub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_stub/") {
		s.inspect(w, r)
		return
	}
	if r.Header.Get("api-key") != s.key {
		refuse(w, http.StatusUnauthorized, "unauthorized", "Key not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v3/events/batch":
		var body struct {
			Events []event `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.Events) == 0 || len(body.Events) > 200 {
			refuse(w, http.StatusBadRequest, "invalid_parameter", "events: 1 to 200")
			return
		}
		var failed []int
		for i, ev := range body.Events {
			if strings.Contains(ev.EventName, "Refused") {
				failed = append(failed, i)
				continue
			}
			ext, _ := ev.Identifiers["ext_id"].(string)
			if ext == "" {
				failed = append(failed, i)
				continue
			}
			_, known := s.contacts[ext]
			c := s.contact(ext)
			if !known {
				c.EmailBlacklisted = true // as measured: no email, blacklisted
			}
			s.set(c, ev.ContactProperties)
			c.Events = append(c.Events, ev)
			s.events = append(s.events, ev)
		}
		if len(failed) > 0 {
			writeJSON(w, http.StatusMultiStatus, map[string]any{
				"status": "partial", "errors": []map[string]any{{"eventIndex": failed, "message": "invalid event"}},
			})
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodPost && r.URL.Path == "/v3/contacts":
		var body struct {
			ExtID            string         `json:"ext_id"`
			Email            string         `json:"email"`
			Attributes       map[string]any `json:"attributes"`
			EmailBlacklisted *bool          `json:"emailBlacklisted"`
			UpdateEnabled    *bool          `json:"updateEnabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ExtID == "" {
			refuse(w, http.StatusBadRequest, "missing_parameter", "ext_id is required")
			return
		}
		prev, existed := s.contacts[body.ExtID]
		if existed && body.UpdateEnabled != nil && !*body.UpdateEnabled {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "duplicate_parameter", "message": "Contact already exist"})
			return
		}
		if existed && body.Email != "" && prev.Email != "" && prev.Email != body.Email {
			writeJSON(w, http.StatusBadRequest, map[string]any{"code": "duplicate_parameter",
				"message": "Unable to update contact, ext_id is already associated with another Contact"})
			return
		}
		c := s.contact(body.ExtID)
		if body.Email != "" {
			c.Email = body.Email
		}
		if body.EmailBlacklisted != nil {
			c.EmailBlacklisted = *body.EmailBlacklisted
		}
		s.set(c, body.Attributes)
		if existed {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]int{"id": c.ID})
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v3/contacts/attributes/normal/"):
		name := strings.TrimPrefix(r.URL.Path, "/v3/contacts/attributes/normal/")
		if s.attributes[name] {
			refuse(w, http.StatusBadRequest, "invalid_parameter", "Attribute name must be unique")
			return
		}
		s.attributes[name] = true
		writeJSON(w, http.StatusCreated, map[string]any{})
	case r.Method == http.MethodPut && strings.HasPrefix(r.URL.Path, "/v3/contacts/"):
		ext := strings.TrimPrefix(r.URL.Path, "/v3/contacts/")
		c, ok := s.contacts[ext]
		if r.URL.Query().Get("identifierType") != "ext_id" || !ok {
			refuse(w, http.StatusNotFound, "document_not_found", "Contact does not exist")
			return
		}
		var body struct {
			Attributes       map[string]any `json:"attributes"`
			EmailBlacklisted *bool          `json:"emailBlacklisted"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			refuse(w, http.StatusBadRequest, "invalid_parameter", "body")
			return
		}
		if body.EmailBlacklisted != nil {
			c.EmailBlacklisted = *body.EmailBlacklisted
		}
		s.set(c, body.Attributes)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v3/contacts/"):
		c, ok := s.contacts[strings.TrimPrefix(r.URL.Path, "/v3/contacts/")]
		if r.URL.Query().Get("identifierType") != "ext_id" || !ok {
			refuse(w, http.StatusNotFound, "document_not_found", "Contact does not exist")
			return
		}
		writeJSON(w, http.StatusOK, listing(c))
	case r.Method == http.MethodGet && r.URL.Path == "/v3/contacts":
		limit, offset := 50, 0
		if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
			limit = v
		}
		if v, err := strconv.Atoi(r.URL.Query().Get("offset")); err == nil {
			offset = v
		}
		if limit < 1 || limit > 1000 || offset < 0 {
			refuse(w, http.StatusBadRequest, "invalid_parameter", "limit 1 to 1000, offset at least 0")
			return
		}
		all := make([]*contact, 0, len(s.contacts))
		for _, c := range s.contacts {
			all = append(all, c)
		}
		sort.Slice(all, func(i, j int) bool { return all[i].ID < all[j].ID })
		page := []map[string]any{}
		for i := offset; i < len(all) && i < offset+limit; i++ {
			page = append(page, listing(all[i]))
		}
		writeJSON(w, http.StatusOK, map[string]any{"contacts": page, "count": len(all)})
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v3/contacts/"):
		ext := strings.TrimPrefix(r.URL.Path, "/v3/contacts/")
		if r.URL.Query().Get("identifierType") != "ext_id" {
			refuse(w, http.StatusBadRequest, "invalid_parameter", "identifierType")
			return
		}
		if _, ok := s.contacts[ext]; !ok {
			refuse(w, http.StatusNotFound, "document_not_found", "Contact does not exist")
			return
		}
		delete(s.contacts, ext)
		w.WriteHeader(http.StatusNoContent)
	default:
		refuse(w, http.StatusNotFound, "not_found", "no such route in the stub")
	}
}

func (s *stub) inspect(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/_stub/contacts/") && strings.HasSuffix(r.URL.Path, "/unsubscribe"):
		c, ok := s.contacts[strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/_stub/contacts/"), "/unsubscribe")]
		if !ok {
			refuse(w, http.StatusNotFound, "document_not_found", "no such contact")
			return
		}
		c.EmailBlacklisted = true
		w.WriteHeader(http.StatusNoContent)
	case r.URL.Path == "/_stub/events":
		writeJSON(w, http.StatusOK, s.events)
	case strings.HasPrefix(r.URL.Path, "/_stub/contacts/"):
		c, ok := s.contacts[strings.TrimPrefix(r.URL.Path, "/_stub/contacts/")]
		if !ok {
			refuse(w, http.StatusNotFound, "document_not_found", "no such contact")
			return
		}
		writeJSON(w, http.StatusOK, c)
	default:
		refuse(w, http.StatusNotFound, "not_found", "no such stub route")
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	key := os.Getenv("API_KEY")
	if key == "" {
		key = "stub-key"
	}
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           &stub{key: key, contacts: map[string]*contact{}, attributes: map[string]bool{}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Print("brevostub listening")
	log.Fatal(srv.ListenAndServe())
}
