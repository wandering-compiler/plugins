// Command brevostub is a dev-only stand-in for the Brevo API, for the
// marketing plugin's brevo feature: it answers the three calls the plugin
// makes and keeps what they said, so a project's suite can read back what
// would have reached Brevo.
//
//	POST   /v3/events/batch                         → 204 (207 for an event named *Refused*)
//	POST   /v3/contacts                             → 201 / 204, upsert by ext_id
//	DELETE /v3/contacts/{id}?identifierType=ext_id  → 204, 404 when unknown
//	GET    /_stub/contacts/{ext_id}                 → the contact and its events, 404 when none
//	GET    /_stub/events                            → every event received, in order
//
// Every /v3 call needs the `api-key` header to equal API_KEY (default
// stub-key). Never shipped to production.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
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
	ExtID      string         `json:"ext_id"`
	Email      string         `json:"email,omitempty"`
	Attributes map[string]any `json:"attributes"`
	Events     []event        `json:"events"`
}

type stub struct {
	key      string
	mu       sync.Mutex
	contacts map[string]*contact
	events   []event
}

func (s *stub) contact(ext string) *contact {
	c := s.contacts[ext]
	if c == nil {
		// The stub creates the contact an event names when it does not know
		// it; whether Brevo does is an open point of the plugin's SPEC.md.
		c = &contact{ExtID: ext, Attributes: map[string]any{}}
		s.contacts[ext] = c
	}
	return c
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
			c := s.contact(ext)
			for k, v := range ev.ContactProperties {
				c.Attributes[k] = v
			}
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
			ExtID      string         `json:"ext_id"`
			Email      string         `json:"email"`
			Attributes map[string]any `json:"attributes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ExtID == "" {
			refuse(w, http.StatusBadRequest, "missing_parameter", "ext_id is required")
			return
		}
		_, existed := s.contacts[body.ExtID]
		c := s.contact(body.ExtID)
		if body.Email != "" {
			c.Email = body.Email
		}
		for k, v := range body.Attributes {
			c.Attributes[k] = v
		}
		if existed {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusCreated, map[string]int{"id": len(s.contacts)})
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
		Handler:           &stub{key: key, contacts: map[string]*contact{}},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	log.Print("brevostub listening")
	log.Fatal(srv.ListenAndServe())
}
