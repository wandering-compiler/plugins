package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func call(t *testing.T, h http.Handler, method, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if key != "" {
		r.Header.Set("api-key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestStub_KeepsWhatThePluginSent(t *testing.T) {
	s := &stub{key: "k", contacts: map[string]*contact{}, attributes: map[string]bool{}}
	if w := call(t, s, http.MethodPost, "/v3/contacts", "k", `{"ext_id":"u1","email":"a@x.example","updateEnabled":true}`); w.Code != http.StatusCreated {
		t.Fatalf("create = %d", w.Code)
	}
	// An attribute the account has not created is dropped, as Brevo drops it.
	call(t, s, http.MethodPost, "/v3/contacts", "k", `{"ext_id":"u1","attributes":{"W17_MARKETING_CONSENT":false}}`)
	if w := call(t, s, http.MethodPost, "/v3/contacts/attributes/normal/W17_MARKETING_CONSENT", "k", `{"type":"boolean"}`); w.Code != http.StatusCreated {
		t.Fatalf("attribute = %d", w.Code)
	}
	if w := call(t, s, http.MethodPost, "/v3/contacts/attributes/normal/W17_MARKETING_CONSENT", "k", `{"type":"boolean"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("attribute twice = %d, want 400", w.Code)
	}
	if w := call(t, s, http.MethodPut, "/v3/contacts/u1?identifierType=ext_id", "k", `{"attributes":{"W17_MARKETING_CONSENT":true}}`); w.Code != http.StatusNoContent {
		t.Fatalf("update = %d", w.Code)
	}
	// An address changes by PUT; by POST, Brevo refuses the ext_id as taken.
	if w := call(t, s, http.MethodPost, "/v3/contacts", "k", `{"ext_id":"u1","email":"b@x.example","updateEnabled":true}`); w.Code != http.StatusBadRequest {
		t.Fatalf("POST with a changed email = %d, want 400", w.Code)
	}
	if w := call(t, s, http.MethodPut, "/v3/contacts/u1?identifierType=ext_id", "k", `{"attributes":{"EMAIL":"a2@x.example"}}`); w.Code != http.StatusNoContent {
		t.Fatalf("PUT email = %d", w.Code)
	}
	if w := call(t, s, http.MethodPost, "/v3/events/batch", "k", `{"events":[{"event_name":"T_Create","identifiers":{"ext_id":"u1"}},{"event_name":"T_Refused","identifiers":{"ext_id":"u1"}}]}`); w.Code != http.StatusMultiStatus {
		t.Fatalf("batch = %d, want 207 for the refused one", w.Code)
	}
	w := call(t, s, http.MethodGet, "/_stub/contacts/u1", "", "")
	var c contact
	if err := json.Unmarshal(w.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.Email != "a2@x.example" || c.Attributes["W17_MARKETING_CONSENT"] != true || len(c.Events) != 1 || c.Events[0].EventName != "T_Create" {
		t.Errorf("contact = %+v", c)
	}
	if w := call(t, s, http.MethodDelete, "/v3/contacts/u1?identifierType=ext_id", "k", ""); w.Code != http.StatusNoContent {
		t.Fatalf("delete = %d", w.Code)
	}
	if w := call(t, s, http.MethodGet, "/_stub/contacts/u1", "", ""); w.Code != http.StatusNotFound {
		t.Errorf("a deleted contact is still there: %d", w.Code)
	}
	if w := call(t, s, http.MethodDelete, "/v3/contacts/u1?identifierType=ext_id", "k", ""); w.Code != http.StatusNotFound {
		t.Errorf("deleting twice = %d, want 404", w.Code)
	}
}

func TestStub_RefusesAWrongKey(t *testing.T) {
	s := &stub{key: "k", contacts: map[string]*contact{}, attributes: map[string]bool{}}
	if w := call(t, s, http.MethodPost, "/v3/events/batch", "other", `{"events":[]}`); w.Code != http.StatusUnauthorized {
		t.Errorf("wrong key = %d, want 401", w.Code)
	}
}

// The stub keeps and answers emailBlacklisted as Brevo does: a contact
// created by POST without it is subscribed, one an event creates is
// blacklisted, and a write that names it sets it.
func TestStub_KeepsEmailBlacklisted(t *testing.T) {
	s := &stub{key: "k", contacts: map[string]*contact{}, attributes: map[string]bool{}}
	get := func(ext string) contact {
		t.Helper()
		var c contact
		if err := json.Unmarshal(call(t, s, http.MethodGet, "/_stub/contacts/"+ext, "", "").Body.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	call(t, s, http.MethodPost, "/v3/contacts", "k", `{"ext_id":"u1","email":"a@x.example","updateEnabled":true}`)
	if get("u1").EmailBlacklisted {
		t.Error("a contact created without emailBlacklisted is blacklisted; Brevo subscribes it")
	}
	call(t, s, http.MethodPost, "/v3/contacts", "k", `{"ext_id":"u2","email":"b@x.example","updateEnabled":true,"emailBlacklisted":true}`)
	if !get("u2").EmailBlacklisted {
		t.Error("emailBlacklisted on create was not kept")
	}
	call(t, s, http.MethodPut, "/v3/contacts/u2?identifierType=ext_id", "k", `{"emailBlacklisted":false}`)
	if get("u2").EmailBlacklisted {
		t.Error("emailBlacklisted on update was not kept")
	}
	call(t, s, http.MethodPut, "/v3/contacts/u2?identifierType=ext_id", "k", `{"attributes":{"EMAIL":"c@x.example"}}`)
	if c := get("u2"); c.EmailBlacklisted || c.Email != "c@x.example" {
		t.Errorf("an update not naming emailBlacklisted changed it: %+v", c)
	}
	call(t, s, http.MethodPost, "/v3/events/batch", "k", `{"events":[{"event_name":"T_Create","identifiers":{"ext_id":"u3"}}]}`)
	if !get("u3").EmailBlacklisted {
		t.Error("a contact an event creates is not blacklisted")
	}
	w := call(t, s, http.MethodGet, "/v3/contacts?limit=2&offset=1&sort=asc", "k", "")
	var page struct {
		Contacts []struct {
			ID               int            `json:"id"`
			EmailBlacklisted bool           `json:"emailBlacklisted"`
			Attributes       map[string]any `json:"attributes"`
		} `json:"contacts"`
		Count int `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if page.Count != 3 || len(page.Contacts) != 2 || page.Contacts[0].Attributes["EXT_ID"] != "u2" || page.Contacts[0].EmailBlacklisted ||
		page.Contacts[1].Attributes["EXT_ID"] != "u3" || !page.Contacts[1].EmailBlacklisted {
		t.Errorf("listing = %s", w.Body.String())
	}
	if w := call(t, s, http.MethodGet, "/v3/contacts?limit=1001", "k", ""); w.Code != http.StatusBadRequest {
		t.Errorf("a page past Brevo's limit = %d, want 400", w.Code)
	}
}
