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
