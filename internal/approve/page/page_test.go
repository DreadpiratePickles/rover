package page

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

// fixture serves one pending approval and returns its link.
func fixture(t *testing.T, showArgs bool) (*Server, *approve.MemStore, approve.Record, string) {
	t.Helper()
	store := approve.NewMemStore()
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	rec := approve.Record{Request: approve.Request{ID: approve.NewID(), Session: "s1", Client: "claude-code", Server: "github",
		Tool: "push_files", Summary: "push to main", Args: []byte(`{"branch":"main","token":"<b>x</b>"}`), RuleIDs: []string{"gh-push"},
		Created: now, Deadline: now.Add(2 * time.Minute)}, State: approve.StatePending}
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}
	p := New(store, showArgs)
	p.now = func() time.Time { return now }
	ts := httptest.NewServer(p)
	t.Cleanup(ts.Close)
	p.SetHost(strings.TrimPrefix(ts.URL, "http://"))
	link, err := p.Register(rec.Request)
	if err != nil {
		t.Fatal(err)
	}
	return p, store, rec, link
}

func do(t *testing.T, method, link string, hdr map[string]string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, link, strings.NewReader(`{"action":"approve"}`))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestGetShowsTheApprovalInCwmStyle(t *testing.T) {
	// Arrange
	_, _, rec, link := fixture(t, false)

	// Act
	code, body := do(t, http.MethodGet, link, nil)

	// Assert
	if code != http.StatusOK {
		t.Fatalf("GET: %d %s", code, body)
	}
	for _, want := range []string{"approval»" + rec.ID + "«", "background:#fff", "font: bold 14px sans-serif", "border:1px solid #000",
		`class="urgent">state pending`, "#FC8814", "tool push_files", "args hidden: approvals.show_args is false", "this page cannot approve"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "main") && strings.Contains(body, "branch") {
		t.Error("arguments shown although show_args is false")
	}
}

func TestPageHasNothingToClickOrRun(t *testing.T) {
	// Arrange: arguments shown, with markup in them.
	_, _, _, link := fixture(t, true)

	// Act
	_, body := do(t, http.MethodGet, link, nil)

	// Assert
	lower := strings.ToLower(body)
	for _, banned := range []string{"<script", "<form", "<input", "<link", "<img", "<button", "<a ", "<iframe", "http://", "https://", "javascript:"} {
		if strings.Contains(lower, banned) {
			t.Errorf("page contains %q", banned)
		}
	}
	if !strings.Contains(body, "&lt;b&gt;x&lt;/b&gt;") {
		t.Errorf("arguments must be shown escaped:\n%s", body)
	}
}

type reqCase struct {
	method, link string
	hdr          map[string]string
	want         int
}

// Acceptance (plan M9): curl against the page cannot change any state.
func TestEveryOtherRequestIsRefusedAndChangesNothing(t *testing.T) {
	// Arrange
	_, store, rec, link := fixture(t, false)
	before, _, _ := store.Get(rec.ID)
	u, _ := url.Parse(link)
	base := u.Scheme + "://" + u.Host
	tok := u.Query().Get("t")
	var cases []reqCase
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions, "APPROVE"} {
		cases = append(cases, reqCase{m, link, nil, http.StatusMethodNotAllowed})
	}
	for _, l := range []string{
		base + "/", base + "/approve/" + rec.ID + "?t=" + tok, base + "/approval/" + rec.ID + "/approve?t=" + tok,
		base + "/approval/" + rec.ID, base + "/approval/" + rec.ID + "?t=" + strings.Repeat("0", 32),
		base + "/approval/" + rec.ID + "?t=" + tok + "&approve=1", base + "/approval/" + rec.ID + "?t=" + tok + "&t=" + tok,
		base + "/approval/" + approve.NewID() + "?t=" + tok, base + "/approval/" + strings.ToUpper(rec.ID) + "?t=" + tok,
		base + "/approval/..%2f" + rec.ID + "?t=" + tok,
	} {
		cases = append(cases, reqCase{http.MethodGet, l, nil, http.StatusNotFound})
	}
	cases = append(cases, reqCase{http.MethodGet, link, map[string]string{"Host": "rebound.example:80"}, http.StatusNotFound})

	for _, c := range cases {
		// Act
		code, _ := do(t, c.method, c.link, c.hdr)

		// Assert
		if code != c.want {
			t.Errorf("%s %s %v: %d, want %d", c.method, c.link, c.hdr, code, c.want)
		}
	}
	after, _, _ := store.Get(rec.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("state changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

func TestDecidedApprovalShowsMethodWithoutUrgentColour(t *testing.T) {
	// Arrange
	_, store, rec, link := fixture(t, false)
	rec.State, rec.Method, rec.DecidedAt = approve.StateDenied, "macos_local_authentication", rec.Created.Add(time.Minute)
	if err := store.Put(rec); err != nil {
		t.Fatal(err)
	}

	// Act
	_, body := do(t, http.MethodGet, link, nil)

	// Assert
	if strings.Contains(body, `class="urgent"`) || !strings.Contains(body, "state denied") || !strings.Contains(body, "by macos_local_authentication") {
		t.Fatalf("decided page:\n%s", body)
	}
}

func TestRegisterRefusesBadIDs(t *testing.T) {
	p, _, _, _ := fixture(t, false)
	if _, err := p.Register(approve.Request{ID: "../x"}); err == nil {
		t.Fatal("a bad id must be refused")
	}
}
