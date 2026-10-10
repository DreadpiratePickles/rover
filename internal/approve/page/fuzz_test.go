package page

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/DreadpiratePickles/rover/internal/approve"
)

// FuzzPageRequest: whatever request reaches the page, only the exact
// link's GET answers 200, and no request changes the record.
func FuzzPageRequest(f *testing.F) {
	store := approve.NewMemStore()
	rec := approve.Record{Request: approve.Request{ID: approve.NewID(), Server: "s", Tool: "t"}, State: approve.StatePending}
	_ = store.Put(rec)
	p := New(store, false)
	p.SetHost("127.0.0.1:9")
	link, _ := p.Register(rec.Request)
	target := strings.TrimPrefix(link, "http://127.0.0.1:9")
	f.Add("GET", target, "127.0.0.1:9")
	f.Add("POST", target, "127.0.0.1:9")
	f.Add("GET", "/approval/"+rec.ID+"?t=", "127.0.0.1:9")
	f.Add("GET", "/approval/../approval/"+rec.ID, "localhost:9")
	f.Fuzz(func(t *testing.T, method, uri, host string) {
		req, err := http.NewRequest(method, "http://127.0.0.1:9", nil)
		if err != nil {
			return
		}
		u, err := req.URL.Parse(uri)
		if err != nil {
			return
		}
		req.URL, req.Host, req.RequestURI = u, host, uri
		w := httptest.NewRecorder()
		p.ServeHTTP(w, req)
		q := u.Query()
		exact := method == http.MethodGet && host == "127.0.0.1:9" && u.Path == "/approval/"+rec.ID && u.RawPath == "" &&
			len(q) == 1 && len(q["t"]) == 1 && "t="+q.Get("t") == strings.SplitN(target, "?", 2)[1]
		if w.Code == http.StatusOK && !exact {
			t.Fatalf("%s %q host %q answered 200", method, uri, host)
		}
		if got, _, _ := store.Get(rec.ID); !reflect.DeepEqual(got, rec) {
			t.Fatal("a request changed the record")
		}
	})
}
