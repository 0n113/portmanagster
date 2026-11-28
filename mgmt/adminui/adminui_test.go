package adminui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	fieldCode    = "code"
	fieldName    = "name"
	headerOrigin = "Origin"
	testOrigin   = "http://localhost:8444"
	testAdmin    = "alice"
	testViewer   = "victor"
)

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

type harness struct {
	t     *testing.T
	store *server.Store
	ui    *UI
	h     http.Handler
	now   time.Time
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	store, err := server.OpenStore(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	h := &harness{t: t, store: store, now: time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC)}
	h.ui, err = New(Config{Store: store, URL: testOrigin, Now: func() time.Time { return h.now }})
	if err != nil {
		t.Fatal(err)
	}
	h.h = h.ui.Handler()
	return h
}

// request runs a request; form is sent url-encoded for POST.
func (h *harness) request(method, path string, form url.Values, cookie string, header map[string]string) *httptest.ResponseRecorder {
	h.t.Helper()
	var r *http.Request
	if form != nil {
		r = httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if method == http.MethodPost {
		r.Header.Set(headerOrigin, testOrigin)
	}
	for k, v := range header {
		r.Header.Set(k, v)
	}
	if cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionName, Value: cookie}) //nolint:gosec // Request cookie.
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, r)
	return w
}

// addTOTPAdmin creates an account and sets up TOTP through the setup link.
func (h *harness) addTOTPAdmin(name, role string) string {
	h.t.Helper()
	err := h.store.AddAdmin(name, role, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	token, err := h.store.CreateSetupLink(name, 15*time.Minute, h.now)
	if err != nil {
		h.t.Fatal(err)
	}
	w := h.request(http.MethodGet, "/setup?token="+token, nil, "", nil)
	if w.Code != http.StatusOK {
		h.t.Fatalf("setup page: %d", w.Code)
	}
	secret, err := newTOTPSecret()
	if err != nil {
		h.t.Fatal(err)
	}
	w = h.request(http.MethodPost, "/setup/totp", url.Values{"token": {token}, "secret": {secret}, fieldCode: {h.code(secret)}}, "", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login?setup=done" {
		h.t.Fatalf("set up TOTP: %d %s", w.Code, w.Body)
	}
	// The setup link is used up.
	w = h.request(http.MethodGet, "/setup?token="+token, nil, "", nil)
	if w.Code != http.StatusNotFound {
		h.t.Fatalf("used setup link: %d", w.Code)
	}
	return secret
}

func (h *harness) code(secret string) string {
	key, err := totpEncoding.DecodeString(secret)
	if err != nil {
		h.t.Fatal(err)
	}
	return totpCode(key, h.now.Unix()/totpPeriod)
}

// login logs in with TOTP in the next time step and returns the session
// cookie and the CSRF token.
func (h *harness) login(name, secret string) (cookie, csrf string) {
	h.t.Helper()
	h.now = h.now.Add(totpPeriod * time.Second)
	w := h.request(http.MethodPost, "/login/totp", url.Values{fieldName: {name}, fieldCode: {h.code(secret)}}, "", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/" {
		h.t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == sessionName {
			if !c.HttpOnly || c.SameSite != http.SameSiteStrictMode {
				h.t.Fatalf("session cookie must be HttpOnly and SameSite=Strict: %+v", c)
			}
			cookie = c.Value
		}
	}
	w = h.request(http.MethodGet, "/", nil, cookie, nil)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), name) {
		h.t.Fatalf("dashboard after login: %d", w.Code)
	}
	m := csrfRe.FindStringSubmatch(w.Body.String())
	if m == nil {
		h.t.Fatal("no CSRF token on the dashboard")
	}
	return cookie, m[1]
}

func TestTOTPVectors(t *testing.T) {
	t.Parallel()
	// RFC 6238 appendix B, SHA1, last six digits.
	key := []byte("12345678901234567890")
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		if got := totpCode(key, unix/totpPeriod); got != want {
			t.Errorf("time %d: got %s, want %s", unix, got, want)
		}
	}
	secret := totpEncoding.EncodeToString(key)
	if _, ok := verifyTOTP(secret, "287082", time.Unix(59+totpPeriod, 0)); !ok {
		t.Error("a code of the previous step must be accepted")
	}
	if _, ok := verifyTOTP(secret, "287082", time.Unix(59+3*totpPeriod, 0)); ok {
		t.Error("an old code must be refused")
	}
}

func TestLoginLogout(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)

	// Without a session the dashboard sends to the login.
	w := h.request(http.MethodGet, "/", nil, "", nil)
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/login" {
		t.Fatalf("anonymous dashboard: %d", w.Code)
	}
	cookie, csrf := h.login(testAdmin, secret)

	// The same code again is a replay.
	w = h.request(http.MethodPost, "/login/totp", url.Values{fieldName: {testAdmin}, fieldCode: {h.code(secret)}}, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("replayed code: %d", w.Code)
	}

	// Logout needs the CSRF token.
	w = h.request(http.MethodPost, "/logout", url.Values{}, cookie, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF token: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/logout", url.Values{csrfField: {"00" + csrf[2:]}}, cookie, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("logout with a wrong CSRF token: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/logout", url.Values{csrfField: {csrf}}, cookie, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("logout: %d", w.Code)
	}
	w = h.request(http.MethodGet, "/", nil, cookie, nil)
	if w.Code != http.StatusSeeOther {
		t.Fatalf("dashboard after logout: %d", w.Code)
	}

	log, err := h.store.AuditLog(time.Time{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	actions := make([]string, 0, len(log))
	for _, e := range log {
		actions = append(actions, e.Action+" "+e.Actor)
	}
	want := "logout admin:alice,login admin:alice,admin.totp admin:alice"
	if strings.Join(actions, ",") != want {
		t.Fatalf("audit log: %v", actions)
	}
}

func TestSessionExpiry(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)

	// Idle timeout.
	cookie, _ := h.login(testAdmin, secret)
	h.now = h.now.Add(SessionIdle + time.Second)
	if w := h.request(http.MethodGet, "/", nil, cookie, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("idle session: %d", w.Code)
	}

	// Maximum age, although used every 20 minutes.
	cookie, _ = h.login(testAdmin, secret)
	start := h.now
	for h.now.Sub(start) < SessionMaxAge-20*time.Minute {
		h.now = h.now.Add(20 * time.Minute)
		if w := h.request(http.MethodGet, "/", nil, cookie, nil); w.Code != http.StatusOK {
			t.Fatalf("active session after %s: %d", h.now.Sub(start), w.Code)
		}
	}
	h.now = start.Add(SessionMaxAge)
	if w := h.request(http.MethodGet, "/", nil, cookie, nil); w.Code != http.StatusSeeOther {
		t.Fatalf("session after the maximum age: %d", w.Code)
	}
}

func TestViewerCannotPost(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	adminSecret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	viewerSecret := h.addTOTPAdmin(testViewer, server.RoleViewer)

	viewer, viewerCSRF := h.login(testViewer, viewerSecret)
	admin, adminCSRF := h.login(testAdmin, adminSecret)
	// Every write route is behind the role check; an unknown one shows
	// that the check comes before the routing.
	w := h.request(http.MethodPost, "/no-such-action", url.Values{csrfField: {viewerCSRF}}, viewer, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/no-such-action", url.Values{csrfField: {adminCSRF}}, admin, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("admin POST: %d", w.Code)
	}
	// A CSRF token belongs to its session.
	w = h.request(http.MethodPost, "/no-such-action", url.Values{csrfField: {viewerCSRF}}, admin, nil)
	if w.Code != http.StatusForbidden {
		t.Fatalf("CSRF token of another session: %d", w.Code)
	}
	// Viewers may log out.
	w = h.request(http.MethodPost, "/logout", nil, viewer, map[string]string{csrfHeader: viewerCSRF})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("viewer logout: %d", w.Code)
	}
}

func TestCrossOriginRefused(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	h.now = h.now.Add(totpPeriod * time.Second)
	form := url.Values{fieldName: {testAdmin}, fieldCode: {h.code(secret)}}
	w := h.request(http.MethodPost, "/login/totp", form, "", map[string]string{headerOrigin: "https://evil.example"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin login: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/login/totp", form, "", map[string]string{headerOrigin: "null", "Sec-Fetch-Site": "cross-site"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("login from an opaque origin: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/login/totp", form, "", map[string]string{headerOrigin: ""})
	if w.Code != http.StatusForbidden {
		t.Fatalf("login without origin: %d", w.Code)
	}
	// Some browsers send "Origin: null" on same-origin form posts.
	w = h.request(http.MethodPost, "/login/totp", form, "", map[string]string{headerOrigin: "null", "Sec-Fetch-Site": "same-origin"})
	if w.Code != http.StatusSeeOther {
		t.Fatalf("same-origin login with Origin null: %d", w.Code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	secret := h.addTOTPAdmin(testAdmin, server.RoleAdmin)
	// The setup check with the used link counted as a failure.
	h.ui.limit = newLimiter(loginFailures, loginWindow)
	h.now = h.now.Add(totpPeriod * time.Second)
	for range loginFailures {
		w := h.request(http.MethodPost, "/login/totp", url.Values{fieldName: {testAdmin}, fieldCode: {"000000"}}, "", nil)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("wrong code: %d", w.Code)
		}
	}
	w := h.request(http.MethodPost, "/login/totp", url.Values{fieldName: {testAdmin}, fieldCode: {h.code(secret)}}, "", nil)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("login after too many failures: %d", w.Code)
	}
	if w := h.request(http.MethodPost, "/api/login/begin", nil, "", nil); w.Code != http.StatusTooManyRequests {
		t.Fatalf("passkey login from a blocked address: %d", w.Code)
	}
	h.now = h.now.Add(loginWindow)
	h.login(testAdmin, secret)
}

func TestPasskeyBegin(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	var resp struct {
		ID      string `json:"id"`
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
				RPID      string `json:"rpId"`
				User      struct {
					Name string `json:"name"`
				} `json:"user"`
				AuthenticatorSelection struct {
					ResidentKey string `json:"residentKey"`
				} `json:"authenticatorSelection"`
			} `json:"publicKey"`
		} `json:"options"`
	}
	w := h.request(http.MethodPost, "/api/login/begin", nil, "", nil)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("login begin: %d %s", w.Code, w.Body)
	}
	if resp.ID == "" || resp.Options.PublicKey.Challenge == "" || resp.Options.PublicKey.RPID != "localhost" {
		t.Fatalf("login options: %s", w.Body)
	}
	// A finish without a credential fails and uses the prompt up.
	w = h.request(http.MethodPost, "/api/login/finish?id="+resp.ID, nil, "", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("login finish without credential: %d", w.Code)
	}
	w = h.request(http.MethodPost, "/api/login/finish?id="+resp.ID, nil, "", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("login finish twice: %d", w.Code)
	}

	err := h.store.AddAdmin(testAdmin, server.RoleAdmin, h.now)
	if err != nil {
		t.Fatal(err)
	}
	token, err := h.store.CreateSetupLink(testAdmin, time.Minute, h.now)
	if err != nil {
		t.Fatal(err)
	}
	setup := func(token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/setup/passkey/begin", strings.NewReader(`{"token":"`+token+`"}`))
		r.Header.Set(headerOrigin, testOrigin)
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, r)
		return w
	}
	w = setup(token)
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil {
		t.Fatalf("setup begin: %d %s", w.Code, w.Body)
	}
	if resp.Options.PublicKey.User.Name != testAdmin || resp.Options.PublicKey.AuthenticatorSelection.ResidentKey != "required" {
		t.Fatalf("setup options: %s", w.Body)
	}
	if w := setup("bad"); w.Code != http.StatusNotFound {
		t.Fatalf("setup begin with a bad token: %d", w.Code)
	}
	h.now = h.now.Add(time.Minute)
	if w := setup(token); w.Code != http.StatusNotFound {
		t.Fatalf("setup begin with an expired token: %d", w.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	w := h.request(http.MethodGet, "/login", nil, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("login page: %d", w.Code)
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe") {
		t.Fatalf("CSP: %q", csp)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("headers: %v", w.Header())
	}
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), " style=") {
		t.Fatal("pages must not contain inline scripts or styles")
	}
	if w := h.request(http.MethodGet, "/static/app.js", nil, "", nil); w.Code != http.StatusOK {
		t.Fatalf("app.js: %d", w.Code)
	}
}
