// Package adminui is the admin web UI of the management server: accounts
// log in with a passkey or TOTP; pages are rendered on the server and use
// a strict content security policy.
package adminui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	schemeHTTPS = "https"
	// SessionMaxAge is the lifetime of a session after the login.
	SessionMaxAge = 12 * time.Hour
	// SessionIdle ends a session that was not used for this long.
	SessionIdle = 30 * time.Minute

	// loginFailures within loginWindow block an account or IP address.
	loginFailures = 5
	loginWindow   = 15 * time.Minute

	// ceremonyTTL is the time a passkey prompt may take.
	ceremonyTTL  = 5 * time.Minute
	maxCeremony  = 1000
	sessionName  = "pmsession"
	csrfField    = "csrf"
	csrfHeader   = "X-Csrf-Token"
	issuer       = "Portmanagster"
	actorPrefix  = "admin:"
	maxBodyBytes = 1 << 20
)

var (
	//go:embed templates/*.html
	templateFS embed.FS
	//go:embed static
	staticFS embed.FS

	errBadURL      = errors.New("the admin URL must be http(s)://host[:port]")
	errTooMany     = errors.New("too many open passkey prompts")
	errNoCeremony  = errors.New("unknown or expired passkey prompt")
	errNoAdminUser = errors.New("unknown passkey")
)

// Config configures the admin UI.
type Config struct {
	Store *server.Store
	// URL is the address under which admins open the UI, e.g.
	// http://localhost:8444. Passkeys are bound to its host name.
	URL    string
	Logger *slog.Logger
	// Now returns the current time; tests replace it.
	Now func() time.Time
	// ClientURL is the address of the client API for the enroll command
	// shown with a new token, e.g. https://pm.example.lan:8443.
	ClientURL string
	// ServerFP and PolicyKeyFP are the fingerprints clients pin.
	ServerFP    string
	PolicyKeyFP string
	// DataDir is the data directory of the server, for the offline key;
	// empty turns the offline signing pages off.
	DataDir string
}

// UI is the admin web UI.
type UI struct {
	cfg     Config
	store   *server.Store
	wa      *webauthn.WebAuthn
	origin  string
	secure  bool
	log     *slog.Logger
	now     func() time.Time
	limit   *limiter
	pages   map[string]*template.Template
	mu      sync.Mutex
	pending map[string]*ceremony
}

// ctxKey is the context key of the session.
type ctxKey struct{}

// ceremony is an open passkey prompt.
type ceremony struct {
	data    *webauthn.SessionData
	token   string // setup token, for a registration
	expires time.Time
}

// New creates the admin UI.
func New(cfg Config) (*UI, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != schemeHTTPS) || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return nil, fmt.Errorf("%q: %w", cfg.URL, errBadURL)
	}
	origin := u.Scheme + "://" + u.Host
	wa, err := webauthn.New(&webauthn.Config{
		RPID:          u.Hostname(),
		RPDisplayName: issuer,
		RPOrigins:     []string{origin},
	})
	if err != nil {
		return nil, err
	}
	pages, err := parsePages()
	if err != nil {
		return nil, err
	}
	ui := &UI{
		cfg:     cfg,
		store:   cfg.Store,
		wa:      wa,
		origin:  origin,
		secure:  u.Scheme == schemeHTTPS,
		log:     cfg.Logger,
		now:     cfg.Now,
		limit:   newLimiter(loginFailures, loginWindow),
		pages:   pages,
		pending: make(map[string]*ceremony),
	}
	if ui.log == nil {
		ui.log = slog.New(slog.DiscardHandler)
	}
	if ui.now == nil {
		ui.now = time.Now
	}
	return ui, nil
}

// Handler returns the HTTP handler of the UI.
func (ui *UI) Handler() http.Handler {
	public := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	public.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	public.HandleFunc("GET /login", ui.handleLoginPage)
	public.HandleFunc("POST /login/totp", ui.handleLoginTOTP)
	public.HandleFunc("POST /api/login/begin", ui.handleLoginBegin)
	public.HandleFunc("POST /api/login/finish", ui.handleLoginFinish)
	public.HandleFunc("GET /setup", ui.handleSetupPage)
	public.HandleFunc("POST /setup/totp", ui.handleSetupTOTP)
	public.HandleFunc("POST /api/setup/passkey/begin", ui.handleSetupBegin)
	public.HandleFunc("POST /api/setup/passkey/finish", ui.handleSetupFinish)

	private := http.NewServeMux()
	private.HandleFunc("GET /{$}", ui.handleDashboard)
	private.HandleFunc("GET /computers", ui.handleComputers)
	private.HandleFunc("GET /computers/{id}", ui.handleComputer)
	private.HandleFunc("GET /groups", ui.handleGroups)
	private.HandleFunc("GET /groups/{name}", ui.handleGroup)
	private.HandleFunc("GET /tokens", ui.handleTokens)
	private.HandleFunc("GET /audit", ui.handleAudit)
	private.HandleFunc("GET /blocks", ui.handleBlocks)
	private.HandleFunc("GET /alerts", ui.handleAlerts)
	private.HandleFunc("POST /alerts/ack", ui.handleAlertAck)
	private.HandleFunc("POST /groups/{name}/silentafter", ui.handleGroupSilentAfter)
	private.HandleFunc("GET /groups/{name}/export", ui.handleGroupExport)
	private.HandleFunc("POST /groups/{name}/publish", ui.handleGroupPublish)
	private.HandleFunc("POST /groups/{name}/blocksummary", ui.handleGroupBlockSummary)
	private.HandleFunc("POST /groups", ui.handleGroupCreate)
	private.HandleFunc("POST /groups/{name}/delete", ui.handleGroupDelete)
	private.HandleFunc("POST /groups/{name}/settings", ui.handleGroupSettings)
	private.HandleFunc("POST /groups/{name}/rules", ui.handleGroupRules)
	private.HandleFunc("POST /groups/{name}/profiles", ui.handleProfileAdd)
	private.HandleFunc("POST /groups/{name}/profiles/remove", ui.handleProfileRemove)
	private.HandleFunc("POST /tokens", ui.handleTokenCreate)
	private.HandleFunc("POST /tokens/{id}/revoke", ui.handleTokenRevoke)
	private.HandleFunc("POST /computers/{id}/move", ui.handleComputerMove)
	private.HandleFunc("POST /computers/{id}/revoke", ui.handleComputerRevoke)
	private.HandleFunc("POST /logout", ui.handleLogout)
	public.Handle("/", ui.requireSession(private))

	return ui.secureHeaders(ui.checkOrigin(public))
}

// Serve runs the UI on addr until ctx is done; with certFile and keyFile
// it uses TLS.
func (ui *UI) Serve(ctx context.Context, addr, certFile, keyFile string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           ui.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		if certFile != "" {
			errCh <- srv.ListenAndServeTLS(certFile, keyFile)
			return
		}
		errCh <- srv.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx) //nolint:contextcheck // The parent context is done.
	}
}

// secureHeaders sets the security headers of every response.
func (ui *UI) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
			"connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		// With no-referrer, browsers send "Origin: null" on form posts.
		h.Set("Referrer-Policy", "same-origin")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if !strings.HasPrefix(r.URL.Path, "/static/") {
			h.Set("Cache-Control", "no-store")
		}
		if ui.secure {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// checkOrigin refuses state-changing requests from other origins, also
// before the login (login CSRF).
func (ui *UI) checkOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			origin := r.Header.Get("Origin")
			// Without a usable Origin header, the browser's Sec-Fetch-Site decides.
			sameSite := origin == ui.origin ||
				((origin == "" || origin == "null") && r.Header.Get("Sec-Fetch-Site") == "same-origin")
			if !sameSite {
				http.Error(w, "cross-origin request refused", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireSession lets only logged-in admins through. POST requests need
// the CSRF token of the session and, except for the logout, the admin role.
func (ui *UI) requireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess := ui.session(r)
		if sess == nil {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			http.Error(w, "not logged in", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			token := r.Header.Get(csrfHeader)
			if token == "" {
				token = r.PostFormValue(csrfField)
			}
			if subtle.ConstantTimeCompare([]byte(token), []byte(sess.CSRF)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
			if sess.Admin.Role != server.RoleAdmin && r.URL.Path != "/logout" {
				http.Error(w, "viewers cannot change anything", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, sess)))
	})
}

// session returns the valid session of the request, or nil.
func (ui *UI) session(r *http.Request) *server.Session {
	c, err := r.Cookie(sessionName)
	if err != nil || c.Value == "" {
		return nil
	}
	sess, err := ui.store.Session(c.Value, ui.now(), SessionMaxAge, SessionIdle)
	if err != nil {
		if !errors.Is(err, server.ErrNoSession) {
			ui.log.Error("session lookup failed", "err", err)
		}
		return nil
	}
	return sess
}

// currentSession returns the session put in the context by requireSession.
func (ui *UI) currentSession(r *http.Request) *server.Session {
	sess, _ := r.Context().Value(ctxKey{}).(*server.Session)
	return sess
}

// startSession logs the admin in and sets the session cookie.
func (ui *UI) startSession(w http.ResponseWriter, name, method string) error {
	now := ui.now()
	token, _, err := ui.store.CreateSession(name, now)
	if err != nil {
		return err
	}
	err = ui.store.Audit(actorPrefix+name, "login", name, method, now)
	if err != nil {
		return err
	}
	// Secure is off only for plain HTTP, e.g. localhost through an SSH tunnel.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // See above.
		Name:     sessionName,
		Value:    token,
		Path:     "/",
		MaxAge:   int(SessionMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   ui.secure,
		SameSite: http.SameSiteStrictMode,
	})
	ui.log.Info("admin logged in", "admin", name, "method", method)
	return nil
}

func (ui *UI) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // Secure is off only for plain HTTP.
		Name:     sessionName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   ui.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// addCeremony stores an open passkey prompt and returns its ID.
func (ui *UI) addCeremony(c *ceremony) (string, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	now := ui.now()
	for id, p := range ui.pending {
		if now.After(p.expires) {
			delete(ui.pending, id)
		}
	}
	if len(ui.pending) >= maxCeremony {
		return "", errTooMany
	}
	id, err := randomID()
	if err != nil {
		return "", err
	}
	c.expires = now.Add(ceremonyTTL)
	ui.pending[id] = c
	return id, nil
}

// takeCeremony removes and returns an open passkey prompt.
func (ui *UI) takeCeremony(id string) (*ceremony, error) {
	ui.mu.Lock()
	defer ui.mu.Unlock()
	c, ok := ui.pending[id]
	delete(ui.pending, id)
	if !ok || ui.now().After(c.expires) {
		return nil, errNoCeremony
	}
	return c, nil
}

// clientIP is the address of the peer; proxies are not trusted.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func randomID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
