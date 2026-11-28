package adminui

import (
	"bytes"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/safing/portmaster/mgmt/server"
)

const loginFailed = "Login failed."

// page is the data of a rendered page.
type page struct {
	Title string
	// Nav is the title of the active navigation item.
	Nav    string
	Now    time.Time
	Admin  *server.Admin
	CSRF   string
	Error  string
	Notice string
	Data   any
}

// CanWrite tells whether the admin may change things; viewers see no forms.
func (p *page) CanWrite() bool { return p.Admin != nil && p.Admin.Role == server.RoleAdmin }

func parsePages() (map[string]*template.Template, error) {
	pages := make(map[string]*template.Template)
	for _, name := range []string{"login", "setup", "dashboard", "computers", "computer", "groups", "group", "tokens", "blocks", "alerts", "audit", "message"} {
		t, err := template.New(name).Funcs(templateFuncs).ParseFS(templateFS, "templates/layout.html", "templates/partials.html", "templates/"+name+".html")
		if err != nil {
			return nil, err
		}
		pages[name] = t
	}
	return pages, nil
}

func (ui *UI) render(w http.ResponseWriter, status int, name string, p *page) {
	if p.Now.IsZero() {
		p.Now = ui.now()
	}
	var buf bytes.Buffer
	err := ui.pages[name].ExecuteTemplate(&buf, "layout", p)
	if err != nil {
		ui.log.Error("render page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (ui *UI) writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		ui.log.Debug("write response", "err", err)
	}
}

func (ui *UI) jsonError(w http.ResponseWriter, status int, msg string) {
	ui.writeJSON(w, status, map[string]string{"error": msg})
}

// --- Login ---

func (ui *UI) handleLoginPage(w http.ResponseWriter, r *http.Request) {
	if ui.session(r) != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	p := &page{Title: "Log in"}
	if r.URL.Query().Get("setup") == "done" {
		p.Notice = "Setup complete. You can log in now."
	}
	ui.render(w, http.StatusOK, "login", p)
}

func (ui *UI) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	now := ui.now()
	name := strings.TrimSpace(r.PostFormValue("name"))
	ip := "ip:" + clientIP(r)
	keys := []string{ip, "name:" + name}
	fail := func(status int, msg string) {
		ui.render(w, status, "login", &page{Title: "Log in", Error: msg})
	}
	if ui.limit.blocked(now, keys...) {
		fail(http.StatusTooManyRequests, "Too many failed logins. Try again later.")
		return
	}
	admin, err := ui.store.Admin(name)
	step, ok := int64(0), false
	if err == nil && admin.TOTPSecret != "" {
		step, ok = verifyTOTP(admin.TOTPSecret, r.PostFormValue("code"), now)
	}
	if ok {
		ok, err = ui.store.UseTOTPStep(name, step)
		if err != nil {
			ui.log.Error("record TOTP step", "err", err)
			ok = false
		}
	}
	if !ok {
		ui.limit.fail(now, keys...)
		ui.log.Warn("failed TOTP login", "admin", name, "ip", ip)
		fail(http.StatusUnauthorized, loginFailed)
		return
	}
	err = ui.startSession(w, name, "totp")
	if err != nil {
		ui.log.Error("start session", "err", err)
		fail(http.StatusInternalServerError, loginFailed)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (ui *UI) handleLoginBegin(w http.ResponseWriter, r *http.Request) {
	if ui.limit.blocked(ui.now(), "ip:"+clientIP(r)) {
		ui.jsonError(w, http.StatusTooManyRequests, "Too many failed logins. Try again later.")
		return
	}
	options, data, err := ui.wa.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		ui.log.Error("begin passkey login", "err", err)
		ui.jsonError(w, http.StatusInternalServerError, loginFailed)
		return
	}
	id, err := ui.addCeremony(&ceremony{data: data})
	if err != nil {
		ui.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	ui.writeJSON(w, http.StatusOK, map[string]any{"id": id, "options": options})
}

func (ui *UI) handleLoginFinish(w http.ResponseWriter, r *http.Request) {
	now := ui.now()
	ip := "ip:" + clientIP(r)
	if ui.limit.blocked(now, ip) {
		ui.jsonError(w, http.StatusTooManyRequests, "Too many failed logins. Try again later.")
		return
	}
	c, err := ui.takeCeremony(r.URL.Query().Get("id"))
	if err != nil || c.token != "" {
		ui.jsonError(w, http.StatusBadRequest, "The passkey prompt expired. Try again.")
		return
	}
	var admin *server.Admin
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		a, err := ui.store.AdminByHandle(userHandle)
		if err != nil {
			return nil, errNoAdminUser
		}
		admin = a
		return newUser(a)
	}
	_, cred, err := ui.wa.FinishPasskeyLogin(handler, *c.data, r)
	if err != nil {
		ui.limit.fail(now, ip)
		ui.log.Warn("failed passkey login", "ip", ip, "err", err)
		ui.jsonError(w, http.StatusUnauthorized, loginFailed)
		return
	}
	if cred.Authenticator.CloneWarning {
		ui.log.Warn("passkey sign count went back, it may be cloned", "admin", admin.Name)
	}
	data, err := json.Marshal(cred)
	if err == nil {
		err = ui.store.UpdatePasskey(cred.ID, data)
	}
	if err == nil {
		err = ui.startSession(w, admin.Name, "passkey")
	}
	if err != nil {
		ui.log.Error("passkey login", "err", err)
		ui.jsonError(w, http.StatusInternalServerError, loginFailed)
		return
	}
	ui.writeJSON(w, http.StatusOK, map[string]string{"next": "/"})
}

func (ui *UI) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess := ui.currentSession(r)
	c, err := r.Cookie(sessionName)
	if err == nil {
		err = ui.store.DeleteSession(c.Value)
	}
	if err == nil {
		err = ui.store.Audit(actorPrefix+sess.Admin.Name, "logout", sess.Admin.Name, "", ui.now())
	}
	if err != nil {
		ui.log.Error("logout", "err", err)
	}
	ui.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// --- Setup with a one-time link ---

type setupData struct {
	Token      string
	TOTPSecret string
	TOTPURI    string
	Passkeys   int
	HasTOTP    bool
}

func (ui *UI) setupAdmin(w http.ResponseWriter, r *http.Request, token string) *server.Admin {
	now := ui.now()
	ip := "ip:" + clientIP(r)
	if ui.limit.blocked(now, ip) {
		ui.render(w, http.StatusTooManyRequests, "setup", &page{Title: "Set up", Error: "Too many failed attempts. Try again later."})
		return nil
	}
	admin, err := ui.store.SetupAdmin(token, now)
	if err != nil {
		ui.limit.fail(now, ip)
		ui.render(w, http.StatusNotFound, "setup", &page{Title: "Set up", Error: "This setup link is invalid or expired. Ask for a new one (admin reset)."})
		return nil
	}
	return admin
}

func (ui *UI) renderSetup(w http.ResponseWriter, status int, admin *server.Admin, token, secret, errMsg string) {
	var err error
	if secret == "" {
		secret, err = newTOTPSecret()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
	}
	ui.render(w, status, "setup", &page{
		Title: "Set up " + admin.Name,
		Admin: admin,
		Error: errMsg,
		Data: &setupData{
			Token:      token,
			TOTPSecret: secret,
			TOTPURI:    totpURI(issuer, admin.Name, secret),
			Passkeys:   len(admin.Credentials),
			HasTOTP:    admin.TOTPSecret != "",
		},
	})
}

func (ui *UI) handleSetupPage(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	admin := ui.setupAdmin(w, r, token)
	if admin == nil {
		return
	}
	ui.renderSetup(w, http.StatusOK, admin, token, "", "")
}

func (ui *UI) handleSetupTOTP(w http.ResponseWriter, r *http.Request) {
	token := r.PostFormValue("token")
	admin := ui.setupAdmin(w, r, token)
	if admin == nil {
		return
	}
	now := ui.now()
	secret := r.PostFormValue("secret")
	step, ok := verifyTOTP(secret, r.PostFormValue("code"), now)
	if !ok {
		ui.limit.fail(now, "ip:"+clientIP(r))
		ui.renderSetup(w, http.StatusBadRequest, admin, token, secret, "The code does not match. Check the time of the device and try again.")
		return
	}
	err := ui.store.SetTOTP(token, secret, step, now)
	if err == nil {
		err = ui.store.Audit(actorPrefix+admin.Name, "admin.totp", admin.Name, "set up", now)
	}
	if err != nil {
		ui.log.Error("set up TOTP", "err", err)
		http.Error(w, "setup failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login?setup=done", http.StatusSeeOther)
}

func (ui *UI) handleSetupBegin(w http.ResponseWriter, r *http.Request) {
	now := ui.now()
	ip := "ip:" + clientIP(r)
	var req struct {
		Token string `json:"token"`
	}
	if ui.limit.blocked(now, ip) {
		ui.jsonError(w, http.StatusTooManyRequests, "Too many failed attempts. Try again later.")
		return
	}
	err := json.NewDecoder(r.Body).Decode(&req)
	var admin *server.Admin
	if err == nil {
		admin, err = ui.store.SetupAdmin(req.Token, now)
	}
	if err != nil {
		ui.limit.fail(now, ip)
		ui.jsonError(w, http.StatusNotFound, "This setup link is invalid or expired.")
		return
	}
	user, err := newUser(admin)
	if err != nil {
		ui.jsonError(w, http.StatusInternalServerError, "setup failed")
		return
	}
	options, data, err := ui.wa.BeginRegistration(user,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(webauthn.Credentials(user.creds).CredentialDescriptors()),
	)
	if err != nil {
		ui.log.Error("begin passkey registration", "err", err)
		ui.jsonError(w, http.StatusInternalServerError, "setup failed")
		return
	}
	id, err := ui.addCeremony(&ceremony{data: data, token: req.Token})
	if err != nil {
		ui.jsonError(w, http.StatusServiceUnavailable, err.Error())
		return
	}
	ui.writeJSON(w, http.StatusOK, map[string]any{"id": id, "options": options})
}

func (ui *UI) handleSetupFinish(w http.ResponseWriter, r *http.Request) {
	now := ui.now()
	c, err := ui.takeCeremony(r.URL.Query().Get("id"))
	if err != nil || c.token == "" {
		ui.jsonError(w, http.StatusBadRequest, "The passkey prompt expired. Try again.")
		return
	}
	admin, err := ui.store.SetupAdmin(c.token, now)
	if err != nil {
		ui.jsonError(w, http.StatusNotFound, "This setup link is invalid or expired.")
		return
	}
	user, err := newUser(admin)
	if err != nil {
		ui.jsonError(w, http.StatusInternalServerError, "setup failed")
		return
	}
	cred, err := ui.wa.FinishRegistration(user, *c.data, r)
	if err != nil {
		ui.log.Warn("passkey registration failed", "admin", admin.Name, "err", err)
		ui.jsonError(w, http.StatusBadRequest, "The passkey could not be registered.")
		return
	}
	data, err := json.Marshal(cred)
	if err == nil {
		err = ui.store.AddPasskey(c.token, cred.ID, data, now)
	}
	if err == nil {
		err = ui.store.Audit(actorPrefix+admin.Name, "admin.passkey", admin.Name, "added", now)
	}
	if err != nil {
		ui.log.Error("store passkey", "err", err)
		ui.jsonError(w, http.StatusInternalServerError, "setup failed")
		return
	}
	ui.writeJSON(w, http.StatusOK, map[string]string{"next": "/login?setup=done"})
}

// --- WebAuthn user ---

// user adapts an admin to webauthn.User.
type user struct {
	admin *server.Admin
	creds []webauthn.Credential
}

func newUser(a *server.Admin) (*user, error) {
	u := &user{admin: a, creds: make([]webauthn.Credential, 0, len(a.Credentials))}
	for _, raw := range a.Credentials {
		var c webauthn.Credential
		err := json.Unmarshal(raw, &c)
		if err != nil {
			return nil, errors.Join(errNoAdminUser, err)
		}
		u.creds = append(u.creds, c)
	}
	return u, nil
}

func (u *user) WebAuthnID() []byte                         { return u.admin.Handle }
func (u *user) WebAuthnName() string                       { return u.admin.Name }
func (u *user) WebAuthnDisplayName() string                { return u.admin.Name }
func (u *user) WebAuthnCredentials() []webauthn.Credential { return u.creds }
