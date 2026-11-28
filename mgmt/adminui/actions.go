package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/safing/portmaster/mgmt/server"
)

const (
	// maxTokenValidity limits the validity of an enrollment token.
	maxTokenValidity = 30 * 24 * time.Hour
	// maxProfileBytes limits an uploaded profile export.
	maxProfileBytes = 512 << 10
)

// notices are the messages shown after a change, by the msg parameter of
// the redirect; the parameter never carries text into the page.
var notices = map[string]string{ //nolint:gosec // Message keys, no credentials.
	"group-created":       "Group created.",
	"alerts-acked":        "Alerts acknowledged.",
	"policy-published":    "Signed policy published. The computers of the group get it with their next pull.",
	"silent-after-saved":  "Silent threshold saved; it applies from the next check (every 5 minutes).",
	"block-summary-on":    "Block summary on. The computers of the group send it from their next pull; the Portmaster app shows this to the users.",
	"block-summary-off":   "Block summary off. The computers of the group stop sending it with their next pull.",
	"group-deleted":       "Group deleted.",
	"settings-saved":      "Settings saved. The computers of the group get them with their next pull.",
	"rules-saved":         "Rules saved. The computers of the group get them with their next pull.",
	"profile-added":       "Profile saved. The computers of the group get it with their next pull.",
	"profile-removed":     "Profile removed.",
	"token-revoked":       "Token revoked.",
	"computer-moved":      "Computer moved. It gets the policy of its new group with its next pull.",
	"computer-revoked":    "Computer revoked. The server rejects its certificate from now on.",
	"computer-unknown":    "There is no computer with this ID.",
	"computer-same-group": "The computer is in this group already.",
	"token-unknown":       "There is no unused token with this ID.",
	"group-not-deleted":   "The group still has computers (revoked ones count too); move them first.",
}

// groupForm holds the editable values of a group, as stored or as submitted.
type groupForm struct {
	Settings         string
	Locked           string
	Endpoints        string
	ServiceEndpoints string
}

func newGroupForm(g *server.Group) (*groupForm, error) {
	form := &groupForm{Locked: strings.Join(g.Locked, "\n")}
	if len(g.Settings) > 0 {
		data, err := server.SettingsYAML(g.Settings)
		if err != nil {
			return nil, err
		}
		form.Settings = string(data)
	}
	if g.Rules != nil {
		form.Endpoints = strings.Join(g.Rules.Endpoints, "\n")
		form.ServiceEndpoints = strings.Join(g.Rules.ServiceEndpoints, "\n")
	}
	return form, nil
}

// actor is the audit actor of the logged-in admin.
func (ui *UI) actor(r *http.Request) string {
	return actorPrefix + ui.currentSession(r).Admin.Name
}

// audit records a change; a failure is logged, the change stays.
func (ui *UI) audit(r *http.Request, action, object, detail string) {
	err := ui.store.Audit(ui.actor(r), action, object, detail, ui.now())
	if err != nil {
		ui.log.Error("audit", "action", action, "err", err)
	}
}

func redirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	// path is a local path built with url.PathEscape, msg a fixed key.
	http.Redirect(w, r, path+"?msg="+msg, http.StatusSeeOther) //nolint:gosec // See above.
}

func groupPath(name string) string { return "/groups/" + url.PathEscape(name) }

// --- Groups ---

func (ui *UI) handleGroupCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("name"))
	err := ui.store.CreateGroup(name, ui.now())
	if err != nil {
		msg := "The group could not be created: " + err.Error()
		if errors.Is(err, server.ErrExists) {
			msg = "A group with this name exists already."
		}
		ui.renderGroups(w, r, http.StatusBadRequest, msg, name)
		return
	}
	ui.audit(r, "group.create", name, "")
	redirect(w, r, groupPath(name), "group-created")
}

func (ui *UI) handleGroupDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	err := ui.store.DeleteGroup(name)
	switch {
	case errors.Is(err, server.ErrNotFound):
		ui.notFound(w, r, navGroups, "There is no group with this name.")
	case errors.Is(err, server.ErrGroupInUse):
		redirect(w, r, groupPath(name), "group-not-deleted")
	case err != nil:
		ui.internalError(w, "delete group", err)
	default:
		ui.audit(r, "group.delete", name, "")
		redirect(w, r, "/groups", "group-deleted")
	}
}

func (ui *UI) handleGroupSettings(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	form := &groupForm{Settings: r.PostFormValue("settings"), Locked: r.PostFormValue("locked")}
	fail := func(msg string) {
		// Keep the stored rules in the rules form.
		if g, err := ui.store.Group(name); err == nil { //nolint:noinlineerr // Only to refill the form.
			if stored, err := newGroupForm(g); err == nil { //nolint:noinlineerr // See above.
				form.Endpoints, form.ServiceEndpoints = stored.Endpoints, stored.ServiceEndpoints
			}
		}
		ui.renderGroup(w, r, http.StatusBadRequest, msg, form)
	}
	settings := map[string]any{}
	if strings.TrimSpace(form.Settings) != "" {
		var err error
		settings, err = server.ParseSettings([]byte(form.Settings))
		if err != nil {
			fail("The settings are invalid: " + err.Error())
			return
		}
	}
	var locked []string
	if r.PostFormValue("lockall") != "" {
		locked = server.SortedKeys(settings)
	} else {
		for line := range strings.Lines(form.Locked) {
			if key := strings.TrimSpace(line); key != "" {
				locked = append(locked, key)
			}
		}
	}
	err := ui.store.SetGroupPolicy(name, settings, locked, ui.now())
	switch {
	case errors.Is(err, server.ErrNotFound):
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	case errors.Is(err, server.ErrLockNotSet):
		fail("The locked keys are invalid: " + err.Error())
		return
	case err != nil:
		ui.internalError(w, "set group settings", err)
		return
	}
	ui.audit(r, "group.set", name, fmt.Sprintf("%d settings, %d locked", len(settings), len(locked)))
	redirect(w, r, groupPath(name), "settings-saved")
}

func (ui *UI) handleGroupRules(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	endpoints, services := r.PostFormValue("endpoints"), r.PostFormValue("serviceEndpoints")
	rules, err := server.RulesFromLines(endpoints, services)
	if err != nil {
		form := &groupForm{Endpoints: endpoints, ServiceEndpoints: services}
		if g, gerr := ui.store.Group(name); gerr == nil { //nolint:noinlineerr // Only to refill the form.
			if stored, ferr := newGroupForm(g); ferr == nil { //nolint:noinlineerr // See above.
				form.Settings, form.Locked = stored.Settings, stored.Locked
			}
		}
		ui.renderGroup(w, r, http.StatusBadRequest, "The rules are invalid: "+err.Error(), form)
		return
	}
	err = ui.store.SetGroupRules(name, rules, ui.now())
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "set group rules", err)
		return
	}
	detail := "cleared"
	if rules != nil {
		detail = fmt.Sprintf("%d endpoint rules, %d service rules", len(rules.Endpoints), len(rules.ServiceEndpoints))
	}
	ui.audit(r, "group.rules", name, detail)
	redirect(w, r, groupPath(name), "rules-saved")
}

// handleProfileAdd adds a profile export (uploaded file or pasted text) to
// the group; a profile with the same name is replaced.
func (ui *UI) handleProfileAdd(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	data := []byte(r.PostFormValue("profile"))
	if file, _, err := r.FormFile("file"); err == nil { //nolint:noinlineerr // The file is optional.
		defer func() { _ = file.Close() }()
		upload, err := io.ReadAll(io.LimitReader(file, maxProfileBytes+1))
		if err != nil || len(upload) > maxProfileBytes {
			ui.renderGroup(w, r, http.StatusBadRequest, "The file could not be read or is too large.", nil)
			return
		}
		if len(upload) > 0 {
			data = upload
		}
	}
	profile, err := server.ParseProfile(data)
	if err != nil {
		ui.renderGroup(w, r, http.StatusBadRequest, "This is not a profile export: "+err.Error(), nil)
		return
	}
	g, err := ui.store.Group(name)
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "add profile", err)
		return
	}
	profileName := server.ProfileName(profile)
	profiles := make([]json.RawMessage, 0, len(g.Profiles)+1)
	detail := "added " + profileName
	for _, p := range g.Profiles {
		if server.ProfileName(p) == profileName {
			detail = "replaced " + profileName
			continue
		}
		profiles = append(profiles, p)
	}
	profiles = append(profiles, profile)
	err = ui.store.SetGroupProfiles(name, profiles, ui.now())
	if err != nil {
		ui.internalError(w, "add profile", err)
		return
	}
	ui.audit(r, "group.profiles", name, detail)
	redirect(w, r, groupPath(name), "profile-added")
}

func (ui *UI) handleProfileRemove(w http.ResponseWriter, r *http.Request) {
	name, profileName := r.PathValue("name"), r.PostFormValue("profile")
	g, err := ui.store.Group(name)
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "remove profile", err)
		return
	}
	profiles := make([]json.RawMessage, 0, len(g.Profiles))
	for _, p := range g.Profiles {
		if server.ProfileName(p) != profileName {
			profiles = append(profiles, p)
		}
	}
	if len(profiles) == len(g.Profiles) {
		ui.renderGroup(w, r, http.StatusBadRequest, "The group has no profile with this name.", nil)
		return
	}
	err = ui.store.SetGroupProfiles(name, profiles, ui.now())
	if err != nil {
		ui.internalError(w, "remove profile", err)
		return
	}
	ui.audit(r, "group.profiles", name, "removed "+profileName)
	redirect(w, r, groupPath(name), "profile-removed")
}

// --- Tokens ---

// newToken is a token just created; it is shown once.
type newToken struct {
	Token   string
	Group   string
	Expires time.Time
	Command string
}

func (ui *UI) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	group := r.PostFormValue("group")
	valid, err := time.ParseDuration(r.PostFormValue("valid"))
	if err != nil || valid <= 0 || valid > maxTokenValidity {
		ui.renderTokens(w, r, http.StatusBadRequest, "The validity must be a duration up to 720h, e.g. 24h.", nil)
		return
	}
	serverURL := strings.TrimSpace(r.PostFormValue("url"))
	if u, err := url.Parse(serverURL); err != nil || u.Scheme != schemeHTTPS || u.Host == "" { //nolint:noinlineerr // Validation only.
		ui.renderTokens(w, r, http.StatusBadRequest, "The server URL must be https://host:port.", nil)
		return
	}
	now := ui.now()
	token, err := ui.store.CreateToken(group, valid, now)
	if errors.Is(err, server.ErrNotFound) {
		ui.renderTokens(w, r, http.StatusBadRequest, "There is no group with this name.", nil)
		return
	}
	if err != nil {
		ui.internalError(w, "create token", err)
		return
	}
	ui.audit(r, "token.create", group, "valid "+valid.String())
	command := fmt.Sprintf("portmaster-core manage enroll --server %s --token %s \\\n  --server-fp %s \\\n  --policy-key-fp %s",
		serverURL, token, ui.cfg.ServerFP, ui.cfg.PolicyKeyFP)
	offlineFP, err := ui.offlineKeyFP()
	if err != nil {
		ui.log.Error("read offline key", "err", err)
	}
	if offlineFP != "" {
		command += " \\\n  --offline-key-fp " + offlineFP
	}
	ui.renderTokens(w, r, http.StatusOK, "", &newToken{Token: token, Group: group, Expires: now.Add(valid), Command: command})
}

func (ui *UI) handleTokenRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	group, err := ui.store.RevokeToken(id)
	switch {
	case errors.Is(err, server.ErrNotFound), errors.Is(err, server.ErrTokenUsed):
		redirect(w, r, "/tokens", "token-unknown")
	case err != nil:
		ui.internalError(w, "revoke token", err)
	default:
		ui.audit(r, "token.revoke", group, "token "+id)
		redirect(w, r, "/tokens", "token-revoked")
	}
}

// --- Computers ---

func computerPath(id string) string { return "/computers/" + url.PathEscape(id) }

func (ui *UI) handleComputerMove(w http.ResponseWriter, r *http.Request) {
	id, group := r.PathValue("id"), r.PostFormValue("group")
	err := ui.store.MoveComputer(id, group, ui.now())
	switch {
	case errors.Is(err, server.ErrSameGroup):
		redirect(w, r, computerPath(id), "computer-same-group")
	case errors.Is(err, server.ErrNotFound):
		ui.notFound(w, r, navComputers, "There is no such computer or group.")
	case err != nil:
		ui.internalError(w, "move computer", err)
	default:
		ui.audit(r, "computer.move", id, "to "+group)
		redirect(w, r, computerPath(id), "computer-moved")
	}
}

func (ui *UI) handleComputerRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := ui.store.Revoke(id)
	switch {
	case errors.Is(err, server.ErrNotFound):
		redirect(w, r, "/computers", "computer-unknown")
	case err != nil:
		ui.internalError(w, "revoke computer", err)
	default:
		ui.audit(r, "computer.revoke", id, "")
		redirect(w, r, computerPath(id), "computer-revoked")
	}
}
