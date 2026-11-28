package adminui

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/safing/portmaster/mgmt/policy"
	"github.com/safing/portmaster/mgmt/server"
)

// offlineState is the offline signing state of a group for the group page.
type offlineState struct {
	KeyFP string
	// Signed is the published signed group policy, nil if there is none.
	Signed *policy.GroupPolicy
	// DraftDiffers tells whether the settings differ from Signed.
	DraftDiffers bool
}

// offlineKeyFP returns the fingerprint of the offline key of the server,
// "" if offline signing is off.
func (ui *UI) offlineKeyFP() (string, error) {
	if ui.cfg.DataDir == "" {
		return "", nil
	}
	text, err := server.ReadOfflineKey(ui.cfg.DataDir)
	if err != nil || text == "" {
		return "", err
	}
	_, fp, err := server.ParseOfflineKey(text)
	return fp, err
}

// groupOffline returns the offline signing state of the group, nil if
// offline signing is off.
func (ui *UI) groupOffline(g *server.Group) (*offlineState, error) {
	fp, err := ui.offlineKeyFP()
	if err != nil || fp == "" {
		return nil, err
	}
	st := &offlineState{KeyFP: fp}
	st.Signed, err = server.SignedPolicy(g)
	if err != nil {
		return nil, err
	}
	st.DraftDiffers, err = server.DraftDiffers(g)
	if err != nil {
		return nil, err
	}
	return st, nil
}

func (ui *UI) handleGroupExport(w http.ResponseWriter, r *http.Request) {
	g, err := ui.store.Group(r.PathValue("name"))
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "export group", err)
		return
	}
	data, err := json.MarshalIndent(server.ExportGroup(g), "", "  ")
	if err != nil {
		ui.internalError(w, "export group", err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s.json", url.PathEscape(g.Name)))
	_, _ = w.Write(append(data, '\n')) //nolint:gosec // JSON download.
}

func (ui *UI) handleGroupPublish(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	file, _, err := r.FormFile("file")
	if err != nil {
		ui.renderGroup(w, r, http.StatusBadRequest, "Choose the signed file.", nil)
		return
	}
	defer func() { _ = file.Close() }()
	signed, err := io.ReadAll(io.LimitReader(file, server.MaxSignedSize+1))
	if err != nil {
		ui.renderGroup(w, r, http.StatusBadRequest, "The file could not be read.", nil)
		return
	}
	_, err = ui.store.Group(name)
	if errors.Is(err, server.ErrNotFound) {
		ui.notFound(w, r, navGroups, "There is no group with this name.")
		return
	}
	if err != nil {
		ui.internalError(w, "publish", err)
		return
	}
	gp, err := server.PublishSigned(ui.store, ui.cfg.DataDir, name, signed, ui.now())
	if err != nil {
		// Signature, group, version and size errors are the admin's to fix.
		ui.renderGroup(w, r, http.StatusBadRequest, "The signed policy was not published: "+err.Error(), nil)
		return
	}
	ui.audit(r, "group.publish", name, fmt.Sprintf("version %d", gp.Version))
	redirect(w, r, groupPath(name), "policy-published")
}
