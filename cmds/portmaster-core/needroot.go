package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"runtime"
)

// The running Portmaster only lets root enroll, pull or leave, and, while the
// computer is managed, import settings and profiles (see api.RequireRoot).
// The checks here only stop early with a helpful message; the API decides.

var errNeedRoot = errors.New("only root may do this")

// checkRunAsRoot returns an error if the command does not run as root on
// Linux. On other systems the API does not check the user yet.
func checkRunAsRoot(action string) error {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return nil
	}
	return fmt.Errorf("%w: %s; run the command with sudo", errNeedRoot, action)
}

// checkRunAsRootIfManaged is checkRunAsRoot, but only while this computer is
// managed. If the status cannot be read, the API decides.
func checkRunAsRootIfManaged(ctx context.Context, action string) error {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return nil
	}
	data, err := syncRequest(ctx, http.MethodGet, "managed/status", url.Values{}, mimeJSON, nil)
	if err != nil {
		return nil //nolint:nilerr // The API decides.
	}
	var status struct {
		Enrolled bool `json:"enrolled"`
	}
	err = json.Unmarshal(data, &status)
	if err != nil {
		return nil //nolint:nilerr // The API decides.
	}
	if !status.Enrolled {
		return nil
	}
	return checkRunAsRoot(action + " on a managed computer")
}
