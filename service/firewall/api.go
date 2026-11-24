package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/safing/portmaster/base/api"
	"github.com/safing/portmaster/base/log"
	"github.com/safing/portmaster/service/netenv"
	"github.com/safing/portmaster/service/network/netutils"
	"github.com/safing/portmaster/service/network/packet"
	"github.com/safing/portmaster/service/network/state"
	"github.com/safing/portmaster/service/process"
)

const (
	deniedMsgUnidentified = `%wFailed to identify the requesting process. Reload to try again.`

	deniedMsgSystem = `%wSystem access to the Portmaster API is not permitted.
You can enable the Development Mode to disable API authentication for development purposes.`

	deniedMsgUnauthorized = `%wThe requesting process is not authorized to access the Portmaster API.
Checked process paths:
%s

The authorized root path is %s.
You can enable the Development Mode to disable API authentication for development purposes.
For production use please create an API key in the settings.`

	deniedMsgMisconfigured = `%wThe authentication system is misconfigured.`
)

var (
	apiPortSet bool
	apiIP      net.IP
	apiPort    uint16
)

func prepAPIAuth() error {
	return api.SetAuthenticator(apiAuthenticator)
}

func startAPIAuth() {
	var err error
	apiIP, apiPort, err = netutils.ParseIPPort(apiListenAddress())
	if err != nil {
		log.Warningf("filter: failed to parse API address for improved api auth mechanism: %s", err)
		return
	}
	apiPortSet = true
	log.Tracef("filter: api port set to %d", apiPort)
}

func apiAuthenticator(r *http.Request, s *http.Server) (token *api.AuthToken, err error) {
	if configReady.IsSet() && devMode() {
		return &api.AuthToken{
			Read:  api.PermitSelf,
			Write: api.PermitSelf,
		}, nil
	}

	// get local IP/Port
	localIP, localPort, err := netutils.ParseIPPort(s.Addr)
	if err != nil {
		return nil, fmt.Errorf("failed to get local IP/Port: %w", err)
	}
	// Correct 0.0.0.0 to 127.0.0.1 to fix local process-based authentication,
	// if 0.0.0.0 is used as the API listen address.
	if localIP.Equal(net.IPv4zero) {
		localIP = net.IPv4(127, 0, 0, 1)
	}

	// get remote IP/Port
	remoteIP, remotePort, err := netutils.ParseIPPort(r.RemoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get remote IP/Port: %w", err)
	}

	// Check if the request is even local.
	myIP, err := netenv.IsMyIP(remoteIP)
	if err == nil && !myIP {
		// Return to caller that the request was not handled.
		return nil, nil
	}

	log.Tracer(r.Context()).Tracef("filter: authenticating API request from %s", r.RemoteAddr)

	// It is important that this works, retry 5 times: every 500ms for 2.5s.
	var retry bool
	for range 5 {
		retry, err = authenticateAPIRequest(
			r.Context(),
			&packet.Info{
				Inbound:  false, // outbound as we are looking for the process of the source address
				Version:  packet.IPv4,
				Protocol: packet.TCP,
				Src:      remoteIP,   // source as in the process we are looking for
				SrcPort:  remotePort, // source as in the process we are looking for
				Dst:      localIP,
				DstPort:  localPort,
				PID:      process.UndefinedProcessID,
			},
		)
		if !retry {
			break
		}
		// wait a little
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil {
		return nil, err
	}

	return &api.AuthToken{
		Read:  api.PermitSelf,
		Write: api.PermitSelf,
	}, nil
}

func authenticateAPIRequest(ctx context.Context, pktInfo *packet.Info) (retry bool, err error) {
	// Get authenticated path.
	authenticatedPath := module.instance.BinaryUpdates().GetMainDir()
	if authenticatedPath == "" {
		return false, fmt.Errorf(deniedMsgMisconfigured, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user
	}
	// Get real path.
	authenticatedPath, err = filepath.EvalSymlinks(authenticatedPath)
	if err != nil {
		return false, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user
	}
	// Add filepath separator to confine to directory.
	authenticatedPath += string(filepath.Separator)

	// Get process of request.
	pid, _, _ := process.GetPidOfConnection(ctx, pktInfo)
	if pid < 0 {
		return false, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user
	}
	trusted, originalPid, procsChecked := checkAPIProcess(ctx, pid, authenticatedPath)
	if trusted {
		// The process found for the connection is only one of the processes
		// that may hold its socket. Grant access only if all of them are
		// trusted, see checkAPISocketHolders.
		holders, holdersErr := lookupSocketHolders(pktInfo)
		return checkAPISocketHolders(ctx, pid, holders, holdersErr, authenticatedPath)
	}

	switch originalPid {
	case process.UnidentifiedProcessID:
		log.Tracer(ctx).Warningf("filter: denying api access: failed to identify process")
		return true, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user

	case process.SystemProcessID:
		log.Tracer(ctx).Warningf("filter: denying api access: request by system")
		return false, fmt.Errorf(deniedMsgSystem, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user

	default: // normal process
		log.Tracer(ctx).Warningf("filter: denying api access to %s - also checked %s (trusted root is %s)", procsChecked[0], strings.Join(procsChecked[1:], " "), module.instance.BinDir())
		return false, fmt.Errorf( //nolint:staticcheck // message for user
			deniedMsgUnauthorized,
			api.ErrAPIAccessDeniedMessage,
			strings.Join(procsChecked, "\n"),
			authenticatedPath,
		)
	}
}

// getAPIProcess and lookupSocketHolders are variables for testing.
var (
	getAPIProcess       = process.GetOrFindProcess
	lookupSocketHolders = state.LookupSocketHolders
)

// checkAPIProcess checks whether the process with the given PID is trusted to
// access the API on its own: its executable is in the authenticated path or
// explicitly allowed, or it is the webview of such a process.
// originalPid is the PID of the process, or a special PID if it could not be
// identified. procsChecked lists the paths of the untrusted processes.
func checkAPIProcess(ctx context.Context, pid int, authenticatedPath string) (trusted bool, originalPid int, procsChecked []string) {
	proc, err := getAPIProcess(ctx, pid)
	if err != nil {
		log.Tracer(ctx).Debugf("filter: failed to get process of api request: %s", err)
		return false, process.UnidentifiedProcessID, nil
	}
	originalPid = proc.Pid
	var previousPid int

	// Find parent for up to two levels, if we don't match the path.
	checkLevels := 2
checkLevelsLoop:
	for i := range checkLevels + 1 {
		// Check for eligible path.
		switch proc.Pid {
		case process.UnidentifiedProcessID, process.SystemProcessID:
			break checkLevelsLoop
		default: // normal process
			// Check if the requesting process is in database root / updates dir.
			realPath, err := filepath.EvalSymlinks(proc.Path)
			if err == nil {

				// check if the client has been allowed by flag
				if slices.Contains(allowedClients, realPath) {
					return true, originalPid, nil
				}

				if strings.HasPrefix(realPath, authenticatedPath) {
					// The trusted binary may have been started with foreign
					// code, check it and the requesting process (a webview).
					for _, checkPid := range []int{proc.Pid, originalPid} {
						if tampered, reason := checkProcessTampered(checkPid); tampered {
							log.Tracer(ctx).Warningf("filter: denying api access to %s (pid %d): %s", proc.Path, checkPid, reason)
							return false, originalPid, append(procsChecked, proc.Path)
						}
					}
					return true, originalPid, nil
				}
			}
		}

		// Add checked path to list.
		procsChecked = append(procsChecked, proc.Path)

		// Only the webview of the app inherits the trust of its parent.
		// Any other process started from the app, like a browser opened
		// by a link, must not get access to the API through its parent.
		if !isEmbeddedWebViewProcess(proc.Path) {
			break checkLevelsLoop
		}

		// Get the parent process.
		if i < checkLevels {
			// save previous PID
			previousPid = proc.Pid

			// get parent process
			proc, err = getAPIProcess(ctx, proc.ParentPid)
			if err != nil {
				log.Tracer(ctx).Debugf("filter: failed to get parent process of api request: %s", err)
				break
			}

			// abort if we are looping
			if proc.Pid == previousPid {
				// this also catches -1 pid loops
				break
			}
		}
	}

	return false, originalPid, procsChecked
}

// checkAPISocketHolders decides about an API request whose connection was
// attributed to the trusted process trustedPid. holders and holdersErr are the
// result of looking up all processes that hold the socket of the connection.
//
// A socket can be held by several processes. An untrusted process could open
// a connection to the API and then start a trusted binary, like the app, that
// inherits the socket. The lookup of the connection might then find the
// trusted child, while the untrusted parent sends the requests. Therefore,
// access is only granted if every process that holds the socket is trusted
// on its own. If the holders cannot be determined, access is denied.
//
// This does not help against a process that hides its descriptor while the
// request is authenticated (eg. by closing it after sending the request, or
// by keeping it in flight in a unix socket), or against code injected into a
// trusted process. The legitimate app is expected to hold its sockets alone:
// the app and its webview processes open their own connections, and sockets
// are opened with close-on-exec, so programs started from the app do not
// inherit them.
func checkAPISocketHolders(ctx context.Context, trustedPid int, holders []int, holdersErr error, authenticatedPath string) (retry bool, err error) {
	switch {
	case errors.Is(holdersErr, state.ErrSocketHoldersUnsupported):
		// There is no way to list the holders of a socket on this system (eg.
		// Windows, which attributes a socket to the process that opened it),
		// keep the result of the connection's process.
		return false, nil

	case errors.Is(holdersErr, state.ErrConnectionNotFound), errors.Is(holdersErr, state.ErrPIDNotFound):
		// The socket tables may not have caught up yet, try again.
		log.Tracer(ctx).Warningf("filter: denying api access: failed to find the holders of the socket: %s", holdersErr)
		return true, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user

	case holdersErr != nil:
		log.Tracer(ctx).Warningf("filter: denying api access: failed to find the holders of the socket: %s", holdersErr)
		return false, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user

	case len(holders) == 0:
		log.Tracer(ctx).Warningf("filter: denying api access: found no holders of the socket")
		return true, fmt.Errorf(deniedMsgUnidentified, api.ErrAPIAccessDeniedMessage) //nolint:staticcheck // message for user
	}

	var untrusted []string
	for _, pid := range holders {
		if pid == trustedPid {
			continue // Already checked.
		}
		trusted, originalPid, procsChecked := checkAPIProcess(ctx, pid, authenticatedPath)
		switch {
		case trusted:
		case originalPid == process.UnidentifiedProcessID:
			// The process may have exited, or its PID been reused since the
			// scan. Either way it cannot be shown to be trusted.
			untrusted = append(untrusted, fmt.Sprintf("unidentified process (PID %d)", pid))
		case len(procsChecked) > 0:
			untrusted = append(untrusted, procsChecked[0])
		default:
			untrusted = append(untrusted, fmt.Sprintf("process with PID %d", pid))
		}
	}
	if len(untrusted) == 0 {
		return false, nil
	}

	log.Tracer(ctx).Warningf("filter: denying api access: the socket of the trusted process %d is also held by %s", trustedPid, strings.Join(untrusted, ", "))
	return false, fmt.Errorf( //nolint:staticcheck // message for user
		deniedMsgUnauthorized,
		api.ErrAPIAccessDeniedMessage,
		strings.Join(untrusted, "\n"),
		authenticatedPath,
	)
}

// embeddedWebViewProcesses are the executables of the webview runtimes that
// the app uses to render its UI: WebView2 on Windows and WebKitGTK on Linux.
var embeddedWebViewProcesses = []string{
	"msedgewebview2.exe",
	"webkitwebprocess",
	"webkitnetworkprocess",
}

// isEmbeddedWebViewProcess returns whether the given executable is a process
// of a webview runtime.
func isEmbeddedWebViewProcess(binPath string) bool {
	// The path may come from another OS than the one running the check in tests.
	name := binPath
	if i := strings.LastIndexAny(name, `/\`); i >= 0 {
		name = name[i+1:]
	}
	return slices.Contains(embeddedWebViewProcesses, strings.ToLower(name))
}
