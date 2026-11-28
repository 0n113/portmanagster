package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/safing/portmaster/mgmt/server"
)

// silentCheckEvery is the interval of the silent check; clients pull every
// 5 minutes.
const silentCheckEvery = 5 * time.Minute

// testName fills the fields of the test alert.
const testName = "test"

var (
	errBadDuration = errors.New("invalid duration: use e.g. 24h, 90m or 0")
	errBadAlertID  = errors.New("invalid alert ID")

	alertWebhook      string
	alertWebhookLevel string
	alertRetention    time.Duration
	alertFilter       server.AlertFilter
)

var groupSilentAfterCmd = &cobra.Command{
	Use:   "silent-after NAME DURATION",
	Short: "Set after how long without contact a computer of the group raises an alert (0 turns it off)",
	Long: `Set after how long without contact a computer of the group raises an alert,
e.g. 24h (the default) or 2h. 0 turns the alert off for the group.`,
	Args: cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		d, err := time.ParseDuration(args[1])
		if err != nil || d < 0 {
			return fmt.Errorf("%w: %q", errBadDuration, args[1])
		}
		return audited("group.silentafter", args[0], d.String(), func(s *server.Store) error {
			return s.SetGroupSilentAfter(args[0], d)
		})
	},
}

var alertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "List alerts, the last changed first (default: open alerts)",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		return withStore(func(s *server.Store) error {
			list, err := s.Alerts(alertFilter)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "ID\tSTATE\tLEVEL\tKIND\tHOSTNAME\tGROUP\tCOUNT\tLAST (UTC)\tMESSAGE")
			for _, a := range list {
				_, _ = fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\n", a.ID, a.State, a.Level, a.Kind,
					a.Hostname, a.Group, a.Count, a.Last.Format(time.DateTime), a.Message)
			}
			return w.Flush()
		})
	},
}

var alertCmd = &cobra.Command{Use: "alert", Short: "Acknowledge alerts and test the webhook"}

var alertAckCmd = &cobra.Command{
	Use:   "ack ID...",
	Short: "Acknowledge new alerts",
	Long: `Acknowledge new alerts. Condition alerts (silent, interception, problems,
refused, error, overridden) stay open until the condition ends; malware and new
app alerts are done when acknowledged.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		ids := make([]int64, 0, len(args))
		for _, arg := range args {
			id, err := strconv.ParseInt(arg, 10, 64)
			if err != nil {
				return fmt.Errorf("%w: %q", errBadAlertID, arg)
			}
			ids = append(ids, id)
		}
		return withStore(func(s *server.Store) error {
			acked, err := s.AckAlerts(ids, cliActor, time.Now())
			if err != nil {
				return err
			}
			for _, id := range acked {
				err = s.Audit(cliActor, "alert.ack", strconv.FormatInt(id, 10), "", time.Now())
				if err != nil {
					return err
				}
			}
			_, _ = fmt.Fprintf(os.Stdout, "acknowledged %d of %d alerts (the others were not new)\n", len(acked), len(ids))
			return nil
		})
	},
}

var alertTestWebhookCmd = &cobra.Command{
	Use:   "test-webhook URL",
	Short: "Send a test alert to a webhook URL",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		hook, err := server.NewWebhook(args[0], server.LevelInfo, nil)
		if err != nil {
			return err
		}
		now := time.Now().UTC().Truncate(time.Second)
		err = hook.Send(cmd.Context(), server.AlertEvent{Event: server.EventRaised, Alert: server.Alert{
			Hostname: testName, Group: testName, Kind: testName, Level: server.LevelInfo,
			Message: "Test alert of portmanagster-server", First: now, Last: now, Count: 1, State: server.StateNew,
		}})
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(os.Stdout, "test alert sent to %s\n", hook.Host())
		return nil
	},
}

// setupAlerts starts the webhook, the silent check and the pruning of old
// alerts for serve.
func setupAlerts(ctx context.Context, s *server.Server, logger *slog.Logger) error {
	if alertWebhook != "" {
		hook, err := server.NewWebhook(alertWebhook, alertWebhookLevel, logger.With("part", "webhook"))
		if err != nil {
			return err
		}
		s.Notify = hook.Notify
		go hook.Run(ctx)
		logger.Info("sending alerts to the webhook", "host", hook.Host(), "level", alertWebhookLevel)
	}
	go checkAlerts(ctx, s, logger)
	return nil
}

// checkAlerts runs the silent check every silentCheckEvery and prunes old
// alerts every hour until ctx is done.
func checkAlerts(ctx context.Context, s *server.Server, logger *slog.Logger) {
	var lastPrune time.Time
	for {
		err := s.CheckSilent()
		if err != nil {
			logger.Error("check silent computers", "err", err)
		}
		if time.Since(lastPrune) >= time.Hour {
			lastPrune = time.Now()
			n, err := s.Store.PruneAlerts(time.Now().Add(-alertRetention))
			switch {
			case err != nil:
				logger.Error("prune alerts", "err", err)
			case n > 0:
				logger.Info("pruned alerts", "rows", n)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(silentCheckEvery):
		}
	}
}

func init() {
	serveCmd.Flags().StringVar(&alertWebhook, "alert-webhook", "", "URL that gets every raised and resolved alert as JSON (POST)")
	serveCmd.Flags().StringVar(&alertWebhookLevel, "alert-webhook-level", server.LevelInfo, "lowest level sent to the webhook: info, warning or critical")
	serveCmd.Flags().DurationVar(&alertRetention, "alert-retention", server.DefaultAlertRetention, "how long resolved and acknowledged alerts are kept")
	alertsCmd.Flags().StringVar(&alertFilter.State, "state", server.StateOpen, "state: "+strings.Join(server.AlertStates, ", "))
	alertsCmd.Flags().StringVar(&alertFilter.Group, "group", "", "only computers of this group")
	alertsCmd.Flags().StringVar(&alertFilter.Computer, "computer", "", "only this computer (ID)")
	alertsCmd.Flags().StringVar(&alertFilter.Kind, "kind", "", "only this kind: "+strings.Join(server.AlertKinds, ", "))
	alertsCmd.Flags().StringVar(&alertFilter.MinLevel, "level", "", "only this level and above: info, warning, critical")
	alertsCmd.Flags().IntVar(&alertFilter.Limit, "limit", 50, "maximum number of rows")
	groupCmd.AddCommand(groupSilentAfterCmd)
	alertCmd.AddCommand(alertAckCmd, alertTestWebhookCmd)
	rootCmd.AddCommand(alertsCmd, alertCmd)
}
