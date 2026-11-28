package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/safing/portmaster/mgmt/server"
)

var (
	blockRetention time.Duration
	blockFilter    server.BlockFilter
	blockSince     time.Duration

	errOnOff = errors.New(`the second argument must be "on" or "off"`)
)

var groupBlockSummaryCmd = &cobra.Command{
	Use:   "block-summary NAME on|off",
	Short: "Turn the summary of blocked connections in the reports of a group on or off",
	Long: `Turn the summary of blocked connections in the reports of a group on or off.

When it is on, every report of the computers of the group counts the blocked
connections per app, reason, filter list and domain (or IP), and lists the apps
with allowed connections (name and a hash of the path, for the new app alert).
No single connections, no paths and no user names. The Portmaster app on the
computers shows that the summary is sent.`,
	Args: cobra.ExactArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		var on bool
		switch args[1] {
		case "on":
			on = true
		case "off":
		default:
			return errOnOff
		}
		return audited("group.blocksummary", args[0], args[1], func(s *server.Store) error {
			return s.SetGroupBlockSummary(args[0], on, time.Now())
		})
	},
}

var blocksCmd = &cobra.Command{
	Use:   "blocks",
	Short: "Show the summed blocked connections of the computers that send a block summary",
	Args:  cobra.NoArgs,
	RunE: func(_ *cobra.Command, _ []string) error {
		f := blockFilter
		f.Since = time.Now().Add(-blockSince)
		return withStore(func(s *server.Store) error {
			rows, err := s.Blocks(f)
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
			_, _ = fmt.Fprintln(w, "COUNT\tCOMPUTERS\tAPP\tTARGET\tDIRECTION\tREASON\tLISTS\tLAST (UTC)")
			for _, r := range rows {
				_, _ = fmt.Fprintf(w, "%d\t%d\t%s\t%s\t%s\t%s\t%s\t%s\n", r.Count, r.Computers, r.App, r.Target,
					direction(r.Inbound), r.Reason, r.Lists, r.Last.Format(time.DateTime))
			}
			return w.Flush()
		})
	},
}

func direction(inbound bool) string {
	if inbound {
		return "in"
	}
	return "out"
}

// pruneBlocks deletes the block summaries older than the retention every hour
// until ctx is done.
func pruneBlocks(ctx context.Context, s *server.Store, retention time.Duration, logger *slog.Logger) {
	for {
		n, err := s.PruneBlocks(time.Now().Add(-retention))
		switch {
		case err != nil:
			logger.Error("prune block summaries", "err", err)
		case n > 0:
			logger.Info("pruned block summaries", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Hour):
		}
	}
}

func init() {
	serveCmd.Flags().DurationVar(&blockRetention, "block-retention", server.DefaultBlockRetention, "how long block summaries are kept")
	blocksCmd.Flags().StringVar(&blockFilter.Group, "group", "", "only computers of this group")
	blocksCmd.Flags().StringVar(&blockFilter.Computer, "computer", "", "only this computer (ID)")
	blocksCmd.Flags().StringVar(&blockFilter.App, "app", "", "only this app")
	blocksCmd.Flags().StringVar(&blockFilter.List, "list", "", "only blocks by this filter list, e.g. MAL")
	blocksCmd.Flags().StringVar(&blockFilter.Target, "target", "", "only domains or IPs containing this")
	blocksCmd.Flags().DurationVar(&blockSince, "since", 24*time.Hour, "only blocks of this last duration")
	blocksCmd.Flags().IntVar(&blockFilter.Limit, "limit", 50, "maximum number of rows")
	groupCmd.AddCommand(groupBlockSummaryCmd)
	rootCmd.AddCommand(blocksCmd)
}
