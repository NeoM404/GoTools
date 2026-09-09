package app

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/NeoM404/GoTools/internal/tools"
)

func cmdDoctor(stdout, stderr io.Writer) int {
	results := tools.Check()
	tw := tabwriter.NewWriter(stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "TOOL\tREQUIRED\tSTATUS\tPURPOSE")
	for _, r := range results {
		status := "missing"
		if r.Found {
			status = "ok"
		}
		req := ""
		if r.Required {
			req = "required"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, req, status, r.Purpose)
	}
	tw.Flush()

	missing := tools.MissingRequired(results)
	if len(missing) == 0 {
		fmt.Fprintln(stdout, "\nall required tools present")
		return 0
	}
	fmt.Fprintln(stderr, "\nmissing REQUIRED tools:")
	for _, m := range missing {
		fmt.Fprintf(stderr, "  %s — install: %s\n", m.Name, m.Install)
	}
	return 1
}
