package inventory

import (
	"fmt"
	"regexp"
	"strings"
)

var awsAccountRe = regexp.MustCompile(`^\d{12}$`)

// ValidationError lists every problem found in a fleet document, so an
// inventory with several mistakes is fixed in one pass rather than one
// failed run at a time.
type ValidationError struct {
	Problems []string
}

func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "inventory is invalid (%d problem", len(e.Problems))
	if len(e.Problems) != 1 {
		b.WriteString("s")
	}
	b.WriteString("):")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p)
	}
	return b.String()
}

// Validate checks the fleet is safe to act on and returns a *ValidationError
// listing every problem, or nil.
//
// Rules, and why they are hard errors rather than warnings:
//   - names are unique, case-insensitively: every command addresses a cluster
//     by name, so a duplicate could hand an operator credentials for the
//     wrong cluster — for example a prod cluster sharing a dev cluster's name.
//   - the cloud is known, and each cluster carries its full identity (AWS:
//     account + region; Azure: subscription + resource group). Without it,
//     the cloud CLI acts in whichever account or subscription happens to be
//     active, and discovery cannot prove the cluster exists.
//   - a version, when present, parses; an environment, when an allow-list is
//     configured, is on it.
func (f Fleet) Validate(allowedEnvs []string) error {
	var problems []string
	add := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }

	allowed := make(map[string]bool, len(allowedEnvs))
	for _, e := range allowedEnvs {
		allowed[strings.ToLower(e)] = true
	}

	firstSeen := make(map[string]int, len(f.Clusters))
	for i, c := range f.Clusters {
		n := i + 1
		label := fmt.Sprintf("cluster #%d %q", n, c.Name)
		if strings.TrimSpace(c.Name) == "" {
			add("cluster #%d: name is empty", n)
			label = fmt.Sprintf("cluster #%d", n)
		} else {
			key := strings.ToLower(c.Name)
			if prev, dup := firstSeen[key]; dup {
				add("%s: duplicate of cluster #%d — names must be unique because commands address clusters by name", label, prev)
			} else {
				firstSeen[key] = n
			}
		}

		switch c.Cloud {
		case AWS:
			if c.Region == "" {
				add("%s: aws cluster has no region", label)
			}
			switch {
			case c.Account == "":
				add("%s: aws cluster has no account (12-digit account ID)", label)
			case !awsAccountRe.MatchString(c.Account):
				add("%s: account %q is not a 12-digit AWS account ID", label, c.Account)
			}
		case Azure:
			if c.Subscription == "" {
				add("%s: azure cluster has no subscription", label)
			}
			if c.ResourceGroup == "" {
				add("%s: azure cluster has no resourceGroup", label)
			}
		case "":
			add("%s: cloud is empty (want aws or azure)", label)
		default:
			add("%s: unknown cloud %q (want aws or azure)", label, c.Cloud)
		}

		if c.Version != "" {
			if _, err := ParseMinor(c.Version); err != nil {
				add("%s: version %q is not a Kubernetes version like 1.30", label, c.Version)
			}
		}
		if len(allowed) > 0 && !allowed[strings.ToLower(c.Environment)] {
			add("%s: environment %q is not one of %s", label, c.Environment, strings.Join(allowedEnvs, ", "))
		}
	}
	if len(problems) > 0 {
		return &ValidationError{Problems: problems}
	}
	return nil
}
