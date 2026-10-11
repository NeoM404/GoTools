package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
)

// cmdConsole opens the AWS management console as the account and role the
// engineer acts with, through an IAM Identity Center shortcut link
// (<portal>/#/console?account_id=…&role_name=…&destination=…): the browser
// signs in with Identity Center, so no credentials pass through nedctl.
func cmdConsole(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("console", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile whose account and role to open (default: $AWS_PROFILE, then the last nedctl aws login)")
	region := fs.String("region", "", "console region (default: where nedctl last found clusters or instances)")
	printOnly := fs.Bool("print", false, "print the link instead of opening a browser")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 1 {
		fmt.Fprintln(stderr, "usage: nedctl console [SERVICE] [--profile P] [--region R] [--print]")
		return ExitUsage
	}
	service := ""
	if len(pos) == 1 {
		service = strings.ToLower(pos[0])
		if !serviceRe.MatchString(service) {
			fmt.Fprintf(stderr, "%q is not a service name such as eks, ec2 or cloudwatch\n", pos[0])
			return ExitUsage
		}
	}
	if *region != "" && !awsRegionRe.MatchString(*region) {
		fmt.Fprintf(stderr, "--region %q is not an AWS region such as eu-west-1\n", *region)
		return ExitUsage
	}
	cfg, ok := loadAWSConfig(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	pc, ok := loadProfileContext(ctx, cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	if pc.AccountID == "" || pc.Role == "" {
		fmt.Fprintf(stderr, "%s is not a profile nedctl wrote, so its account and role are unknown — sign in with `nedctl aws login`\n", pc.Name)
		return ExitFailure
	}
	r := firstNonBlank(*region, consoleRegion(cfg, pc, service))
	link := consoleLink(cfg.AWS.StartURL, pc.AccountID, pc.Role, service, r)

	base := audit.Event{Action: "aws-console", Cloud: "aws", Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, Detail: fmt.Sprintf("console %s in %s, role %s", firstNonBlank(service, "home"), r, pc.Role)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to open the console: every access must be recorded\n", err)
		return ExitFailure
	}
	if *printOnly || !openBrowser(link) {
		fmt.Fprintln(stdout, link)
	} else {
		s := helpStyle(stderr)
		fmt.Fprintf(stderr, "%s %s\n", s.OK("Opening the AWS console:"), s.Fg(cfg.ColorFor(pc.Environment), pc.label()+" · "+pc.Role+" · "+firstNonBlank(service, "home")+" · "+r))
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	return ExitOK
}

var serviceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,40}$`)

// consoleRegion is where the engineer most likely wants to look: where
// nedctl last found that kind of resource in the account, else the profile
// region.
func consoleRegion(cfg config.Config, pc profileContext, service string) string {
	kind := "ec2"
	if service == "eks" {
		kind = "eks"
	}
	c := loadRegionCache(cfg, pc)
	for _, k := range []string{kind, "eks", "ec2"} {
		if rs := c.Active[k]; len(rs) > 0 {
			return rs[0]
		}
	}
	return cfg.AWS.ProfileRegion()
}

// consoleDestinations are console pages worth landing on directly.
var consoleDestinations = map[string]string{
	"eks":        "https://console.aws.amazon.com/eks/home?region=%s#/clusters",
	"ec2":        "https://console.aws.amazon.com/ec2/home?region=%s#Instances:",
	"ssm":        "https://console.aws.amazon.com/systems-manager/session-manager?region=%s",
	"cloudwatch": "https://console.aws.amazon.com/cloudwatch/home?region=%s",
	"logs":       "https://console.aws.amazon.com/cloudwatch/home?region=%s#logsV2:log-groups",
	"cloudtrail": "https://console.aws.amazon.com/cloudtrail/home?region=%s#/events",
	"s3":         "https://s3.console.aws.amazon.com/s3/home?region=%s",
	"iam":        "https://console.aws.amazon.com/iam/home?region=%s",
	"vpc":        "https://console.aws.amazon.com/vpc/home?region=%s",
}

func consoleLink(startURL, account, role, service, region string) string {
	portal := strings.TrimRight(strings.SplitN(startURL, "#", 2)[0], "/")
	q := url.Values{}
	q.Set("account_id", account)
	q.Set("role_name", role)
	if service != "" {
		dest, ok := consoleDestinations[service]
		if !ok {
			dest = "https://console.aws.amazon.com/" + service + "/home?region=%s"
		}
		q.Set("destination", fmt.Sprintf(dest, region))
	} else {
		q.Set("destination", fmt.Sprintf("https://console.aws.amazon.com/console/home?region=%s", region))
	}
	return portal + "/#/console?" + q.Encode()
}

// openURL starts the platform's browser opener; a var so tests can see the
// link instead of opening a browser.
var openURL = func(name string, args ...string) error {
	cmd := exec.Command(name, args...) //nolint:gosec // fixed opener, the link is built from validated parts
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// openBrowser opens link in the desktop's browser: the Windows one from
// WSL. It reports false where there is none (SSH, a headless box), so the
// caller prints the link instead.
func openBrowser(link string) bool {
	var tries [][]string
	switch {
	case runtime.GOOS == "darwin":
		tries = [][]string{{"open", link}}
	case runtime.GOOS == "windows":
		tries = [][]string{{"rundll32", "url.dll,FileProtocolHandler", link}}
	case inWSL():
		tries = [][]string{{"wslview", link}, {"explorer.exe", link}}
	case lookupEnv("SSH_CONNECTION") != "" || (lookupEnv("DISPLAY") == "" && lookupEnv("WAYLAND_DISPLAY") == ""):
		return false
	default:
		tries = [][]string{{"xdg-open", link}}
	}
	for _, t := range tries {
		if _, err := exec.LookPath(t[0]); err != nil {
			continue
		}
		if openURL(t[0], t[1:]...) == nil {
			return true
		}
	}
	return false
}
