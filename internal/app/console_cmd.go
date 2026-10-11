package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os/exec"
	"regexp"
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
	yes := fs.Bool("yes", false, "confirm production access without being asked (when confirmProduction is on)")
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
	link := consoleLink(portalURL(cfg.AWS), pc.AccountID, pc.Role, service, r)

	if !confirmProduction(cfg, pc, "the AWS console", *yes, stderr) {
		return ExitFailure
	}
	base := audit.Event{Action: "aws-console", Cloud: "aws", Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, Detail: fmt.Sprintf("console %s in %s, role %s", firstNonBlank(service, "home"), r, pc.Role)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to open the console: every access must be recorded\n", err)
		return ExitFailure
	}
	switch {
	case *printOnly:
		fmt.Fprintln(stdout, link)
	case !openBrowser(link):
		fmt.Fprintln(stderr, helpStyle(stderr).Warn("no browser could be opened from here — open this link:"))
		fmt.Fprintln(stdout, link)
	default:
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

var issuerStartRe = regexp.MustCompile(`^https://identitycenter\.amazonaws\.com/(ssoins-[0-9a-f]+)/?$`)

// portalURL is the AWS access portal shortcut links are made on. A
// d-xxxxxxxxxx.awsapps.com/start URL is the portal itself; an instance
// that signs in with https://identitycenter.amazonaws.com/ssoins-… has its
// portal at https://ssoins-….portal.<region>.app.aws. aws.portalUrl
// overrides both.
func portalURL(a config.AWS) string {
	if a.PortalURL != "" {
		return a.PortalURL
	}
	if m := issuerStartRe.FindStringSubmatch(a.StartURL); m != nil {
		return "https://" + m[1] + ".portal." + a.SSORegion + ".app.aws"
	}
	return a.StartURL
}

func consoleLink(portalURL, account, role, service, region string) string {
	portal := strings.TrimRight(strings.SplitN(portalURL, "#", 2)[0], "/")
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

// windowsRoot is where WSL mounts the Windows drive; a var for tests.
var windowsRoot = "/mnt/c"

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
	case goos == "darwin":
		tries = [][]string{{"open", link}}
	case goos == "windows":
		tries = [][]string{{"rundll32", "url.dll,FileProtocolHandler", link}}
	case inWSL():
		// WSL often runs without the Windows PATH, so the Windows openers
		// are also tried at their fixed locations.
		tries = [][]string{{"wslview", link}, {"rundll32.exe", "url.dll,FileProtocolHandler", link},
			{windowsRoot + "/Windows/System32/rundll32.exe", "url.dll,FileProtocolHandler", link},
			{"explorer.exe", link}, {windowsRoot + "/Windows/explorer.exe", link}}
	case lookupEnv("SSH_CONNECTION") != "" || (lookupEnv("DISPLAY") == "" && lookupEnv("WAYLAND_DISPLAY") == ""):
		return false
	default:
		tries = [][]string{{"xdg-open", link}}
	}
	for _, t := range tries {
		if _, err := exec.LookPath(t[0]); err != nil {
			continue // LookPath also checks a full path is an executable file
		}
		if openURL(t[0], t[1:]...) == nil {
			return true
		}
	}
	return false
}

// cmdOpenURL is `nedctl __open-url <https-url>`: the BROWSER the AWS CLI is
// given during sign-in in WSL. It opens only https links.
func cmdOpenURL(args []string, stderr io.Writer) int {
	if len(args) != 1 || !strings.HasPrefix(args[0], "https://") || strings.ContainsAny(args[0], " \t\r\n") {
		fmt.Fprintln(stderr, "usage: nedctl __open-url <https-url>")
		return ExitUsage
	}
	if !openBrowser(args[0]) {
		return ExitFailure // the AWS CLI then prints the link itself
	}
	return ExitOK
}
