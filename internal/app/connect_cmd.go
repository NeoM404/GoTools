package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
)

var (
	eksNameRe     = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)
	eksEndpointRe = regexp.MustCompile(`^[a-z0-9.-]+\.eks\.amazonaws\.com(\.cn)?$`)
)

// eksTarget is what connect needs from describe-cluster.
type eksTarget struct {
	Name, Region, Host, CAData string
	Version                    string
}

func describeEKS(ctx context.Context, cfg config.Config, profile, name string) (eksTarget, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-cluster", "--name", name, "--profile", profile, "--output", "json")
	if err != nil {
		return eksTarget{}, err
	}
	var d struct {
		Cluster struct {
			Name, Arn, Endpoint, Version string
			CertificateAuthority         struct{ Data string } `json:"certificateAuthority"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return eksTarget{}, fmt.Errorf("parsing eks describe-cluster: %w", err)
	}
	u, err := url.Parse(d.Cluster.Endpoint)
	if err != nil || u.Scheme != "https" || !eksEndpointRe.MatchString(u.Hostname()) {
		return eksTarget{}, fmt.Errorf("eks returned an unexpected endpoint %q", d.Cluster.Endpoint)
	}
	if _, err := base64.StdEncoding.DecodeString(d.Cluster.CertificateAuthority.Data); err != nil || d.Cluster.CertificateAuthority.Data == "" {
		return eksTarget{}, fmt.Errorf("eks returned no valid certificate authority for %s", name)
	}
	m := eksARN.FindStringSubmatch(d.Cluster.Arn)
	if m == nil {
		return eksTarget{}, fmt.Errorf("eks returned an unexpected ARN %q", d.Cluster.Arn)
	}
	return eksTarget{Name: name, Region: m[1], Host: u.Hostname(), CAData: d.Cluster.CertificateAuthority.Data, Version: d.Cluster.Version}, nil
}

// eksARN matches an EKS cluster ARN; group 1 is the region.
var eksARN = regexp.MustCompile(`^arn:aws[a-z-]*:eks:([a-z0-9-]+):\d{12}:cluster/.+$`)

// tunnelKubeconfig is a kubeconfig for the cluster through a local tunnel:
// TLS is still verified against the cluster's own CA and hostname
// (tls-server-name), and the token comes from `aws eks get-token` under the
// engineer's profile — nothing long-lived is stored.
func tunnelKubeconfig(c eksTarget, profile string, port int) ([]byte, error) {
	doc := map[string]any{
		"apiVersion": "v1", "kind": "Config", "current-context": c.Name,
		"clusters": []any{map[string]any{"name": c.Name, "cluster": map[string]any{
			"server":                     "https://127.0.0.1:" + strconv.Itoa(port),
			"tls-server-name":            c.Host,
			"certificate-authority-data": c.CAData,
		}}},
		"users": []any{map[string]any{"name": c.Name + "." + profile, "user": map[string]any{"exec": map[string]any{
			"apiVersion": "client.authentication.k8s.io/v1beta1", "command": "aws",
			"args":            []string{"eks", "get-token", "--cluster-name", c.Name, "--region", c.Region, "--profile", profile, "--output", "json"},
			"interactiveMode": "Never",
		}}}},
		"contexts": []any{map[string]any{"name": c.Name, "context": map[string]any{"cluster": c.Name, "user": c.Name + "." + profile}}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func cmdConnect(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("connect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	profileFlag := fs.String("profile", "", "profile to act with (default: $AWS_PROFILE, then the last `nedctl aws login`)")
	viaInstance := fs.String("via-instance", "", "instance to tunnel through (default: the account's devops instance)")
	port := fs.Int("port", 0, "local port for the tunnel (default: a free one)")
	tab := fs.Bool("tab", false, "hold the tunnel in a new Windows Terminal tab coloured by environment")
	crFlag := fs.String("change-record", "", "change record for this access, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) != 1 || !eksNameRe.MatchString(pos[0]) {
		fmt.Fprintln(stderr, "usage: nedctl connect <eks-cluster> [--profile P] [--via-instance ID|NAME] [--port N] [--tab] [--change-record CHG…|--break-glass REASON]")
		return ExitUsage
	}
	if *port < 0 || *port > 65535 {
		fmt.Fprintln(stderr, "--port must be 1-65535")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	pc, ok := loadProfileContext(cfg, *profileFlag, stderr)
	if !ok {
		return ExitFailure
	}
	cluster, err := describeEKS(ctx, cfg, pc.Name, pos[0])
	if err != nil {
		fmt.Fprintf(stderr, "looking up %s with %s: %v\n", pos[0], pc.Name, err)
		return ExitFailure
	}
	list, err := listInstances(ctx, cfg, pc.Name)
	if err != nil {
		fmt.Fprintf(stderr, "listing instances with %s: %v\n", pc.Name, err)
		return ExitFailure
	}
	terms := []string{cfg.AWS.DevopsName()}
	var running []ec2Instance
	for _, in := range list {
		if in.State == "running" {
			running = append(running, in)
		}
	}
	hop, code := chooseInstance(cfg, pc, running, *viaInstance, terms, stderr)
	if code != ExitOK {
		return code
	}
	if *port == 0 {
		if *port, err = freePort(); err != nil {
			fmt.Fprintf(stderr, "finding a free local port: %v\n", err)
			return ExitFailure
		}
	}
	kc, err := writeTunnelKubeconfig(cfg, cluster, pc.Name, *port)
	if err != nil {
		fmt.Fprintf(stderr, "writing the kubeconfig: %v\n", err)
		return ExitFailure
	}
	if *tab {
		return openTunnelTab(cfg, pc, cluster, hop, *port, kc, *crFlag, *glassFlag, stderr)
	}

	cr, glass := strings.TrimSpace(*crFlag), strings.TrimSpace(*glassFlag)
	base := audit.Event{Action: "eks-connect", Cloud: "aws", Cluster: cluster.Name, Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("tunnel 127.0.0.1:%d → %s:443 via %s (%s), profile %s", *port, cluster.Host, hop.ID, firstNonBlank(hop.Name, "unnamed"), pc.Name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to connect: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: cluster.Name, Environment: pc.Environment}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	banner(cfg, pc, cluster.Name, stderr)
	fmt.Fprintf(stderr, "kubeconfig: %s\nIn another terminal:  export KUBECONFIG=%s   (PowerShell: $env:KUBECONFIG = '%s')\nTunnel open until you press Ctrl-C.\n", kc, kc, kc)
	err = execx.Interactive(ctx, execx.Spec{Name: "aws", Args: []string{"ssm", "start-session", "--target", hop.ID,
		"--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
		"--parameters", fmt.Sprintf("host=%s,portNumber=443,localPortNumber=%d", cluster.Host, *port),
		"--profile", pc.Name}, Stdout: stderr, Timeout: cfg.AWS.Timeout()})
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "tunnel failed: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	return ExitOK
}

// writeTunnelKubeconfig writes the isolated kubeconfig (0600) under
// kubeconfigDir, or ~/.kube/nedctl, and returns its path.
func writeTunnelKubeconfig(cfg config.Config, c eksTarget, profile string, port int) (string, error) {
	dir := cfg.KubeconfigDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".kube", "nedctl")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	data, err := tunnelKubeconfig(c, profile, port)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, c.Name+".json")
	return path, writeFileAtomic(path, append(data, '\n'), 0o600)
}

// openTunnelTab runs `nedctl connect` in a new coloured Windows Terminal
// tab that holds the tunnel; this terminal keeps working with KUBECONFIG.
func openTunnelTab(cfg config.Config, pc profileContext, c eksTarget, hop ec2Instance, port int, kc, cr, glass string, stderr io.Writer) int {
	if os.Getenv("WT_SESSION") == "" {
		fmt.Fprintln(stderr, "--tab needs Windows Terminal (WT_SESSION is not set) — run without --tab to hold the tunnel here")
		return ExitUsage
	}
	wt, err := exec.LookPath("wt.exe")
	if err != nil {
		fmt.Fprintln(stderr, "--tab: wt.exe not found in PATH")
		return ExitFailure
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(stderr, "--tab: locating nedctl: %v\n", err)
		return ExitFailure
	}
	title := "tunnel · " + pc.label() + " · " + c.Name
	args := []string{"-w", "0", "nt", "--title", title}
	if col := cfg.ColorFor(pc.Environment); col != "" {
		args = append(args, "--tabColor", col)
	}
	if distro := os.Getenv("WSL_DISTRO_NAME"); distro != "" {
		args = append(args, "wsl.exe", "-d", distro, "--")
	}
	args = append(args, self, "connect", c.Name, "--profile", pc.Name, "--via-instance", hop.ID, "--port", strconv.Itoa(port))
	if cr != "" {
		args = append(args, "--change-record", cr)
	}
	if glass != "" {
		args = append(args, "--break-glass", glass)
	}
	cmd := exec.Command(wt, args...) //nolint:gosec // fixed binary, validated arguments
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(stderr, "--tab: %v\n", err)
		return ExitFailure
	}
	_ = cmd.Process.Release()
	fmt.Fprintf(stderr, "tunnel opening in a new tab: %s\nexport KUBECONFIG=%s\n", title, kc)
	return ExitOK
}
