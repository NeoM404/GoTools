package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/httpx"
	"nedctl/internal/inventory"
)

var (
	eksNameRe = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)
	// EKS hands out endpoints with an upper-case hex prefix
	// (51AD….yl4.af-south-1.eks.amazonaws.com); DNS names are
	// case-insensitive, so the check is too, and the host is lower-cased.
	eksEndpointRe = regexp.MustCompile(`(?i)^[a-z0-9.-]+\.eks\.amazonaws\.com(\.cn)?$`)
)

// eksTarget is what connect needs from describe-cluster.
type eksTarget struct {
	Name, Region, Host, CAData string
	Version                    string
	// PublicAccess and PrivateAccess are the endpoint's exposure, used to
	// explain why a direct connection is or is not possible.
	PublicAccess, PrivateAccess bool
}

func describeEKS(ctx context.Context, cfg config.Config, profile, name, region string) (eksTarget, error) {
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", "eks", "describe-cluster", "--name", name, "--profile", profile, "--region", region, "--output", "json")
	if err != nil {
		return eksTarget{}, err
	}
	var d struct {
		Cluster struct {
			Name, Arn, Endpoint, Version string
			CertificateAuthority         struct{ Data string } `json:"certificateAuthority"`
			ResourcesVpcConfig           struct {
				EndpointPublicAccess  bool `json:"endpointPublicAccess"`
				EndpointPrivateAccess bool `json:"endpointPrivateAccess"`
			} `json:"resourcesVpcConfig"`
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
	return eksTarget{Name: name, Region: m[1], Host: strings.ToLower(u.Hostname()), CAData: d.Cluster.CertificateAuthority.Data, Version: d.Cluster.Version,
		PublicAccess: d.Cluster.ResourcesVpcConfig.EndpointPublicAccess, PrivateAccess: d.Cluster.ResourcesVpcConfig.EndpointPrivateAccess}, nil
}

// eksARN matches an EKS cluster ARN; group 1 is the region.
var eksARN = regexp.MustCompile(`^arn:aws[a-z-]*:eks:([a-z0-9-]+):\d{12}:cluster/.+$`)

// tunnelKubeconfig is a kubeconfig for the cluster through a local tunnel:
// TLS is still verified against the cluster's own CA and hostname
// (tls-server-name), and the token comes from `aws eks get-token` under the
// engineer's profile — nothing long-lived is stored.
func tunnelKubeconfig(c eksTarget, profile string, port int) ([]byte, error) {
	return clusterKubeconfig(c, profile, "https://127.0.0.1:"+strconv.Itoa(port), c.Host)
}

// clusterKubeconfig points kubectl at server, verifying TLS against the
// cluster's CA (under tlsName when set, for a tunnel), with tokens from
// `aws eks get-token` as the engineer's profile.
func clusterKubeconfig(c eksTarget, profile, server, tlsName string) ([]byte, error) {
	cl := map[string]any{"server": server, "certificate-authority-data": c.CAData}
	if tlsName != "" {
		cl["tls-server-name"] = tlsName
	}
	doc := map[string]any{
		"apiVersion": "v1", "kind": "Config", "current-context": c.Name,
		"clusters": []any{map[string]any{"name": c.Name, "cluster": cl}},
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
	via := fs.String("via", viaAuto, "auto (direct if the endpoint answers from here, else the devops instance), direct, or bastion")
	crFlag := fs.String("change-record", "", "change record for this access, when change control requires one")
	glassFlag := fs.String("break-glass", "", "emergency access without a change record; recorded and flagged")
	var rs regionSearch
	addRegionFlags(fs, &rs)
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
	if !validVia(*via) {
		fmt.Fprintf(stderr, "--via %q: want auto, direct or bastion\n", *via)
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
	plan, code := planTunnel(ctx, cfg, pc, rs, pos[0], *via, *viaInstance, *port, stderr)
	if code != ExitOK {
		return code
	}
	if plan.direct {
		return connectDirect(ctx, cfg, pc, plan, *crFlag, *glassFlag, stderr)
	}
	cluster, hop, kc := plan.cluster, plan.hop, plan.kubeconfig
	*port = plan.port
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
	err = execx.Interactive(ctx, execx.Spec{Name: "aws", Args: portForwardArgs(plan, pc.Name), Stdout: stderr, Timeout: cfg.AWS.Timeout()})
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "tunnel failed: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	return ExitOK
}

// connectDirect records and change-controls a direct connection, then tells
// the engineer how to use it: there is no tunnel to hold open.
func connectDirect(ctx context.Context, cfg config.Config, pc profileContext, plan tunnelPlan, crFlag, glassFlag string, stderr io.Writer) int {
	cr, glass := strings.TrimSpace(crFlag), strings.TrimSpace(glassFlag)
	base := audit.Event{Action: "eks-connect", Cloud: "aws", Cluster: plan.cluster.Name, Account: pc.AccountID, Environment: pc.Environment,
		Production: pc.Production, ChangeRecord: cr, BreakGlass: glass != "", BreakGlassReason: glass,
		Detail: fmt.Sprintf("direct to %s:443, profile %s", plan.cluster.Host, pc.Name)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing to connect: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: plan.cluster.Name, Environment: pc.Environment}, cr, glass, tr, stderr); code != ExitOK {
		return code
	}
	tr.end(ctx, audit.OutcomeSuccess, pc.Role, base.Detail, stderr)
	banner(cfg, pc, plan.cluster.Name, stderr)
	kc := plan.kubeconfig
	fmt.Fprintf(stderr, "Direct: the endpoint answers from here, no tunnel needed.\nexport KUBECONFIG=%s   (PowerShell: $env:KUBECONFIG = '%s')\n", kc, kc)
	return ExitOK
}

// tunnelPlan is everything a connection to one cluster needs, worked out
// before anything is started or recorded. direct means kubectl reaches the
// endpoint itself and there is no hop or port.
type tunnelPlan struct {
	cluster    eksTarget
	direct     bool
	hop        ec2Instance
	port       int
	kubeconfig string
}

// How a cluster is reached.
const (
	viaAuto    = "auto"    // directly if the endpoint answers from here, else through the devops instance
	viaDirect  = "direct"  // kubectl talks to the endpoint from this machine (VPN, or a public endpoint)
	viaBastion = "bastion" // a Session Manager tunnel through the devops instance
)

func validVia(v string) bool { return v == viaAuto || v == viaDirect || v == viaBastion }

// directServer is the API server address for a direct connection, and the
// TLS name to verify (empty: the server's own host). A seam for tests.
var directServer = func(c eksTarget) (server, tlsName string) { return "https://" + c.Host, "" }

// directReachable reports whether the cluster's API answers from this
// machine: any HTTP response over TLS verified against the cluster's CA
// counts (an unauthenticated /version may well be refused). It honours the
// proxy like every nedctl client.
func directReachable(ctx context.Context, c eksTarget) error {
	pem, err := base64.StdEncoding.DecodeString(c.CAData)
	if err != nil {
		return err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("the cluster CA could not be read")
	}
	server, tlsName := directServer(c)
	tr := httpx.Transport()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, ServerName: tlsName}
	client := &http.Client{Transport: tr, Timeout: 6 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server+"/version", nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// planTunnel finds the cluster's region, describes it, picks the devops
// instance in that region to tunnel through, chooses a local port and writes
// the kubeconfig. It is shared by connect and kube so both behave the same.
func planTunnel(ctx context.Context, cfg config.Config, pc profileContext, rs regionSearch, name, mode, via string, port int, stderr io.Writer) (tunnelPlan, int) {
	if via != "" {
		mode = viaBastion // naming the hop means going through it
	}
	region, err := findCluster(ctx, cfg, pc, rs, name, stderr)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return tunnelPlan{}, ExitFailure
	}
	cluster, err := describeEKS(ctx, cfg, pc.Name, name, region)
	if err != nil {
		fmt.Fprintf(stderr, "looking up %s with %s: %v\n", name, pc.Name, err)
		return tunnelPlan{}, ExitFailure
	}
	var directErr error
	if mode == viaAuto || mode == viaDirect {
		if directErr = directReachable(ctx, cluster); directErr == nil {
			server, tlsName := directServer(cluster)
			data, err := clusterKubeconfig(cluster, pc.Name, server, tlsName)
			if err == nil {
				var kc string
				if kc, err = writeKubeconfigFile(cfg, cluster.Name, data); err == nil {
					return tunnelPlan{cluster: cluster, direct: true, kubeconfig: kc}, ExitOK
				}
			}
			fmt.Fprintf(stderr, "writing the kubeconfig: %v\n", err)
			return tunnelPlan{}, ExitFailure
		}
		if mode == viaDirect {
			fmt.Fprintf(stderr, "%s is not reachable directly from here: %v\n%s", name, directErr, exposureHint(cluster))
			return tunnelPlan{}, ExitFailure
		}
	}
	// The hop must be in the cluster's region (and VPC) to reach its endpoint.
	list, err := instancesIn(ctx, cfg, pc.Name, cluster.Region)
	if err != nil {
		fmt.Fprintf(stderr, "listing instances with %s: %v\n", pc.Name, err)
		return tunnelPlan{}, ExitFailure
	}
	var running []ec2Instance
	for _, in := range list {
		if in.State == "running" && (via != "" || strings.Contains(strings.ToLower(in.Name), strings.ToLower(cfg.AWS.DevopsName()))) {
			running = append(running, in)
		}
	}
	if len(running) == 0 && via == "" {
		fmt.Fprintf(stderr, "no running instance named like %q in %s to tunnel through", cfg.AWS.DevopsName(), cluster.Region)
		if directErr != nil {
			fmt.Fprintf(stderr, ", and the endpoint is not reachable directly (%v)\n%s", directErr, exposureHint(cluster))
		} else {
			fmt.Fprintln(stderr)
		}
		fmt.Fprintln(stderr, "→ connect the VPN and use --via direct, or name another instance with --via-instance")
		return tunnelPlan{}, ExitFailure
	}
	hop, code := chooseInstance(cfg, pc, running, via, nil, stderr)
	if code != ExitOK {
		return tunnelPlan{}, code
	}
	if port == 0 {
		if port, err = freePort(); err != nil {
			fmt.Fprintf(stderr, "finding a free local port: %v\n", err)
			return tunnelPlan{}, ExitFailure
		}
	}
	kc, err := writeTunnelKubeconfig(cfg, cluster, pc.Name, port)
	if err != nil {
		fmt.Fprintf(stderr, "writing the kubeconfig: %v\n", err)
		return tunnelPlan{}, ExitFailure
	}
	return tunnelPlan{cluster: cluster, hop: hop, port: port, kubeconfig: kc}, ExitOK
}

// exposureHint says what the endpoint's exposure means for reaching it.
func exposureHint(c eksTarget) string {
	switch {
	case c.PrivateAccess && !c.PublicAccess:
		return "  the endpoint is private only: reachable from the VPC, or over the VPN if it routes there\n"
	case c.PublicAccess:
		return "  the endpoint is public but may be limited to certain source addresses (publicAccessCidrs)\n"
	}
	return ""
}

// portForwardArgs are the aws arguments of the Session Manager
// port-forward behind a tunnel.
func portForwardArgs(p tunnelPlan, profile string) []string {
	return []string{"ssm", "start-session", "--target", p.hop.ID,
		"--document-name", "AWS-StartPortForwardingSessionToRemoteHost",
		"--parameters", fmt.Sprintf("host=%s,portNumber=443,localPortNumber=%d", p.cluster.Host, p.port),
		"--region", p.cluster.Region, "--profile", profile}
}

// writeTunnelKubeconfig writes the kubeconfig for a tunnel on port.
func writeTunnelKubeconfig(cfg config.Config, c eksTarget, profile string, port int) (string, error) {
	data, err := tunnelKubeconfig(c, profile, port)
	if err != nil {
		return "", err
	}
	return writeKubeconfigFile(cfg, c.Name, data)
}

// writeKubeconfigFile writes an isolated kubeconfig (0600) under
// kubeconfigDir, or ~/.kube/nedctl, and returns its path.
func writeKubeconfigFile(cfg config.Config, cluster string, data []byte) (string, error) {
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
	path := filepath.Join(dir, cluster+".json")
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
	args = append(args, self, "connect", c.Name, "--profile", pc.Name, "--region", c.Region, "--via-instance", hop.ID, "--port", strconv.Itoa(port))
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
