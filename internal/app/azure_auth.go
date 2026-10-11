package app

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"

	"nedctl/internal/execx"
	"nedctl/internal/ui"
)

// `nedctl azure auth` shows, per AKS cluster on the bastions, how the
// bastion's kubeconfig authenticates: a shared local account (clusterUser
// or clusterAdmin — a certificate in system:masters, so the cluster's
// audit log cannot tell engineers apart) or Entra ID through kubelogin
// (per person). It tracks the move to per-person identity, the way `eks
// auth` tracks EKS access entries. It reads `kubectl config view`, which
// hides every key, certificate and token.

type aksAuthRow struct {
	Environment string `json:"environment"`
	Cluster     string `json:"cluster"`
	User        string `json:"user"`
	Auth        string `json:"auth"` // local-account | entra-id | exec | unknown
	Action      string `json:"action,omitempty"`
}

type kubeconfigView struct {
	Users []struct {
		Name string `json:"name"`
		User struct {
			ClientCert   string `json:"client-certificate-data"`
			ClientCertF  string `json:"client-certificate"`
			Token        string `json:"token"`
			Password     string `json:"password"`
			AuthProvider *struct {
				Name string `json:"name"`
			} `json:"auth-provider"`
			Exec *struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
			} `json:"exec"`
		} `json:"user"`
	} `json:"users"`
	Contexts []struct {
		Name    string `json:"name"`
		Context struct {
			User string `json:"user"`
		} `json:"context"`
	} `json:"contexts"`
}

const localAccountAction = "grant Entra ID groups RBAC, then disable local accounts (az aks update --disable-local-accounts)"

func aksAuthRows(env string, data []byte) ([]aksAuthRow, error) {
	var kc kubeconfigView
	if err := json.Unmarshal(data, &kc); err != nil {
		return nil, fmt.Errorf("reading the bastion's kubeconfig: %w", err)
	}
	auth := map[string]string{}
	for _, u := range kc.Users {
		switch {
		case u.User.Exec != nil && filepath.Base(u.User.Exec.Command) == "kubelogin":
			auth[u.Name] = "entra-id"
		case u.User.AuthProvider != nil && u.User.AuthProvider.Name == "azure":
			auth[u.Name] = "entra-id (legacy auth-provider)"
		case u.User.Exec != nil:
			auth[u.Name] = "exec: " + filepath.Base(u.User.Exec.Command)
		case u.User.ClientCert != "" || u.User.ClientCertF != "" || u.User.Token != "" || u.User.Password != "":
			auth[u.Name] = "local-account"
		default:
			auth[u.Name] = "unknown"
		}
	}
	var rows []aksAuthRow
	for _, c := range kc.Contexts {
		if !kubeContextRe.MatchString(c.Name) {
			continue
		}
		r := aksAuthRow{Environment: env, Cluster: c.Name, User: c.Context.User, Auth: firstNonBlank(auth[c.Context.User], "unknown")}
		if r.Auth == "local-account" {
			r.Action = localAccountAction
		}
		rows = append(rows, r)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Cluster < rows[j].Cluster })
	return rows, nil
}

func azureAuth(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure auth", flag.ContinueOnError)
	fs.SetOutput(stderr)
	envFlag := fs.String("env", "", "only these environments, e.g. qa or dev,qa (default: every bastion)")
	failOnLocal := fs.Bool("fail-on-local", false, "exit 1 while any cluster is reached with a shared local account")
	output := addOutputFlag(fs)
	if pos, err := parseInterspersed(fs, args); err != nil || len(pos) > 0 {
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	envs := azureEnvs(cfg)
	if *envFlag != "" {
		envs = nil
		for _, e := range strings.Split(strings.ToLower(*envFlag), ",") {
			if _, ok := cfg.Azure.Bastion(strings.TrimSpace(e)); !ok {
				fmt.Fprintf(stderr, "no bastion for %q — azure.bastions has %s\n", e, strings.Join(azureEnvs(cfg), ", "))
				return ExitUsage
			}
			envs = append(envs, strings.TrimSpace(e))
		}
	}
	rows := []aksAuthRow{}
	failed := false
	for _, env := range envs {
		t := bastionTarget(cfg, env)
		fmt.Fprintf(stderr, "Reading the kubeconfig on %s…\n", t.Name)
		var out bytes.Buffer
		err := execx.Interactive(ctx, execx.Spec{Stdin: strings.NewReader(""), Stdout: &out, Name: "ssh",
			Args: sshArgs(cfg, t, false, remoteBash("kubectl config view -o json")), Timeout: cfg.Timeout()})
		if err == nil {
			var r []aksAuthRow
			if r, err = aksAuthRows(env, out.Bytes()); err == nil {
				rows = append(rows, r...)
				continue
			}
		}
		failed = true
		fmt.Fprintf(stderr, "%s: %v\n", t.Name, sshError(t, err))
	}
	local := 0
	for _, r := range rows {
		if r.Auth == "local-account" {
			local++
		}
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, rows); code != ExitOK {
			return code
		}
	} else {
		st := ui.Style{Color: colorOn(stdout)}
		tw := newTable(stdout)
		fmt.Fprintln(tw, "ENV\tCLUSTER\tAUTH\tKUBECONFIG USER")
		for _, r := range rows {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Environment, r.Cluster, r.Auth, r.User)
		}
		tw.Flush()
		fmt.Fprintln(stdout)
		if local > 0 {
			fmt.Fprintln(stdout, st.Warn(fmt.Sprintf("%d of %d cluster(s) are reached with a shared local account: their audit logs cannot name the engineer", local, len(rows))))
			fmt.Fprintln(stdout, st.Hint("to move one to per-person access: "+localAccountAction+" — see docs/security-checks.md"))
		} else if len(rows) > 0 {
			fmt.Fprintln(stdout, st.OK("every cluster is reached with per-person Entra ID sign-in"))
		}
	}
	if failed || (*failOnLocal && local > 0) {
		return ExitFailure
	}
	return ExitOK
}
