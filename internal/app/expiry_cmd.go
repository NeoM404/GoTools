package app

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/inventory"
	"nedctl/internal/support"
	"nedctl/internal/ui"
)

// `nedctl expiry` is everything on a cluster that stops working on a date:
// TLS certificates in Secrets (and whether cert-manager is renewing them),
// cert-manager Certificates failing to renew, Ingresses and Istio Gateways
// pointing at certificates that are not there, the CA bundles admission
// webhooks and aggregated APIs are called with, the cluster's own CA, and
// the Kubernetes version's support window. Sorted by days left, across
// environments. Read-only; private keys are never printed.

func expiryProbes(ns string) []probe {
	return []probe{
		versionProbe,
		// Only the certificate is printed; the key never leaves kubectl.
		listProbe("secrets", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.metadata.annotations.cert-manager\.io/certificate-name}{"\t"}{.data.tls\.crt}{"\n"}{end}`, "--field-selector", "type=kubernetes.io/tls"),
		listProbe("certificates.cert-manager.io", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.secretName}{"\t"}{.status.notAfter}{"\t"}{.status.renewalTime}{"\t"}{range .status.conditions[?(@.type=="Ready")]}{.status}{"\t"}{.message}{end}{"\n"}{end}`),
		listProbe("ingresses", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.tls[*].secretName}{"\n"}{end}`),
		listProbe("gateways.networking.istio.io", ns, `{range .items[*]}{.metadata.namespace}{"\t"}{.metadata.name}{"\t"}{.spec.servers[*].tls.credentialName}{"\n"}{end}`),
		clusterProbe("validatingwebhookconfigurations,mutatingwebhookconfigurations", `{range .items[*]}H{"\t"}{.kind}{"\t"}{.metadata.name}{"\n"}{range .webhooks[*]}B{"\t"}{.name}{"\t"}{.clientConfig.caBundle}{"\n"}{end}{end}`),
		clusterProbe("apiservices", `{range .items[*]}{.metadata.name}{"\t"}{.spec.caBundle}{"\t"}{range .status.conditions[?(@.type=="Available")]}{.status}{end}{"\n"}{end}`),
		{"get", "configmap", "kube-root-ca.crt", "-n", "kube-system", "-o", `jsonpath={.data.ca\.crt}`},
	}
}

const (
	exSecrets = iota + 1
	exCertificates
	exIngresses
	exGateways
	exWebhooks
	exAPIServices
	exRootCA
)

// certSummary is what nedctl reads from a certificate: never more.
type certSummary struct {
	NotAfter time.Time
	Subject  string // CN, else the first DNS name
	Issuer   string
	Count    int // certificates in the bundle
}

// readCerts reads every certificate of PEM data; the summary is the one
// expiring first.
func readCerts(pemData []byte) (certSummary, bool) {
	var first certSummary
	ok := false
	for {
		var block *pem.Block
		block, pemData = pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		first.Count++
		if !ok || c.NotAfter.Before(first.NotAfter) {
			subject := c.Subject.CommonName
			if subject == "" && len(c.DNSNames) > 0 {
				subject = c.DNSNames[0]
			}
			first.NotAfter, first.Subject, first.Issuer = c.NotAfter, subject, c.Issuer.CommonName
			ok = true
		}
	}
	return first, ok
}

func readCertsB64(b64 string) (certSummary, bool) {
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return certSummary{}, false
	}
	return readCerts(data)
}

// expirySeverity grades days left: expired critical, a week high, within
// warn days medium, within 90 low; later is not a finding.
func expirySeverity(days, warn int) string {
	switch {
	case days < 0:
		return "critical"
	case days <= 7:
		return "high"
	case days <= warn:
		return "medium"
	case days <= 90:
		return "low"
	}
	return ""
}

// lower is one severity less (cert-manager will renew it), never below low.
func lower(sev string) string {
	if r := severityRank(sev); r > 1 && sev != "critical" {
		return severities[r-1]
	}
	return sev
}

func daysLeft(t, today time.Time) int {
	return int(t.Sub(today).Hours() / 24)
}

func whenText(days int, t time.Time) string {
	d := t.Format("2006-01-02")
	switch {
	case days < 0:
		return fmt.Sprintf("expired %d day(s) ago (%s)", -days, d)
	case days == 0:
		return "expires today (" + d + ")"
	}
	return fmt.Sprintf("expires in %d day(s) (%s)", days, d)
}

func assessExpiry(cfg config.Config, r clusterOut, today time.Time, warn int, all bool) clusterFindings {
	cf := newClusterFindings(r)
	if err := r.reachErr(); err != nil {
		cf.Status, cf.Error = "unreachable", err.Error()
		return cf
	}
	lines := func(i int, what string, optional bool) ([]string, bool) {
		if i >= len(r.Outs) {
			return nil, false
		}
		if err := r.Outs[i].Err; err != nil {
			if !(optional && notInstalled(err)) {
				cf.unassessed("%s: %v", what, err)
			}
			return nil, false
		}
		return nonEmptyLines(string(r.Outs[i].Out)), true
	}
	checked := 0
	cert := func(check, object string, c certSummary, sev, fix, extra string) {
		checked++
		days := daysLeft(c.NotAfter, today)
		if sev == "" {
			if !all {
				return
			}
			sev = "info"
		}
		detail := whenText(days, c.NotAfter)
		if c.Subject != "" {
			detail += "; " + c.Subject
		}
		if c.Issuer != "" && c.Issuer != c.Subject {
			detail += ", issued by " + c.Issuer
		}
		if extra != "" {
			detail += "; " + extra
		}
		title := "certificate expiring"
		if days < 0 {
			title = "certificate has expired"
		}
		cf.add(checkFinding{Check: check, Area: "certificates", Severity: sev, Title: title,
			Object: object, Detail: detail, Fix: fix, Source: "kubernetes"})
	}

	// cert-manager Certificates, by the Secret they write.
	type cmCert struct {
		name, ready, message, renewal string
	}
	managed := map[string]cmCert{}
	if ls, ok := lines(exCertificates, "cert-manager certificates", true); ok {
		for _, l := range ls {
			f := strings.Split(l, "\t")
			if len(f) < 7 {
				continue
			}
			c := cmCert{name: f[1], renewal: f[4], ready: f[5], message: strings.TrimSpace(f[6])}
			managed[f[0]+"/"+f[2]] = c
			if c.ready == "False" {
				cf.add(checkFinding{Check: "cert-manager-renewal", Area: "certificates", Severity: "high", Title: "cert-manager cannot issue or renew it",
					Object: "certificate/" + f[0] + "/" + f[1], Detail: firstNonBlank(c.message, "Ready is False"),
					Fix: "kubectl describe certificate -n " + f[0] + " " + f[1] + " (and its CertificateRequest, Order and Challenge) — usually the issuer, DNS or ACME challenge", Source: "cert-manager"})
			}
		}
	}

	// TLS Secrets.
	tls := map[string]bool{}
	tlsByName := map[string]bool{}
	if ls, ok := lines(exSecrets, "TLS secrets", false); ok {
		for _, l := range ls {
			f := strings.Split(l, "\t")
			if len(f) < 4 {
				continue
			}
			tls[f[0]+"/"+f[1]] = true
			tlsByName[f[1]] = true
			c, ok := readCertsB64(f[3])
			if !ok {
				continue
			}
			sev := expirySeverity(daysLeft(c.NotAfter, today), warn)
			fix := "replace the certificate in the Secret (or move it to cert-manager so it renews itself)"
			extra := ""
			if m, isManaged := managed[f[0]+"/"+f[1]]; isManaged || f[2] != "" {
				extra = "renewed by cert-manager"
				fix = "cert-manager renews it; check the Certificate is Ready"
				if m.ready == "True" {
					sev = lower(sev)
					if m.renewal != "" {
						extra += " from " + strings.SplitN(m.renewal, "T", 2)[0]
					}
				} else if m.ready == "False" {
					extra = "cert-manager is NOT renewing it"
				}
			}
			cert("tls-secret", "secret/"+f[0]+"/"+f[1], c, sev, fix, extra)
		}
	}

	// Ingresses and Gateways naming a certificate that is not there.
	if ls, ok := lines(exIngresses, "ingresses", false); ok && len(r.Outs) > exSecrets && r.Outs[exSecrets].Err == nil {
		for _, l := range ls {
			f := strings.Split(l, "\t")
			if len(f) < 3 {
				continue
			}
			for _, s := range strings.Fields(f[2]) {
				if !tls[f[0]+"/"+s] {
					cf.add(checkFinding{Check: "missing-certificate", Area: "certificates", Severity: "high", Title: "serves TLS from a Secret that is not there",
						Object: "ingress/" + f[0] + "/" + f[1], Detail: "secret " + s + " is missing in " + f[0] + " (or is not of type kubernetes.io/tls); clients get the controller's default certificate",
						Fix: "create the TLS Secret in the Ingress's namespace, or correct spec.tls[].secretName", Source: "kubernetes"})
				}
			}
		}
	}
	if ls, ok := lines(exGateways, "Istio gateways", true); ok && len(r.Outs) > exSecrets && r.Outs[exSecrets].Err == nil {
		for _, l := range ls {
			f := strings.Split(l, "\t")
			if len(f) < 3 {
				continue
			}
			for _, s := range strings.Fields(f[2]) {
				if !tlsByName[s] { // it lives with the gateway's pods, whose namespace the object does not say
					cf.add(checkFinding{Check: "missing-certificate", Area: "certificates", Severity: "high", Title: "serves TLS from a credential that is not there",
						Object: "gateway/" + f[0] + "/" + f[1], Detail: "no TLS Secret named " + s + " in any namespace",
						Fix: "create the TLS Secret in the ingress gateway's namespace (e.g. istio-system), or correct tls.credentialName", Source: "kubernetes"})
				}
			}
		}
	}

	// Webhook and API service CA bundles: when they expire, the API server
	// cannot call the webhook — creates fail, or the API group disappears.
	if ls, ok := lines(exWebhooks, "webhook configurations", false); ok {
		cfgName := ""
		for _, l := range ls {
			f := strings.Split(l, "\t")
			switch {
			case len(f) >= 3 && f[0] == "H":
				cfgName = strings.ToLower(strings.TrimSuffix(f[1], "Configuration")) + "/" + f[2]
			case len(f) >= 3 && f[0] == "B" && f[2] != "":
				if c, ok := readCertsB64(f[2]); ok {
					cert("webhook-ca", cfgName+" ("+f[1]+")", c, expirySeverity(daysLeft(c.NotAfter, today), warn),
						"rotate the webhook's serving certificate and its caBundle together (often the add-on's own job or cert-manager's ca-injector)", "")
				}
			}
		}
	}
	if ls, ok := lines(exAPIServices, "API services", false); ok {
		for _, l := range ls {
			f := strings.Split(l, "\t")
			if len(f) < 2 || f[1] == "" {
				continue
			}
			if c, ok := readCertsB64(f[1]); ok {
				cert("apiservice-ca", "apiservice/"+f[0], c, expirySeverity(daysLeft(c.NotAfter, today), warn),
					"rotate the aggregated API's serving certificate and spec.caBundle (e.g. metrics-server)", "")
			}
		}
	}
	// The cluster's own CA.
	if len(r.Outs) > exRootCA {
		if r.Outs[exRootCA].Err != nil {
			cf.unassessed("cluster CA (kube-root-ca.crt): %v", r.Outs[exRootCA].Err)
		} else if c, ok := readCerts(r.Outs[exRootCA].Out); ok {
			fix := "rotate the cluster CA (EKS and AKS: the cloud's certificate rotation)"
			if r.Cloud == "azure" {
				fix = "az aks rotate-certs (plan it: nodes and clients take new credentials)"
			}
			cert("cluster-ca", "cluster CA", c, expirySeverity(daysLeft(c.NotAfter, today), max(warn, 180)), fix, "")
		}
	}

	// The Kubernetes version's support.
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if json.Unmarshal(r.Outs[0].Out, &v) == nil && v.GitVersion != "" {
		version := strings.TrimPrefix(strings.SplitN(v.GitVersion, "-", 2)[0], "v")
		cloud := inventory.AWS
		if r.Cloud == "azure" {
			cloud = inventory.Azure
		}
		a := support.Assess(cfg.SupportCalendar, cfg.CostRates, cloud, version, today, 90)
		days := -1
		if a.DaysLeft != nil {
			days = *a.DaysLeft
		}
		fix := "plan the upgrade: nedctl upgrade-check --cluster " + cf.Cluster
		add := func(sev, title, detail string) {
			cf.add(checkFinding{Check: "kubernetes-support", Area: "versions", Severity: sev, Title: title, Object: "Kubernetes " + version, Detail: detail, Fix: fix, Source: "supportCalendar"})
		}
		switch a.Status {
		case support.Unsupported:
			add("critical", "out of support", "no security fixes; the provider may upgrade it on its own")
		case support.Extended:
			add("medium", "in extended support (costs more)", fmt.Sprintf("until %s, %d day(s)", a.PhaseEnds, days))
		case support.Ending:
			add(firstNonBlank(expirySeverity(days, warn), "low"), "standard support ends soon", fmt.Sprintf("on %s, in %d day(s)", a.PhaseEnds, days))
		case support.Unknown:
			cf.unassessed("support window of Kubernetes %s: not in supportCalendar (nedctl fleet calendar aws writes it)", version)
		default:
			if all {
				add("info", "in standard support", fmt.Sprintf("until %s, %d day(s)", a.PhaseEnds, days))
			}
		}
	}
	cf.Summary = map[string]any{"certificatesChecked": checked}
	cf.finish()
	return cf
}

func cmdExpiry(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("expiry", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	warn := fs.Int("days", 30, "medium when it expires within this many days (a week is high, expired critical, 90 days low)")
	ns := fs.String("n", "", "only this namespace's Secrets, Certificates, Ingresses and Gateways")
	all := fs.Bool("all", false, "also list what expires later than 90 days")
	minSev := fs.String("min", "low", "show findings at least this severe: info, low, medium, high, critical")
	failOn := failOnFlag(fs, "high")
	output := addOutputFlag(fs)
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 0 || *warn < 1 || *warn > 365 || severityRank(*minSev) < 0 || !validFailOn(*failOn) || (*ns != "" && !config.ValidNamespace(*ns)) {
		fmt.Fprintln(stderr, "usage: nedctl expiry [--cluster C | --env prod | --aws | --aws-env ete,qa] [--match WORD] [--days 30] [-n NS] [--all] [--fail-on high] [-o json]")
		return ExitUsage
	}
	if *output != "table" && *output != "json" {
		return badOutput(stderr, *output)
	}
	if *all {
		*minSev = "info"
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	results, code := runProbes(ctx, cfg, sel, expiryProbes(*ns), stderr)
	if code != ExitOK {
		return code
	}
	report := make([]clusterFindings, 0, len(results))
	for _, r := range results {
		report = append(report, assessExpiry(cfg, r, now(), *warn, *all))
	}
	if *output == "json" {
		if code := writeJSON(stdout, stderr, findingsDoc("expiry", report, map[string]any{"warnDays": *warn})); code != ExitOK {
			return code
		}
	} else {
		printReport(stdout, cfg, report, *minSev)
		printFixes(stdout, report, *minSev)
		fmt.Fprintf(stdout, "\n%s\n", ui.Style{Color: colorOn(stdout)}.Dim("private keys are never printed · -o json is the evidence · --fail-on medium makes a pipeline gate"))
	}
	if failed(report, *failOn) {
		return ExitFailure
	}
	return ExitOK
}
