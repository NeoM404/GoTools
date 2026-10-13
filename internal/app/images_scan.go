package app

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/httpx"
	"nedctl/internal/ui"
)

// `nedctl images scan` puts the vulnerability results the bank already has
// next to what is actually running: every image (by digest) on the clusters
// selected, with its critical and high counts from each scanner —
//
//   - ECR image scanning (basic or Amazon Inspector enhanced), for images in
//     ECR, read with your AWS profile;
//   - Trivy Operator's VulnerabilityReports in the cluster (read-only, no
//     image pulls), and the trivy CLI when asked (--source trivy);
//   - Prisma Cloud Compute (Twistlock), with a short-lived token from
//     NEDCTL_PRISMA_TOKEN (never stored).
//
// An image no scanner has a result for is a finding too: a blind spot.

var ecrHostRe = regexp.MustCompile(`^([0-9]{12})\.dkr\.ecr(-fips)?\.([a-z0-9-]+)\.amazonaws\.com$`)

var trivyReportsProbe = listProbe("vulnerabilityreports.aquasecurity.github.io", "", `{range .items[*]}{.report.registry.server}{"\t"}{.report.artifact.repository}{"\t"}{.report.artifact.tag}{"\t"}{.report.artifact.digest}{"\t"}{.report.summary.criticalCount}{"\t"}{.report.summary.highCount}{"\t"}{.report.summary.mediumCount}{"\t"}{.report.summary.lowCount}{"\t"}{.report.updateTimestamp}{"\t"}{.report.vulnerabilities[?(@.severity=="CRITICAL")].vulnerabilityID}{"\n"}{end}`)

// scanResult is one scanner's answer for one image.
type scanResult struct {
	Source   string   `json:"source"`
	Critical int      `json:"critical"`
	High     int      `json:"high"`
	Medium   int      `json:"medium"`
	Low      int      `json:"low"`
	Fixable  int      `json:"fixableCriticalOrHigh"`
	Top      []string `json:"topCritical,omitempty"`
	When     string   `json:"scanned,omitempty"`
	Error    string   `json:"error,omitempty"`
}

type scannedImage struct {
	imageRow
	Results []scanResult `json:"results"`
}

func (s scannedImage) worst() (crit, high, fixable int, sources []string) {
	for _, r := range s.Results {
		if r.Error != "" {
			continue
		}
		sources = append(sources, r.Source)
		crit, high, fixable = max(crit, r.Critical), max(high, r.High), max(fixable, r.Fixable)
	}
	return
}

// prismaClient is the HTTPS client for Prisma Cloud (tests replace it).
var prismaClient = func() *http.Client { return httpx.Client(20*time.Second, nil) }

func cmdImagesScan(ctx context.Context, cfgPath string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("images scan", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, true)
	sources := fs.String("source", "", "scanners to ask: ecr, trivy-operator, prisma, trivy (default: ecr, trivy-operator, and prisma when configured)")
	limit := fs.Int("limit", 300, "at most this many images (the largest estates: narrow with --match)")
	failOn := failOnFlag(fs, "critical")
	output := fs.String("o", "table", "output format: table|json|csv")
	pos, err := parseInterspersed(fs, args)
	if err != nil || len(pos) > 0 || !validFailOn(*failOn) || *limit < 1 || (*output != "table" && *output != "json" && *output != "csv") {
		fmt.Fprintln(stderr, "usage: nedctl images scan [--cluster C | --env prod | --aws | --aws-env ete,qa] [--match WORD] [--source ecr,trivy-operator,prisma,trivy] [--fail-on critical] [-o table|json|csv]")
		return ExitUsage
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	use := map[string]bool{}
	if *sources == "" {
		use["ecr"], use["trivy-operator"] = cfg.AWS.Configured(), true
		use["prisma"] = cfg.Security.PrismaAPI != "" && os.Getenv("NEDCTL_PRISMA_TOKEN") != ""
	}
	for _, s := range strings.Split(*sources, ",") {
		if s = strings.TrimSpace(s); s == "" {
			continue
		}
		if s != "ecr" && s != "trivy-operator" && s != "prisma" && s != "trivy" {
			fmt.Fprintf(stderr, "--source %q: want ecr, trivy-operator, prisma or trivy\n", s)
			return ExitUsage
		}
		use[s] = true
	}
	if use["prisma"] && (cfg.Security.PrismaAPI == "" || os.Getenv("NEDCTL_PRISMA_TOKEN") == "") {
		fmt.Fprintln(stderr, "Prisma Cloud needs security.prismaApi in the config and a token in NEDCTL_PRISMA_TOKEN (from the console; it is never stored)")
		return ExitUsage
	}
	probes := []probe{versionProbe, imagesProbe}
	if use["trivy-operator"] {
		probes = append(probes, trivyReportsProbe)
	}
	results, code := runProbes(ctx, cfg, sel, probes, stderr)
	if code != ExitOK {
		return code
	}
	for i := range results { // imageInventory reads the image list as the first probe
		if results[i].Err == nil && len(results[i].Outs) > 1 {
			results[i].Outs = results[i].Outs[1:]
		}
	}
	rows, unreachable := imageInventory(cfg, results)
	var notes []string
	if len(rows) > *limit {
		notes = append(notes, fmt.Sprintf("%d images running; only the first %d are scanned (narrow with --match)", len(rows), *limit))
		rows = rows[:*limit]
	}
	imgs := make([]scannedImage, len(rows))
	for i, r := range rows {
		imgs[i] = scannedImage{imageRow: r}
	}
	if use["trivy-operator"] {
		trivyOperatorResults(results, imgs, &notes)
	}
	sp := spinning(stderr, fmt.Sprintf("Asking the scanners about %d image(s)…", len(imgs)))
	var wg sync.WaitGroup
	if use["ecr"] {
		wg.Add(1)
		go func() { defer wg.Done(); ecrResults(ctx, cfg, sel.awsProfile, imgs) }()
	}
	if use["prisma"] {
		wg.Add(1)
		go func() { defer wg.Done(); prismaResults(ctx, cfg, imgs) }()
	}
	if use["trivy"] {
		wg.Add(1)
		go func() { defer wg.Done(); trivyCLIResults(ctx, cfg, imgs) }()
	}
	wg.Wait()
	sp.Stop()
	for i := range imgs {
		sort.Slice(imgs[i].Results, func(a, b int) bool { return imgs[i].Results[a].Source < imgs[i].Results[b].Source })
	}

	// Findings: vulnerable images, and images no scanner knows.
	report := clusterFindings{Cluster: "running images", Status: "ok", Findings: []checkFinding{}}
	for _, img := range imgs {
		crit, high, fix, srcs := img.worst()
		where := fmt.Sprintf("in %d cluster(s): %s", len(img.Clusters), strings.Join(img.Clusters[:min(3, len(img.Clusters))], ", "))
		var top []string
		for _, r := range img.Results {
			top = append(top, r.Top...)
		}
		sort.Strings(top)
		top = dedupe(top)
		detail := where + "; " + strings.Join(srcs, ", ")
		if len(top) > 0 {
			detail += "; " + strings.Join(top[:min(5, len(top))], ", ")
		}
		switch {
		case len(srcs) == 0:
			report.add(checkFinding{Check: "not-scanned", Area: "images", Severity: "medium", Title: "no scanner has a result for this image", Object: img.Image,
				Detail: where, Fix: "scan it (push it through ECR scanning, Prisma or Trivy) — an unscanned image is a blind spot", Source: "scan"})
		case crit > 0 && fix > 0:
			report.add(checkFinding{Check: "vulnerable-image", Area: "images", Severity: "critical", Title: fmt.Sprintf("%d critical, %d high vulnerabilities (%d with a fix)", crit, high, fix), Object: img.Image, Detail: detail,
				Fix: "rebuild on a patched base image or dependency and redeploy", Source: strings.Join(srcs, ",")})
		case crit > 0:
			report.add(checkFinding{Check: "vulnerable-image", Area: "images", Severity: "high", Title: fmt.Sprintf("%d critical, %d high vulnerabilities (no fix yet)", crit, high), Object: img.Image, Detail: detail,
				Fix: "track the fix; mitigate (network policy, least privilege) until it lands", Source: strings.Join(srcs, ",")})
		case high > 0:
			report.add(checkFinding{Check: "vulnerable-image", Area: "images", Severity: "medium", Title: fmt.Sprintf("%d high vulnerabilities", high), Object: img.Image, Detail: detail,
				Fix: "rebuild on a patched base image in the next release", Source: strings.Join(srcs, ",")})
		}
	}
	report.finish()
	for _, u := range unreachable {
		report.unassessed("%s", u)
	}

	switch *output {
	case "json":
		if imgs == nil {
			imgs = []scannedImage{}
		}
		if code := writeJSON(stdout, stderr, map[string]any{"schema": findingsSchema, "command": "images scan", "generated": now().UTC().Format("2006-01-02T15:04:05Z"),
			"images": imgs, "clusters": []clusterFindings{report}, "notes": notes}); code != ExitOK {
			return code
		}
	case "csv":
		w := csv.NewWriter(stdout)
		_ = w.Write([]string{"image", "digests", "clusters", "source", "critical", "high", "medium", "low", "fixable", "error"})
		for _, img := range imgs {
			if len(img.Results) == 0 {
				_ = w.Write([]string{img.Image, strings.Join(img.Digests, " "), strings.Join(img.Clusters, " "), "", "", "", "", "", "", "not scanned"})
			}
			for _, r := range img.Results {
				_ = w.Write([]string{img.Image, strings.Join(img.Digests, " "), strings.Join(img.Clusters, " "), r.Source, fmt.Sprint(r.Critical), fmt.Sprint(r.High), fmt.Sprint(r.Medium), fmt.Sprint(r.Low), fmt.Sprint(r.Fixable), r.Error})
			}
		}
		w.Flush()
	default:
		printScan(stdout, cfg, imgs, report)
	}
	for _, n := range notes {
		fmt.Fprintln(stderr, "note: "+n)
	}
	if failed([]clusterFindings{report}, *failOn) {
		return ExitFailure
	}
	return ExitOK
}

func printScan(w io.Writer, cfg config.Config, imgs []scannedImage, report clusterFindings) {
	st := ui.Style{Color: colorOn(w)}
	sort.SliceStable(imgs, func(i, j int) bool {
		ci, hi, _, _ := imgs[i].worst()
		cj, hj, _, _ := imgs[j].worst()
		if ci != cj {
			return ci > cj
		}
		return hi > hj
	})
	tw := newTable(w)
	fmt.Fprintln(tw, "IMAGE\tCRITICAL\tHIGH\tFIXABLE\tSCANNED BY\tCLUSTERS")
	for _, img := range imgs {
		crit, high, fix, srcs := img.worst()
		by := strings.Join(srcs, ", ")
		if by == "" {
			by = "nobody"
		}
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%s\t%d\n", img.Image, crit, high, fix, by, len(img.Clusters))
	}
	tw.Flush()
	fmt.Fprintln(w)
	printReport(w, cfg, []clusterFindings{report}, "medium")
	fmt.Fprintf(w, "\n%s\n", st.Dim("counts are the most any scanner reports · -o json has each scanner's result · -o csv for a spreadsheet"))
}

// trivyOperatorResults reads Trivy Operator's VulnerabilityReports.
func trivyOperatorResults(results []clusterOut, imgs []scannedImage, notes *[]string) {
	byDigest := map[string]scanResult{}
	byRef := map[string]scanResult{}
	found := false
	for _, r := range results {
		if r.reachErr() != nil || len(r.Outs) < 2 {
			continue
		}
		if err := r.Outs[1].Err; err != nil {
			if !notInstalled(err) {
				*notes = append(*notes, fmt.Sprintf("%s: Trivy Operator reports not read: %v", r.Cluster, err))
			}
			continue
		}
		for _, l := range nonEmptyLines(string(r.Outs[1].Out)) {
			f := strings.Split(l, "\t")
			if len(f) < 10 {
				continue
			}
			found = true
			res := scanResult{Source: "trivy-operator", Critical: atoi(f[4]), High: atoi(f[5]), Medium: atoi(f[6]), Low: atoi(f[7]), When: f[8], Top: strings.Fields(f[9])}
			if f[3] != "" {
				byDigest[f[3]] = res
			}
			ref := f[1] + ":" + f[2]
			if f[0] != "" && f[0] != "index.docker.io" {
				ref = f[0] + "/" + ref
			}
			byRef[ref] = res
		}
	}
	if !found {
		return
	}
	for i, img := range imgs {
		for _, d := range img.Digests {
			if res, ok := byDigest[d]; ok {
				imgs[i].Results = append(imgs[i].Results, res)
				goto next
			}
		}
		if res, ok := byRef[strings.TrimPrefix(img.Image, "docker.io/")]; ok {
			imgs[i].Results = append(imgs[i].Results, res)
		}
	next:
	}
}

// ecrResults asks ECR for each running digest in ECR.
func ecrResults(ctx context.Context, cfg config.Config, profileFlag string, imgs []scannedImage) {
	profile := resolveProfile(cfg, profileFlag)
	sem := make(chan struct{}, 4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range imgs {
		host := imgs[i].Registry
		m := ecrHostRe.FindStringSubmatch(host)
		if m == nil || len(imgs[i].Digests) == 0 {
			continue
		}
		repo := strings.TrimPrefix(imgs[i].Image, host+"/")
		repo, _, _ = strings.Cut(repo, "@")
		if j := strings.LastIndex(repo, ":"); j > 0 {
			repo = repo[:j]
		}
		wg.Add(1)
		go func(i int, account, region, repo, digest string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			res := ecrScan(ctx, cfg, profile, account, region, repo, digest)
			mu.Lock()
			imgs[i].Results = append(imgs[i].Results, res)
			mu.Unlock()
		}(i, m[1], m[3], repo, imgs[i].Digests[0])
	}
	wg.Wait()
}

func ecrScan(ctx context.Context, cfg config.Config, profile, account, region, repo, digest string) scanResult {
	res := scanResult{Source: "ecr"}
	args := []string{"ecr", "describe-image-scan-findings", "--registry-id", account, "--repository-name", repo, "--image-id", "imageDigest=" + digest, "--max-items", "100", "--region", region, "--output", "json"}
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	out, err := execx.Output(ctx, cfg.Timeout(), "aws", args...)
	if err != nil {
		msg := err.Error()
		switch {
		case strings.Contains(msg, "ScanNotFoundException"):
			msg = "not scanned in ECR"
		case strings.Contains(msg, "AccessDenied"):
			msg = "not allowed to read ECR scan results in account " + account
		}
		res.Error = msg
		return res
	}
	var v struct {
		ImageScanStatus   struct{ Status string }
		ImageScanFindings struct {
			FindingSeverityCounts map[string]int
			ImageScanCompletedAt  json.RawMessage
			Findings              []struct{ Name, Severity string }
			EnhancedFindings      []struct {
				Severity                    string
				FixAvailable                string
				PackageVulnerabilityDetails struct{ VulnerabilityID string }
			}
		}
	}
	if err := json.Unmarshal(out, &v); err != nil {
		res.Error = "unreadable answer from ECR"
		return res
	}
	if s := v.ImageScanStatus.Status; s != "" && s != "COMPLETE" && s != "ACTIVE" {
		res.Error = "ECR scan status " + s
		return res
	}
	c := v.ImageScanFindings.FindingSeverityCounts
	res.Critical, res.High, res.Medium, res.Low = c["CRITICAL"], c["HIGH"], c["MEDIUM"], c["LOW"]
	res.When, _ = awsDate(v.ImageScanFindings.ImageScanCompletedAt)
	for _, f := range v.ImageScanFindings.EnhancedFindings {
		if f.Severity == "CRITICAL" {
			res.Top = append(res.Top, f.PackageVulnerabilityDetails.VulnerabilityID)
		}
		if (f.Severity == "CRITICAL" || f.Severity == "HIGH") && f.FixAvailable == "YES" {
			res.Fixable++
		}
	}
	for _, f := range v.ImageScanFindings.Findings {
		if f.Severity == "CRITICAL" {
			res.Top = append(res.Top, f.Name)
		}
	}
	return res
}

// prismaResults asks Prisma Cloud Compute about each running image.
func prismaResults(ctx context.Context, cfg config.Config, imgs []scannedImage) {
	client := prismaClient()
	token := os.Getenv("NEDCTL_PRISMA_TOKEN")
	base := strings.TrimRight(cfg.Security.PrismaAPI, "/")
	type prismaImage struct {
		RepoDigests  []string `json:"repoDigests"`
		Distribution struct {
			Critical, High, Medium, Low int
		} `json:"vulnerabilityDistribution"`
		Vulnerabilities []struct {
			Cve, Severity, Status string
		} `json:"vulnerabilities"`
		ScanTime string `json:"scanTime"`
	}
	cache := map[string][]prismaImage{}
	for i, img := range imgs {
		repo := img.Image
		if j := strings.LastIndexAny(repo, ":@"); j > strings.LastIndex(repo, "/") {
			repo = repo[:j]
		}
		list, seen := cache[repo]
		if !seen {
			q := url.Values{"search": {repo}, "limit": {"50"}, "fields": {"repoDigests,vulnerabilityDistribution,vulnerabilities,scanTime"}}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/images?"+q.Encode(), nil)
			if err != nil {
				continue
			}
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := client.Do(req)
			if err != nil {
				imgs[i].Results = append(imgs[i].Results, scanResult{Source: "prisma", Error: "Prisma Cloud not reachable"})
				continue
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				imgs[i].Results = append(imgs[i].Results, scanResult{Source: "prisma", Error: fmt.Sprintf("Prisma Cloud answered %s (an expired token is 401)", resp.Status)})
				continue
			}
			_ = json.Unmarshal(body, &list)
			cache[repo] = list
		}
		for _, p := range list {
			match := false
			for _, rd := range p.RepoDigests {
				for _, d := range img.Digests {
					match = match || strings.HasSuffix(rd, "@"+d)
				}
			}
			if !match {
				continue
			}
			res := scanResult{Source: "prisma", Critical: p.Distribution.Critical, High: p.Distribution.High, Medium: p.Distribution.Medium, Low: p.Distribution.Low, When: p.ScanTime}
			for _, v := range p.Vulnerabilities {
				sev := strings.ToLower(v.Severity)
				if sev == "critical" {
					res.Top = append(res.Top, v.Cve)
				}
				if (sev == "critical" || sev == "high") && strings.HasPrefix(strings.ToLower(v.Status), "fixed") {
					res.Fixable++
				}
			}
			imgs[i].Results = append(imgs[i].Results, res)
			break
		}
	}
}

// trivyCLIResults runs the trivy CLI on each digest (client mode against
// security.trivyServer when set), two at a time.
func trivyCLIResults(ctx context.Context, cfg config.Config, imgs []scannedImage) {
	sem := make(chan struct{}, 2)
	var wg sync.WaitGroup
	var mu sync.Mutex
	for i := range imgs {
		ref := imgs[i].Image
		if len(imgs[i].Digests) > 0 && !strings.Contains(ref, "@") {
			if j := strings.LastIndex(ref, ":"); j > strings.LastIndex(ref, "/") {
				ref = ref[:j]
			}
			ref += "@" + imgs[i].Digests[0]
		}
		wg.Add(1)
		go func(i int, ref string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			args := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln"}
			if cfg.Security.TrivyServer != "" {
				args = append(args, "--server", cfg.Security.TrivyServer)
			}
			out, err := execx.Output(ctx, 10*time.Minute, "trivy", append(args, ref)...)
			res := scanResult{Source: "trivy"}
			var v struct {
				Results []struct {
					Vulnerabilities []struct{ VulnerabilityID, Severity, FixedVersion string }
				}
			}
			switch {
			case err != nil:
				res.Error = "trivy: " + err.Error()
			case json.Unmarshal(out, &v) != nil:
				res.Error = "unreadable answer from trivy"
			default:
				for _, r := range v.Results {
					for _, x := range r.Vulnerabilities {
						switch x.Severity {
						case "CRITICAL":
							res.Critical++
							res.Top = append(res.Top, x.VulnerabilityID)
						case "HIGH":
							res.High++
						case "MEDIUM":
							res.Medium++
						case "LOW":
							res.Low++
						}
						if (x.Severity == "CRITICAL" || x.Severity == "HIGH") && x.FixedVersion != "" {
							res.Fixable++
						}
					}
				}
				res.When = now().UTC().Format("2006-01-02")
			}
			mu.Lock()
			imgs[i].Results = append(imgs[i].Results, res)
			mu.Unlock()
		}(i, ref)
	}
	wg.Wait()
}
