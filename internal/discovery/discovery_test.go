package discovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"nedctl/internal/config"
	"nedctl/internal/inventory"
)

// fakeCloud answers CLI invocations from a table keyed by a substring of the
// joined command line. The first matching rule wins.
type fakeCloud struct {
	rules []rule
	delay time.Duration

	inFlight, peak atomic.Int32
	mu             sync.Mutex
	calls          []string
}

type rule struct {
	match string
	out   string
	err   error
}

func (f *fakeCloud) on(match, out string) { f.rules = append(f.rules, rule{match: match, out: out}) }
func (f *fakeCloud) fail(match string, e error) {
	f.rules = append(f.rules, rule{match: match, err: e})
}

func (f *fakeCloud) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	n := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		p := f.peak.Load()
		if n <= p || f.peak.CompareAndSwap(p, n) {
			break
		}
	}
	line := name + " " + strings.Join(args, " ")
	f.mu.Lock()
	f.calls = append(f.calls, line)
	f.mu.Unlock()
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	for _, r := range f.rules {
		if strings.Contains(line, r.match) {
			return []byte(r.out), r.err
		}
	}
	return nil, fmt.Errorf("fake cloud: unexpected call %q", line)
}

func eks(name, version, status string, tags string) string {
	return fmt.Sprintf(`{"cluster":{"name":%q,"arn":"arn:aws:eks:eu-west-1:111111111111:cluster/%s","version":%q,"status":%q,"tags":%s}}`,
		name, name, version, status, tags)
}

func awsScope() config.Discovery {
	return config.Discovery{AWS: []config.AWSTarget{{Profile: "pay-prod", Account: "111111111111", Regions: []string{"eu-west-1"}}}}
}

func TestScanAWSDescribesAndEnrichesFromTags(t *testing.T) {
	f := &fakeCloud{}
	f.on("sts get-caller-identity", `{"Account":"111111111111"}`)
	f.on("eks list-clusters", `{"clusters":["pay-prod","pay-legacy"]}`)
	f.on("--name pay-prod ", eks("pay-prod", "1.30", "ACTIVE", `{"Environment":"prod","owner":"payments","cost-centre":"CC-1"}`))
	f.on("--name pay-legacy ", eks("pay-legacy", "1.27", "ACTIVE", `{}`))

	res := Scan(context.Background(), f.run, awsScope())
	if !res.Complete() || len(res.Scanned) != 1 || len(res.Clusters) != 2 {
		t.Fatalf("got %+v", res)
	}
	c := res.Clusters[1] // sorted: pay-legacy, pay-prod
	if c.Name != "pay-prod" || c.Version != "1.30" || c.Account != "111111111111" || c.Region != "eu-west-1" {
		t.Fatalf("identity/version: %+v", c)
	}
	if c.Environment != "prod" || c.Owner != "payments" || c.CostCentre != "CC-1" {
		t.Fatalf("tag enrichment (case-insensitive keys): %+v", c.Cluster)
	}
	if !strings.HasPrefix(c.ID, "arn:aws:eks:") || c.Status != "ACTIVE" {
		t.Fatalf("id/status: %+v", c)
	}
	for _, call := range f.calls {
		if !strings.Contains(call, "--profile pay-prod") || !strings.Contains(call, "--output json") {
			t.Fatalf("call missing profile/output: %q", call)
		}
	}
}

func TestScanRefusesProfileForWrongAccount(t *testing.T) {
	f := &fakeCloud{}
	f.on("sts get-caller-identity", `{"Account":"999999999999"}`)
	res := Scan(context.Background(), f.run, awsScope())
	if res.Complete() || len(res.Scanned) != 0 {
		t.Fatalf("wrong-account profile must not be scanned: %+v", res)
	}
	if !strings.Contains(res.Errors[0].Error, "resolve to account 999999999999, expected 111111111111") {
		t.Fatalf("got %+v", res.Errors)
	}
	for _, call := range f.calls {
		if strings.Contains(call, "eks") {
			t.Fatalf("scanned EKS despite identity mismatch: %q", call)
		}
	}
}

func TestOneFailedDescribeFailsWholeRegion(t *testing.T) {
	f := &fakeCloud{}
	f.on("sts get-caller-identity", `{"Account":"111111111111"}`)
	f.on("eks list-clusters", `{"clusters":["a","b"]}`)
	f.on("--name a ", eks("a", "1.30", "ACTIVE", `{}`))
	f.fail("--name b ", errors.New("AccessDenied"))
	res := Scan(context.Background(), f.run, awsScope())
	if res.Complete() || len(res.Scanned) != 0 || len(res.Clusters) != 0 {
		t.Fatalf("a partially described region must not count as scanned: %+v", res)
	}
	if !strings.Contains(res.Errors[0].Error, "describing b") {
		t.Fatalf("got %+v", res.Errors)
	}
}

func TestRegionFailureIsolatedFromOtherRegions(t *testing.T) {
	f := &fakeCloud{}
	f.on("sts get-caller-identity", `{"Account":"111111111111"}`)
	f.fail("list-clusters --region eu-central-1", errors.New("could not connect"))
	f.on("list-clusters --region eu-west-1", `{"clusters":[]}`)
	d := awsScope()
	d.AWS[0].Regions = []string{"eu-west-1", "eu-central-1"}
	res := Scan(context.Background(), f.run, d)
	if len(res.Scanned) != 1 || res.Scanned[0].Region != "eu-west-1" || len(res.Errors) != 1 {
		t.Fatalf("got %+v", res)
	}
}

func TestScanAzureResolvesSubscriptionAndPrefersRunningVersion(t *testing.T) {
	f := &fakeCloud{}
	f.on("account show --subscription sub-core-prod", `{"id":"0000-aaaa","name":"sub-core-prod"}`)
	f.on("aks list --subscription 0000-aaaa", `[{"name":"aks-core-prod-weu","id":"/subscriptions/0000-aaaa/x","location":"westeurope",
	  "resourceGroup":"RG-AKS-CORE-PROD","kubernetesVersion":"1.31","currentKubernetesVersion":"1.30.4",
	  "provisioningState":"Succeeded","tags":{"environment":"prod"}}]`)
	res := Scan(context.Background(), f.run, config.Discovery{Azure: []config.AzureTarget{{Subscription: "sub-core-prod"}}})
	if !res.Complete() || len(res.Clusters) != 1 {
		t.Fatalf("got %+v", res)
	}
	c := res.Clusters[0]
	if c.Version != "1.30.4" {
		t.Fatalf("want running version 1.30.4, got %q", c.Version)
	}
	if c.Subscription != "0000-aaaa" || c.Environment != "prod" || c.Cloud != inventory.Azure {
		t.Fatalf("got %+v", c.Cluster)
	}
	if s := res.Scanned[0]; s.Subscription != "0000-aaaa" || s.SubscriptionName != "sub-core-prod" {
		t.Fatalf("scope: %+v", s)
	}
}

func TestConcurrencyIsBoundedAcrossWholeScan(t *testing.T) {
	f := &fakeCloud{delay: 20 * time.Millisecond}
	f.on("sts get-caller-identity", `{"Account":"111111111111"}`)
	names := make([]string, 40)
	for i := range names {
		names[i] = fmt.Sprintf("%q", fmt.Sprintf("c%02d", i))
	}
	f.on("eks list-clusters", `{"clusters":[`+strings.Join(names, ",")+`]}`)
	f.on("describe-cluster", eks("x", "1.30", "ACTIVE", `{}`))
	d := awsScope()
	d.AWS[0].Regions = []string{"eu-west-1", "eu-west-2", "eu-central-1"}
	d.Concurrency = 4
	res := Scan(context.Background(), f.run, d)
	if !res.Complete() || len(res.Clusters) != 120 {
		t.Fatalf("clusters=%d errors=%v", len(res.Clusters), res.Errors)
	}
	if p := f.peak.Load(); p > 4 {
		t.Fatalf("peak concurrency %d exceeded limit 4", p)
	}
	if p := f.peak.Load(); p < 2 {
		t.Fatalf("peak concurrency %d: scan is not actually parallel", p)
	}
}

func TestCancellationStopsScan(t *testing.T) {
	f := &fakeCloud{delay: time.Minute}
	f.on("", "{}")
	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	start := time.Now()
	res := Scan(ctx, f.run, awsScope())
	if time.Since(start) > 5*time.Second {
		t.Fatal("scan did not stop on cancellation")
	}
	if res.Complete() {
		t.Fatal("a cancelled scan must not be complete")
	}
}

func TestResultIsDeterministic(t *testing.T) {
	build := func() Result {
		f := &fakeCloud{}
		f.on("sts get-caller-identity", `{"Account":"111111111111"}`)
		f.on("eks list-clusters", `{"clusters":["zeta","alpha","mid"]}`)
		f.on("--name zeta ", eks("zeta", "1.30", "ACTIVE", `{}`))
		f.on("--name alpha ", eks("alpha", "1.30", "ACTIVE", `{}`))
		f.on("--name mid ", eks("mid", "1.30", "ACTIVE", `{}`))
		return Scan(context.Background(), f.run, awsScope())
	}
	for i := 0; i < 20; i++ {
		r := build()
		if got := r.Clusters[0].Name + r.Clusters[1].Name + r.Clusters[2].Name; got != "alphamidzeta" {
			t.Fatalf("run %d: order %q", i, got)
		}
	}
}

// Well beyond today's estate: 50 accounts × 3 regions × 10 clusters, every
// call with latency. The scan must be complete, correct and bounded.
func TestScanAtFleetScale(t *testing.T) {
	const accounts, perRegion, workers = 50, 10, 16
	regions := []string{"eu-west-1", "eu-west-2", "eu-central-1"}
	f := &fakeCloud{delay: 2 * time.Millisecond}
	var d config.Discovery
	d.Concurrency = workers
	for a := 0; a < accounts; a++ {
		acct := fmt.Sprintf("%012d", 100000000000+a)
		profile := "p" + acct
		d.AWS = append(d.AWS, config.AWSTarget{Profile: profile, Account: acct, Regions: regions})
		f.on("get-caller-identity --output json --profile "+profile, `{"Account":"`+acct+`"}`)
		for _, r := range regions {
			var names []string
			for c := 0; c < perRegion; c++ {
				names = append(names, fmt.Sprintf(`"c%d-%s-%d"`, a, r, c))
			}
			f.on("list-clusters --region "+r+" --output json --profile "+profile, `{"clusters":[`+strings.Join(names, ",")+`]}`)
		}
	}
	f.on("describe-cluster", `{"cluster":{"version":"1.30","status":"ACTIVE"}}`)

	start := time.Now()
	res := Scan(context.Background(), f.run, d)
	elapsed := time.Since(start)

	want := accounts * len(regions) * perRegion
	if !res.Complete() || len(res.Clusters) != want || len(res.Scanned) != accounts*len(regions) {
		t.Fatalf("clusters=%d/%d scanned=%d errors=%d", len(res.Clusters), want, len(res.Scanned), len(res.Errors))
	}
	if p := f.peak.Load(); p > workers {
		t.Fatalf("peak concurrency %d exceeded %d", p, workers)
	}
	calls := accounts + accounts*len(regions) + want
	t.Logf("%d clusters, %d CLI calls, peak concurrency %d, %s", want, calls, f.peak.Load(), elapsed)
}
