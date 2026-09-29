// Package discovery enumerates the Kubernetes clusters that actually exist in
// the configured AWS accounts and Azure subscriptions, by driving the aws and
// az CLIs. It is the "observed" side that `inventory diff` reconciles against
// the declared inventory.
//
// Correctness properties the rest of bankctl relies on:
//   - A scope (one AWS account+region, or one Azure subscription) is either
//     scanned completely or reported as an error. A partially listed scope
//     is never reported as scanned, so a completeness claim is never made
//     on partial data.
//   - Identity is verified, not assumed: an AWS profile must resolve to the
//     configured account before anything in it is scanned.
//   - At most Concurrency cloud CLI processes run at once, however many
//     accounts, regions and clusters are in scope.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/NeoM404/GoTools/internal/config"
	"github.com/NeoM404/GoTools/internal/execx"
	"github.com/NeoM404/GoTools/internal/inventory"
)

// Runner runs a CLI and returns its stdout. Production uses ExecRunner; tests
// substitute a fake to drive every cloud response and failure deterministically.
type Runner func(ctx context.Context, name string, args ...string) ([]byte, error)

// ExecRunner runs real CLIs through execx, each call bounded by timeout.
func ExecRunner(timeout time.Duration) Runner {
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		return execx.Output(ctx, timeout, name, args...)
	}
}

// Observed is a cluster as the cloud reports it.
type Observed struct {
	inventory.Cluster
	ID     string            `json:"id"`     // ARN or Azure resource ID
	Status string            `json:"status"` // e.g. ACTIVE (EKS), Succeeded (AKS)
	Tags   map[string]string `json:"tags,omitempty"`
}

// Scope is the unit of an all-or-nothing scan.
type Scope struct {
	Cloud            inventory.Cloud `json:"cloud"`
	Account          string          `json:"account,omitempty"`
	Region           string          `json:"region,omitempty"`
	Subscription     string          `json:"subscription,omitempty"` // resolved subscription ID
	SubscriptionName string          `json:"subscriptionName,omitempty"`
}

func (s Scope) String() string {
	if s.Cloud == inventory.AWS {
		return "aws " + s.Account + "/" + s.Region
	}
	if s.SubscriptionName != "" && !strings.EqualFold(s.SubscriptionName, s.Subscription) {
		return "azure " + s.SubscriptionName + " (" + s.Subscription + ")"
	}
	return "azure " + s.Subscription
}

// ScanError records a scope that could not be scanned completely.
type ScanError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

// Result is the outcome of a scan.
type Result struct {
	Clusters []Observed  `json:"clusters"`
	Scanned  []Scope     `json:"scanned"`
	Errors   []ScanError `json:"errors"`
}

// Complete reports whether every configured scope was scanned.
func (r Result) Complete() bool { return len(r.Errors) == 0 }

// Scan enumerates every configured scope concurrently.
func Scan(ctx context.Context, run Runner, d config.Discovery) Result {
	s := &scanner{run: limit(run, d.Workers()), keys: d.Keys()}
	var wg sync.WaitGroup
	for _, t := range d.AWS {
		wg.Add(1)
		go func() { defer wg.Done(); s.scanAWS(ctx, t) }()
	}
	for _, t := range d.Azure {
		wg.Add(1)
		go func() { defer wg.Done(); s.scanAzure(ctx, t) }()
	}
	wg.Wait()
	return s.result()
}

// limit wraps run so at most n invocations are in flight at once. Callers can
// then fan out freely; the subprocess count stays bounded.
func limit(run Runner, n int) Runner {
	sem := make(chan struct{}, n)
	return func(ctx context.Context, name string, args ...string) ([]byte, error) {
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: %w", name, execx.ErrInterrupted)
		}
		defer func() { <-sem }()
		return run(ctx, name, args...)
	}
}

type scanner struct {
	run  Runner
	keys config.TagKeys

	mu       sync.Mutex
	clusters []Observed
	scanned  []Scope
	errs     []ScanError
}

func (s *scanner) ok(scope Scope, found []Observed) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanned = append(s.scanned, scope)
	s.clusters = append(s.clusters, found...)
}

func (s *scanner) fail(target string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, ScanError{Target: target, Error: err.Error()})
}

// result returns everything in a deterministic order, so two scans of the
// same estate produce identical output (diffable, reviewable).
func (s *scanner) result() Result {
	sort.Slice(s.clusters, func(i, j int) bool { return clusterKey(s.clusters[i]) < clusterKey(s.clusters[j]) })
	sort.Slice(s.scanned, func(i, j int) bool { return s.scanned[i].String() < s.scanned[j].String() })
	sort.Slice(s.errs, func(i, j int) bool { return s.errs[i].Target < s.errs[j].Target })
	return Result{Clusters: s.clusters, Scanned: s.scanned, Errors: s.errs}
}

func clusterKey(o Observed) string {
	return strings.ToLower(strings.Join([]string{string(o.Cloud), o.Account, o.Subscription, o.Region, o.ResourceGroup, o.Name}, "/"))
}

// meta fills inventory metadata from tags. Tag keys match case-insensitively
// (Azure tag keys are case-insensitive; AWS teams are rarely consistent).
func (s *scanner) meta(c *inventory.Cluster, tags map[string]string) {
	c.Environment = tag(tags, s.keys.Environment)
	c.Owner = tag(tags, s.keys.Owner)
	c.CostCentre = tag(tags, s.keys.CostCentre)
}

func tag(tags map[string]string, key string) string {
	if v, ok := tags[key]; ok {
		return v
	}
	for k, v := range tags {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// ---- AWS ----

func awsArgs(profile string, args ...string) []string {
	args = append(args, "--output", "json")
	if profile != "" {
		args = append(args, "--profile", profile)
	}
	return args
}

func awsLabel(t config.AWSTarget, region string) string {
	l := "aws " + t.Account
	if region != "" {
		l += "/" + region
	}
	if t.Profile != "" {
		l += " (profile " + t.Profile + ")"
	}
	return l
}

func (s *scanner) scanAWS(ctx context.Context, t config.AWSTarget) {
	// Verify identity first: scanning with a profile that points at the wrong
	// account would produce a confident, wrong answer.
	out, err := s.run(ctx, "aws", awsArgs(t.Profile, "sts", "get-caller-identity")...)
	if err == nil {
		var id struct{ Account string }
		if err = json.Unmarshal(out, &id); err == nil && id.Account != t.Account {
			err = fmt.Errorf("credentials resolve to account %s, expected %s — refusing to scan", id.Account, t.Account)
		}
	}
	if err != nil {
		for _, r := range t.Regions {
			s.fail(awsLabel(t, r), fmt.Errorf("verifying identity: %w", err))
		}
		return
	}

	var wg sync.WaitGroup
	for _, region := range t.Regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found, err := s.scanAWSRegion(ctx, t, region)
			if err != nil {
				s.fail(awsLabel(t, region), err)
				return
			}
			s.ok(Scope{Cloud: inventory.AWS, Account: t.Account, Region: region}, found)
		}()
	}
	wg.Wait()
}

func (s *scanner) scanAWSRegion(ctx context.Context, t config.AWSTarget, region string) ([]Observed, error) {
	out, err := s.run(ctx, "aws", awsArgs(t.Profile, "eks", "list-clusters", "--region", region)...)
	if err != nil {
		return nil, fmt.Errorf("listing clusters: %w", err)
	}
	var list struct {
		Clusters []string `json:"clusters"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("parsing eks list-clusters: %w", err)
	}

	found := make([]Observed, len(list.Clusters))
	errs := make([]error, len(list.Clusters))
	var wg sync.WaitGroup
	for i, name := range list.Clusters {
		wg.Add(1)
		go func() {
			defer wg.Done()
			found[i], errs[i] = s.describeEKS(ctx, t, region, name)
		}()
	}
	wg.Wait()
	// One undescribed cluster makes the whole region incomplete.
	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return found, nil
}

func (s *scanner) describeEKS(ctx context.Context, t config.AWSTarget, region, name string) (Observed, error) {
	out, err := s.run(ctx, "aws", awsArgs(t.Profile, "eks", "describe-cluster", "--name", name, "--region", region)...)
	if err != nil {
		return Observed{}, fmt.Errorf("describing %s: %w", name, err)
	}
	var d struct {
		Cluster struct {
			Name    string            `json:"name"`
			Arn     string            `json:"arn"`
			Version string            `json:"version"`
			Status  string            `json:"status"`
			Tags    map[string]string `json:"tags"`
		} `json:"cluster"`
	}
	if err := json.Unmarshal(out, &d); err != nil {
		return Observed{}, fmt.Errorf("parsing eks describe-cluster %s: %w", name, err)
	}
	o := Observed{
		Cluster: inventory.Cluster{
			Name: d.Cluster.Name, Cloud: inventory.AWS, Region: region,
			Version: d.Cluster.Version, Account: t.Account,
		},
		ID: d.Cluster.Arn, Status: d.Cluster.Status, Tags: d.Cluster.Tags,
	}
	if o.Name == "" {
		o.Name = name
	}
	s.meta(&o.Cluster, o.Tags)
	return o, nil
}

// ---- Azure ----

func (s *scanner) scanAzure(ctx context.Context, t config.AzureTarget) {
	label := "azure " + t.Subscription
	out, err := s.run(ctx, "az", "account", "show", "--subscription", t.Subscription, "--output", "json", "--only-show-errors")
	if err != nil {
		s.fail(label, fmt.Errorf("resolving subscription: %w", err))
		return
	}
	var sub struct{ ID, Name string }
	if err := json.Unmarshal(out, &sub); err != nil || sub.ID == "" {
		s.fail(label, fmt.Errorf("parsing az account show: %v", err))
		return
	}

	out, err = s.run(ctx, "az", "aks", "list", "--subscription", sub.ID, "--output", "json", "--only-show-errors")
	if err != nil {
		s.fail(label, fmt.Errorf("listing clusters: %w", err))
		return
	}
	var list []struct {
		Name                     string            `json:"name"`
		ID                       string            `json:"id"`
		Location                 string            `json:"location"`
		ResourceGroup            string            `json:"resourceGroup"`
		KubernetesVersion        string            `json:"kubernetesVersion"`
		CurrentKubernetesVersion string            `json:"currentKubernetesVersion"`
		ProvisioningState        string            `json:"provisioningState"`
		Tags                     map[string]string `json:"tags"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		s.fail(label, fmt.Errorf("parsing az aks list: %w", err))
		return
	}

	found := make([]Observed, 0, len(list))
	for _, a := range list {
		version := a.CurrentKubernetesVersion // what is running, not what was requested
		if version == "" {
			version = a.KubernetesVersion
		}
		o := Observed{
			Cluster: inventory.Cluster{
				Name: a.Name, Cloud: inventory.Azure, Region: a.Location, Version: version,
				Subscription: sub.ID, ResourceGroup: a.ResourceGroup,
			},
			ID: a.ID, Status: a.ProvisioningState, Tags: a.Tags,
		}
		s.meta(&o.Cluster, o.Tags)
		found = append(found, o)
	}
	s.ok(Scope{Cloud: inventory.Azure, Subscription: sub.ID, SubscriptionName: sub.Name}, found)
}
