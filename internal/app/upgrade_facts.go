package app

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"nedctl/internal/config"
	"nedctl/internal/execx"
)

// eksFacts is what upgrade-check learns about an EKS cluster from the EKS
// and EC2 APIs — no load on the cluster itself. It is part of the JSON
// report, so a reviewer (or an agent) sees the evidence behind each
// finding. Errors records what could not be read: those checks are
// "not assessed", never a pass.
type eksFacts struct {
	Cluster         string               `json:"cluster"`
	Region          string               `json:"region"`
	Profile         string               `json:"profile"`
	Version         string               `json:"version"`
	PlatformVersion string               `json:"platformVersion,omitempty"`
	Status          string               `json:"status"`
	SupportType     string               `json:"upgradePolicySupportType,omitempty"`
	AuthMode        string               `json:"authenticationMode,omitempty"`
	AutoMode        bool                 `json:"autoMode,omitempty"`
	HealthIssues    []string             `json:"healthIssues,omitempty"`
	SubnetIDs       []string             `json:"subnetIds,omitempty"`
	Versions        []eksVersionInfo     `json:"availableVersions,omitempty"`
	Insights        []eksInsight         `json:"insights,omitempty"`
	Nodegroups      []eksNodegroup       `json:"nodegroups,omitempty"`
	Addons          []eksAddon           `json:"addons,omitempty"`
	AddonVersions   map[string]addonSets `json:"addonVersions,omitempty"` // Kubernetes version → add-on → builds
	Subnets         []eksSubnet          `json:"subnets,omitempty"`
	Fargate         []string             `json:"fargateProfiles,omitempty"`
	Errors          map[string]string    `json:"errors,omitempty"`
}

type eksVersionInfo struct {
	Version     string `json:"version"`
	Status      string `json:"status"`
	StandardEnd string `json:"standardSupportEnds,omitempty"`
	ExtendedEnd string `json:"extendedSupportEnds,omitempty"`
}

type eksInsight struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Category    string          `json:"category"`
	Version     string          `json:"kubernetesVersion,omitempty"`
	Status      string          `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	Recommend   string          `json:"recommendation,omitempty"`
	Resources   []string        `json:"resources,omitempty"`
	Deprecation []eksDeprecated `json:"deprecations,omitempty"`
}

type eksDeprecated struct {
	Usage        string   `json:"usage"`
	ReplacedWith string   `json:"replacedWith,omitempty"`
	StopServing  string   `json:"stopServingVersion,omitempty"`
	Clients      []string `json:"clients,omitempty"` // user agent (requests in the last 30 days)
}

type eksNodegroup struct {
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	ReleaseVersion string   `json:"releaseVersion,omitempty"`
	AMIType        string   `json:"amiType"`
	Status         string   `json:"status"`
	CapacityType   string   `json:"capacityType,omitempty"`
	InstanceTypes  []string `json:"instanceTypes,omitempty"`
	Desired        int      `json:"desired"`
	MaxUnavailable string   `json:"maxUnavailable,omitempty"`
	UpdateStrategy string   `json:"updateStrategy,omitempty"`
	LaunchTemplate string   `json:"launchTemplate,omitempty"`
	HealthIssues   []string `json:"healthIssues,omitempty"`
}

type eksAddon struct {
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Status       string   `json:"status"`
	HealthIssues []string `json:"healthIssues,omitempty"`
}

// addonSets is, per add-on, the builds compatible with one Kubernetes
// version and the default among them.
type addonSets map[string]addonBuilds

type addonBuilds struct {
	Versions []string `json:"versions"`
	Default  string   `json:"default,omitempty"`
}

type eksSubnet struct {
	ID        string `json:"id"`
	Zone      string `json:"zone"`
	CIDR      string `json:"cidr"`
	Available int    `json:"availableIps"`
}

// awsJSON runs a read-only aws CLI call and decodes its JSON.
type awsJSON func(ctx context.Context, v any, args ...string) error

func awsCaller(cfg config.Config, profile, region string) awsJSON {
	return func(ctx context.Context, v any, args ...string) error {
		args = append(args, "--profile", profile, "--region", region, "--output", "json")
		out, err := execx.Output(ctx, cfg.Timeout(), "aws", args...)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(out, v); err != nil {
			return fmt.Errorf("parsing aws %s: %w", strings.Join(args[:2], " "), err)
		}
		return nil
	}
}

// gatherEKSFacts reads the cluster, its versions, insights, node groups,
// add-ons, compatible add-on builds (for the current and target versions)
// and subnets. Independent reads run a few at a time.
var gatherEKSFacts = func(ctx context.Context, cfg config.Config, profile, region, cluster, target string) eksFacts {
	call := awsCaller(cfg, profile, region)
	f := eksFacts{Cluster: cluster, Region: region, Profile: profile, Errors: map[string]string{}, AddonVersions: map[string]addonSets{}}
	var mu sync.Mutex
	fail := func(what string, err error) {
		mu.Lock()
		f.Errors[what] = err.Error()
		mu.Unlock()
	}

	var dc struct {
		Cluster struct {
			Version, PlatformVersion, Status string
			UpgradePolicy                    struct{ SupportType string }
			AccessConfig                     struct{ AuthenticationMode string }
			ComputeConfig                    *struct{ Enabled bool }
			ResourcesVpcConfig               struct{ SubnetIds []string }
			Health                           struct {
				Issues []struct{ Code, Message string }
			}
		}
	}
	if err := call(ctx, &dc, "eks", "describe-cluster", "--name", cluster); err != nil {
		fail("cluster", err)
		return f
	}
	c := dc.Cluster
	f.Version, f.PlatformVersion, f.Status = c.Version, c.PlatformVersion, c.Status
	f.SupportType, f.AuthMode, f.SubnetIDs = c.UpgradePolicy.SupportType, c.AccessConfig.AuthenticationMode, c.ResourcesVpcConfig.SubnetIds
	f.AutoMode = c.ComputeConfig != nil && c.ComputeConfig.Enabled
	for _, i := range c.Health.Issues {
		f.HealthIssues = append(f.HealthIssues, i.Code+": "+i.Message)
	}
	if target == "" {
		target = nextMinor(f.Version)
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	goRead := func(fn func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn()
		}()
	}
	goRead(func() {
		var v struct {
			ClusterVersions []struct {
				ClusterVersion, Status, VersionStatus string
				EndOfStandardSupportDate              json.RawMessage
				EndOfExtendedSupportDate              json.RawMessage
			}
		}
		if err := call(ctx, &v, "eks", "describe-cluster-versions"); err != nil {
			fail("versions", err)
			return
		}
		var out []eksVersionInfo
		for _, x := range v.ClusterVersions {
			std, _ := awsDate(x.EndOfStandardSupportDate)
			ext, _ := awsDate(x.EndOfExtendedSupportDate)
			out = append(out, eksVersionInfo{Version: x.ClusterVersion, Status: firstNonBlank(x.VersionStatus, x.Status), StandardEnd: std, ExtendedEnd: ext})
		}
		sort.Slice(out, func(i, j int) bool { return minorOf(out[i].Version) < minorOf(out[j].Version) })
		mu.Lock()
		f.Versions = out
		mu.Unlock()
	})
	goRead(func() {
		var v struct {
			Insights []struct {
				ID, Name, Category, KubernetesVersion string
				InsightStatus                         struct{ Status, Reason string }
			}
		}
		if err := call(ctx, &v, "eks", "list-insights", "--cluster-name", cluster); err != nil {
			fail("insights", err)
			return
		}
		var out []eksInsight
		for _, x := range v.Insights {
			in := eksInsight{ID: x.ID, Name: x.Name, Category: x.Category, Version: x.KubernetesVersion, Status: x.InsightStatus.Status, Reason: x.InsightStatus.Reason}
			if in.Status != "PASSING" {
				describeInsight(ctx, call, cluster, &in)
			}
			out = append(out, in)
		}
		mu.Lock()
		f.Insights = out
		mu.Unlock()
	})
	goRead(func() {
		var v struct{ Nodegroups []string }
		if err := call(ctx, &v, "eks", "list-nodegroups", "--cluster-name", cluster); err != nil {
			fail("nodegroups", err)
			return
		}
		var out []eksNodegroup
		for _, name := range v.Nodegroups {
			var d struct {
				Nodegroup struct {
					NodegroupName, Version, ReleaseVersion, AmiType, Status, CapacityType string
					InstanceTypes                                                         []string
					ScalingConfig                                                         struct{ DesiredSize int }
					UpdateConfig                                                          struct {
						MaxUnavailable, MaxUnavailablePercentage int
						UpdateStrategy                           string
					}
					LaunchTemplate *struct{ Name, ID, Version string }
					Health         struct {
						Issues []struct{ Code, Message string }
					}
				}
			}
			if err := call(ctx, &d, "eks", "describe-nodegroup", "--cluster-name", cluster, "--nodegroup-name", name); err != nil {
				fail("nodegroup "+name, err)
				continue
			}
			n := d.Nodegroup
			ng := eksNodegroup{Name: n.NodegroupName, Version: n.Version, ReleaseVersion: n.ReleaseVersion, AMIType: n.AmiType, Status: n.Status,
				CapacityType: n.CapacityType, InstanceTypes: n.InstanceTypes, Desired: n.ScalingConfig.DesiredSize, UpdateStrategy: n.UpdateConfig.UpdateStrategy}
			switch {
			case n.UpdateConfig.MaxUnavailable > 0:
				ng.MaxUnavailable = fmt.Sprint(n.UpdateConfig.MaxUnavailable)
			case n.UpdateConfig.MaxUnavailablePercentage > 0:
				ng.MaxUnavailable = fmt.Sprintf("%d%%", n.UpdateConfig.MaxUnavailablePercentage)
			}
			if n.LaunchTemplate != nil {
				ng.LaunchTemplate = firstNonBlank(n.LaunchTemplate.Name, n.LaunchTemplate.ID) + ifNonBlank(":", n.LaunchTemplate.Version)
			}
			for _, i := range n.Health.Issues {
				ng.HealthIssues = append(ng.HealthIssues, i.Code+": "+i.Message)
			}
			out = append(out, ng)
		}
		mu.Lock()
		f.Nodegroups = out
		mu.Unlock()
	})
	goRead(func() {
		var v struct{ Addons []string }
		if err := call(ctx, &v, "eks", "list-addons", "--cluster-name", cluster); err != nil {
			fail("addons", err)
			return
		}
		var out []eksAddon
		for _, name := range v.Addons {
			var d struct {
				Addon struct {
					AddonName, AddonVersion, Status string
					Health                          struct {
						Issues []struct{ Code, Message string }
					}
				}
			}
			if err := call(ctx, &d, "eks", "describe-addon", "--cluster-name", cluster, "--addon-name", name); err != nil {
				fail("addon "+name, err)
				continue
			}
			a := eksAddon{Name: d.Addon.AddonName, Version: d.Addon.AddonVersion, Status: d.Addon.Status}
			for _, i := range d.Addon.Health.Issues {
				a.HealthIssues = append(a.HealthIssues, i.Code+": "+i.Message)
			}
			out = append(out, a)
		}
		mu.Lock()
		f.Addons = out
		mu.Unlock()
	})
	for _, kv := range []string{f.Version, target} {
		goRead(func() {
			var v struct {
				Addons []struct {
					AddonName     string
					AddonVersions []struct {
						AddonVersion    string
						Compatibilities []struct {
							ClusterVersion string
							DefaultVersion bool
						}
					}
				}
			}
			if err := call(ctx, &v, "eks", "describe-addon-versions", "--kubernetes-version", kv); err != nil {
				fail("addon versions for "+kv, err)
				return
			}
			sets := addonSets{}
			for _, a := range v.Addons {
				b := addonBuilds{}
				for _, av := range a.AddonVersions {
					for _, cv := range av.Compatibilities {
						if cv.ClusterVersion != kv {
							continue
						}
						b.Versions = append(b.Versions, av.AddonVersion)
						if cv.DefaultVersion {
							b.Default = av.AddonVersion
						}
					}
				}
				sets[a.AddonName] = b
			}
			mu.Lock()
			f.AddonVersions[kv] = sets
			mu.Unlock()
		})
	}
	if len(f.SubnetIDs) > 0 {
		goRead(func() {
			var v struct {
				Subnets []struct {
					SubnetId, AvailabilityZone, CidrBlock string
					AvailableIpAddressCount               int
				}
			}
			if err := call(ctx, &v, append([]string{"ec2", "describe-subnets", "--subnet-ids"}, f.SubnetIDs...)...); err != nil {
				fail("subnets", err)
				return
			}
			var out []eksSubnet
			for _, s := range v.Subnets {
				out = append(out, eksSubnet{ID: s.SubnetId, Zone: s.AvailabilityZone, CIDR: s.CidrBlock, Available: s.AvailableIpAddressCount})
			}
			mu.Lock()
			f.Subnets = out
			mu.Unlock()
		})
	}
	goRead(func() {
		var v struct{ FargateProfileNames []string }
		if err := call(ctx, &v, "eks", "list-fargate-profiles", "--cluster-name", cluster); err == nil {
			mu.Lock()
			f.Fargate = v.FargateProfileNames
			mu.Unlock()
		}
	})
	wg.Wait()
	return f
}

// describeInsight adds an insight's recommendation, affected resources
// and, for deprecated APIs, which clients still call them.
func describeInsight(ctx context.Context, call awsJSON, cluster string, in *eksInsight) {
	var v struct {
		Insight struct {
			Recommendation string
			Resources      []struct {
				KubernetesResourceURI string `json:"kubernetesResourceUri"`
				Arn                   string
			}
			CategorySpecificSummary struct {
				DeprecationDetails []struct {
					Usage, ReplacedWith, StopServingVersion string
					ClientStats                             []struct {
						UserAgent                  string
						NumberOfRequestsLast30Days int
					}
				}
			}
		}
	}
	if err := call(ctx, &v, "eks", "describe-insight", "--cluster-name", cluster, "--id", in.ID); err != nil {
		in.Reason = firstNonBlank(in.Reason, "details not read: "+err.Error())
		return
	}
	in.Recommend = v.Insight.Recommendation
	for _, r := range v.Insight.Resources {
		in.Resources = append(in.Resources, firstNonBlank(r.KubernetesResourceURI, r.Arn))
	}
	for _, d := range v.Insight.CategorySpecificSummary.DeprecationDetails {
		dd := eksDeprecated{Usage: d.Usage, ReplacedWith: d.ReplacedWith, StopServing: d.StopServingVersion}
		for _, c := range d.ClientStats {
			dd.Clients = append(dd.Clients, fmt.Sprintf("%s (%d)", c.UserAgent, c.NumberOfRequestsLast30Days))
		}
		in.Deprecation = append(in.Deprecation, dd)
	}
}
