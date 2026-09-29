// Package inventory models the fleet of Kubernetes clusters and loads it from
// a local JSON file or an HTTPS endpoint. This is the org-specific glue that
// no off-the-shelf tool provides: one view of every EKS/AKS/OpenShift cluster
// with its owner, environment, version and cost centre.
package inventory

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"
)

// Cloud identifies the platform hosting a cluster.
type Cloud string

const (
	AWS   Cloud = "aws"
	Azure Cloud = "azure"
)

// Cluster is one entry in the fleet inventory.
type Cluster struct {
	Name        string `json:"name"`
	Cloud       Cloud  `json:"cloud"`
	Environment string `json:"environment"` // e.g. dev | sit | uat | prod (see config "environments")
	Region      string `json:"region"`
	Version     string `json:"version"` // e.g. "1.29"
	Owner       string `json:"owner"`
	CostCentre  string `json:"costCentre"`

	// AWS-specific
	Account string `json:"account,omitempty"`

	// Azure-specific
	Subscription  string `json:"subscription,omitempty"`
	ResourceGroup string `json:"resourceGroup,omitempty"`
}

// Fleet is the top-level inventory document.
type Fleet struct {
	Clusters []Cluster `json:"clusters"`
}

// Find returns the cluster with the given name (case-insensitive) or an error.
func (f Fleet) Find(name string) (Cluster, error) {
	for _, c := range f.Clusters {
		if strings.EqualFold(c.Name, name) {
			return c, nil
		}
	}
	return Cluster{}, fmt.Errorf("cluster %q not found in inventory", name)
}

// Filter returns clusters matching all non-empty criteria.
func (f Fleet) Filter(cloud, env, owner string) []Cluster {
	var out []Cluster
	for _, c := range f.Clusters {
		if cloud != "" && !strings.EqualFold(string(c.Cloud), cloud) {
			continue
		}
		if env != "" && !strings.EqualFold(c.Environment, env) {
			continue
		}
		if owner != "" && !strings.Contains(strings.ToLower(c.Owner), strings.ToLower(owner)) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cloud != out[j].Cloud {
			return out[i].Cloud < out[j].Cloud
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// MaxInventoryBytes caps an inventory document. A fleet of thousands of
// clusters is well under 1 MiB; the cap stops a wrong URL or a runaway file
// from exhausting memory.
const MaxInventoryBytes = 32 << 20

// LoadFile reads a fleet inventory from a local JSON file.
func LoadFile(path string) (Fleet, error) {
	f, err := os.Open(path)
	if err != nil {
		return Fleet{}, fmt.Errorf("reading inventory %s: %w", path, err)
	}
	defer f.Close()
	data, err := readCapped(f)
	if err != nil {
		return Fleet{}, fmt.Errorf("reading inventory %s: %w", path, err)
	}
	return parse(data)
}

// readCapped reads r fully, failing if it exceeds MaxInventoryBytes.
func readCapped(r io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInventoryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxInventoryBytes {
		return nil, fmt.Errorf("inventory exceeds %d MiB", MaxInventoryBytes>>20)
	}
	return data, nil
}

// LoadURL fetches a fleet inventory over HTTPS. Plain HTTP is refused — this
// tool drives access to production clusters and must not trust cleartext.
func LoadURL(raw string) (Fleet, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Fleet{}, fmt.Errorf("invalid inventory URL: %w", err)
	}
	if u.Scheme != "https" {
		return Fleet{}, fmt.Errorf("inventory URL must be https, got %q", u.Scheme)
	}
	client := &http.Client{
		Timeout:   15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}},
		// Refuse any redirect that downgrades to plain HTTP — a redirect must
		// not defeat the https-only guarantee.
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing redirect to non-https URL %q", req.URL.String())
			}
			return nil
		},
	}
	return loadURLWithClient(raw, client)
}

// loadURLWithClient performs the fetch with an injected client (for tests).
// The scheme check in LoadURL still applies to the initial URL.
func loadURLWithClient(raw string, client *http.Client) (Fleet, error) {
	resp, err := client.Get(raw)
	if err != nil {
		return Fleet{}, fmt.Errorf("fetching inventory: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Fleet{}, fmt.Errorf("inventory endpoint returned %s", resp.Status)
	}
	data, err := readCapped(resp.Body)
	if err != nil {
		return Fleet{}, fmt.Errorf("reading inventory response: %w", err)
	}
	return parse(data)
}

func marshal(f Fleet) ([]byte, error) { return json.MarshalIndent(f, "", "  ") }

func parse(data []byte) (Fleet, error) {
	var f Fleet
	if err := json.Unmarshal(data, &f); err != nil {
		return Fleet{}, fmt.Errorf("parsing inventory JSON: %w", err)
	}
	return f, nil
}
