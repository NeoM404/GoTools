package inventory

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validFleet() Fleet {
	return Fleet{Clusters: []Cluster{
		{Name: "eks-prod", Cloud: AWS, Environment: "prod", Region: "eu-west-1", Account: "111111111111", Version: "1.30"},
		{Name: "aks-uat", Cloud: Azure, Environment: "uat", Subscription: "sub", ResourceGroup: "rg", Version: "1.29.4"},
	}}
}

func problems(t *testing.T, err error) []string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want *ValidationError, got %v", err)
	}
	return ve.Problems
}

func TestValidateAcceptsGoodFleet(t *testing.T) {
	if err := validFleet().Validate([]string{"dev", "sit", "uat", "prod"}); err != nil {
		t.Fatal(err)
	}
}

func TestValidateDuplicateNameCaseInsensitive(t *testing.T) {
	f := validFleet()
	dup := f.Clusters[0]
	dup.Name, dup.Environment = "EKS-PROD", "dev"
	f.Clusters = append(f.Clusters, dup)
	p := problems(t, f.Validate(nil))
	if len(p) != 1 || !strings.Contains(p[0], "duplicate of cluster #1") {
		t.Fatalf("got %q", p)
	}
}

func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	f := Fleet{Clusters: []Cluster{
		{Name: "", Cloud: Azure},                     // empty name, no sub, no rg
		{Name: "a", Cloud: "gcp"},                    // unknown cloud
		{Name: "b", Cloud: AWS, Account: "12345"},    // no region, bad account
		{Name: "c", Cloud: AWS, Region: "eu-west-1"}, // no account
		{Name: "d", Cloud: "", Version: "latest"},    // empty cloud, bad version
		{Name: "e", Cloud: Azure, Subscription: "s", ResourceGroup: "r", Environment: "prd"}, // not allowed
	}}
	p := problems(t, f.Validate([]string{"dev", "sit", "uat", "prod"}))
	want := []string{
		"#1: name is empty", "no subscription", "no resourceGroup",
		`unknown cloud "gcp"`, "has no region", `"12345" is not a 12-digit`,
		"has no account", "cloud is empty", `version "latest"`, `environment "prd" is not one of`,
	}
	joined := strings.Join(p, "\n")
	for _, w := range want {
		if !strings.Contains(joined, w) {
			t.Errorf("missing problem %q in:\n%s", w, joined)
		}
	}
}

func TestValidateEnvironmentsOptionalAndCaseInsensitive(t *testing.T) {
	f := validFleet()
	f.Clusters[0].Environment = "anything"
	if err := f.Validate(nil); err != nil {
		t.Fatalf("no allow-list configured: %v", err)
	}
	f.Clusters[0].Environment = "PROD"
	if err := f.Validate([]string{"dev", "uat", "prod"}); err != nil {
		t.Fatalf("allow-list should be case-insensitive: %v", err)
	}
}

func TestValidationErrorMessage(t *testing.T) {
	e := &ValidationError{Problems: []string{"x"}}
	if got := e.Error(); !strings.Contains(got, "(1 problem)") {
		t.Fatalf("singular: %q", got)
	}
	e.Problems = append(e.Problems, "y")
	if got := e.Error(); !strings.Contains(got, "(2 problems)") || !strings.Contains(got, "\n  - y") {
		t.Fatalf("plural/format: %q", got)
	}
}

func TestLoadFileRejectsOversizedInventory(t *testing.T) {
	path := filepath.Join(t.TempDir(), "huge.json")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(MaxInventoryBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := LoadFile(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size error, got %v", err)
	}
}

func TestExampleFleetIsValid(t *testing.T) {
	f, err := LoadFile("../../configs/fleet.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate([]string{"dev", "sit", "uat", "prod"}); err != nil {
		t.Fatalf("the shipped example must pass validation: %v", err)
	}
}
