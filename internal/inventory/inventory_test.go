package inventory

import "testing"

func sampleFleet() Fleet {
	return Fleet{Clusters: []Cluster{
		{Name: "eks-prod", Cloud: AWS, Environment: "prod", Version: "1.30", Owner: "payments"},
		{Name: "eks-np", Cloud: AWS, Environment: "nonprod", Version: "1.29", Owner: "payments"},
		{Name: "aks-old", Cloud: Azure, Environment: "sandbox", Version: "1.27", Owner: "data"},
	}}
}

func TestFindCaseInsensitive(t *testing.T) {
	f := sampleFleet()
	c, err := f.Find("EKS-PROD")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.Name != "eks-prod" {
		t.Fatalf("got %q", c.Name)
	}
	if _, err := f.Find("nope"); err == nil {
		t.Fatal("expected error for missing cluster")
	}
}

func TestFilter(t *testing.T) {
	f := sampleFleet()
	if got := f.Filter("aws", "", ""); len(got) != 2 {
		t.Fatalf("cloud filter: got %d", len(got))
	}
	if got := f.Filter("", "prod", ""); len(got) != 1 {
		t.Fatalf("env filter: got %d", len(got))
	}
	if got := f.Filter("", "", "PAY"); len(got) != 2 {
		t.Fatalf("owner substring filter: got %d", len(got))
	}
	if got := f.Filter("azure", "prod", ""); len(got) != 0 {
		t.Fatalf("combined filter should be empty, got %d", len(got))
	}
}

func TestFilterSorted(t *testing.T) {
	f := sampleFleet()
	got := f.Filter("", "", "")
	// aws before azure, then by name
	if got[0].Cloud != AWS || got[len(got)-1].Cloud != Azure {
		t.Fatalf("not sorted by cloud: %+v", got)
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		cluster, target string
		want            DriftStatus
	}{
		{"1.30", "1.30", StatusCurrent},
		{"1.31", "1.30", StatusCurrent}, // ahead
		{"1.29", "1.30", StatusN1},
		{"1.28", "1.30", StatusStale},
		{"1.27", "1.30", StatusStale},
		{"v1.29.4", "1.30", StatusN1},
		{"", "1.30", StatusUnknown},
		{"garbage", "1.30", StatusUnknown},
	}
	for _, c := range cases {
		if got := Classify(c.cluster, c.target); got != c.want {
			t.Errorf("Classify(%q,%q)=%q want %q", c.cluster, c.target, got, c.want)
		}
	}
}

func TestLoadURLRejectsHTTP(t *testing.T) {
	if _, err := LoadURL("http://insecure.example/fleet.json"); err == nil {
		t.Fatal("expected LoadURL to reject non-https")
	}
}
