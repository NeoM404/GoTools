package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func accessFixture(t *testing.T, approved string) *clusterFixture {
	dir := t.TempDir()
	extra := ""
	if approved != "" {
		p := filepath.Join(dir, "approved.json")
		os.WriteFile(p, []byte(approved), 0o600)
		extra = `,"security":{"approvedAccess":` + quote(p) + `}`
	}
	f := newClusterFixture(t, extra, "pay-k8s-qa-cluster")
	c := "pay-k8s-qa-cluster"
	f.answer(t, c, strings.Join(accessProbes[0], " "),
		"cluster-admin\tcluster-admin\tGroup::system:masters \n"+
			"platform\tcluster-admin\tGroup::platform-admins User::alice@bank.example \n"+
			"argocd\tcluster-admin\tServiceAccount:argocd:argocd-application-controller \n"+
			"system:kube-proxy\tsystem:node-proxier\tUser::system:kube-proxy \n"+
			"kube-system-admin\tcluster-admin\tServiceAccount:kube-system:addon-manager \n")
	f.answer(t, c, strings.Join(accessProbes[1], " "),
		"pay\tdevs\tedit\tGroup::pay-developers ServiceAccount::ci \n"+
			"pay\tviewers\tview\tGroup::pay-readers \n")
	return f
}

const approvedJSON = `{"rules":[
 {"subject":"Group:platform-admins","roles":["cluster-admin"]},
 {"subject":"Group:system:masters","roles":["cluster-admin"],"note":"AKS/EKS built-in"},
 {"subject":"ServiceAccount:argocd/argocd-application-controller","roles":["*"]},
 {"subject":"Group:.*-developers","roles":["edit"],"clusters":".*-qa-.*"},
 {"subject":"Group:old-team","roles":["admin"]}]}`

func TestAccessReviewAgainstTheApprovedList(t *testing.T) {
	f := accessFixture(t, approvedJSON)
	code, out, errb := run("--config", f.cfg, "access", "review", "--env", "qa")
	if code != ExitFailure {
		t.Fatalf("code=%d err=%q", code, errb)
	}
	for _, want := range [][]string{
		{"pay-k8s-qa-cluster", "User:alice@bank.example", "cluster-admin", "cluster-wide", "unapproved"},
		{"pay-k8s-qa-cluster", "ServiceAccount:pay/ci", "edit", "namespace:pay", "unapproved"},
		{"pay-k8s-qa-cluster", "Group:pay-developers", "edit", "namespace:pay", "approved"},
		{"pay-k8s-qa-cluster", "Group:system:masters", "cluster-admin", "cluster-wide", "approved"},
	} {
		if !regexpLine(out, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, not := range []string{"pay-readers", "kube-proxy", "addon-manager"} {
		if strings.Contains(out, not) {
			t.Errorf("%s should not be reviewed", not)
		}
	}
	if !strings.Contains(out, "2 grant(s) not on the approved list") || !strings.Contains(out, "approval no longer used: Group:old-team → admin") ||
		!strings.Contains(out, "clusterUser") {
		t.Error("summary")
	}
	if t.Failed() {
		t.Log(out)
	}
	_, out, _ = run("--config", f.cfg, "access", "review", "--env", "qa", "-o", "json")
	if !strings.Contains(out, `"unapproved": 2`) || !strings.Contains(out, `"subject": "Group:old-team"`) {
		t.Fatalf("json: %s", out)
	}
}

func TestAccessReviewWithoutAListShowsEverything(t *testing.T) {
	f := accessFixture(t, "")
	code, out, _ := run("--config", f.cfg, "access", "review", "--cluster", "pay-k8s-qa-cluster", "--roles", "*")
	if code != ExitOK || !strings.Contains(out, "no approved list") || !strings.Contains(out, "Group:pay-readers") {
		t.Fatalf("code=%d out=%s", code, out)
	}
	code, _, errb := run("--config", f.cfg, "access", "review", "--env", "qa", "--approved", "/nope.json")
	if code != ExitFailure || !strings.Contains(errb, "/nope.json") {
		t.Fatalf("a named file that is missing must fail: %d %s", code, errb)
	}
}

func TestRepositoryApprovedAccessIsValid(t *testing.T) {
	if _, err := loadApproved("../../access/approved.json"); err != nil {
		t.Fatal(err)
	}
}
