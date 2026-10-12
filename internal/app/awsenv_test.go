package app

import (
	"strings"
	"testing"

	"nedctl/internal/awssso"
	"nedctl/internal/config"
)

func TestChooseEnvAssignmentFollowsSquadAndRole(t *testing.T) {
	cfg := config.Config{AWS: config.AWS{ElevatedRolePattern: "(?i)admin"}}
	ch := func(id, squad, env, role string) awsChoice {
		return awsChoice{Assignment: awssso.Assignment{AccountID: id, AccountName: squad + "-" + env, Role: role}, Squad: squad, Environment: env}
	}
	choices := []awsChoice{
		ch("1", "lms", "qa", "Admin"), ch("1", "lms", "qa", "ReadOnly"),
		ch("2", "lms", "ete", "Admin"),
		ch("3", "pay", "qa", "ReadOnly"),
		ch("4", "lms", "dev", "DevOps"), ch("4", "lms", "dev", "ReadOnly"),
	}
	cur := profileContext{Name: "p", Squad: "lms", Role: "DevOps", Environment: "dev"}
	c, err := chooseEnvAssignment(cfg, choices, cur, "qa")
	if err != nil || c.AccountID != "1" || c.Role != "ReadOnly" {
		t.Fatalf("qa: %+v %v — the same squad, and not an elevated role", c, err)
	}
	cur.Role = "Admin"
	if c, err := chooseEnvAssignment(cfg, choices, cur, "qa"); err != nil || c.Role != "Admin" {
		t.Fatalf("the same role where you hold it: %+v %v", c, err)
	}
	cur.Role = "DevOps"
	if _, err := chooseEnvAssignment(cfg, choices, cur, "ete"); err == nil || !strings.Contains(err.Error(), "elevated") {
		t.Fatalf("only an elevated role there must not be taken silently: %v", err)
	}
	if _, err := chooseEnvAssignment(cfg, choices, cur, "prod"); err == nil || !strings.Contains(err.Error(), "no role in a PROD account of squad lms") {
		t.Fatalf("prod: %v", err)
	}
}

func TestHealthWithAnAppNameExplainsItself(t *testing.T) {
	code, _, errb := run("health", "kiali", "--aws", "--match", "lms")
	if code != ExitUsage || !strings.Contains(errb, "not one app") || !strings.Contains(errb, "nedctl app kiali") {
		t.Fatalf("code=%d err=%q", code, errb)
	}
}
