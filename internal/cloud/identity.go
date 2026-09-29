package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/NeoM404/GoTools/internal/execx"
	"github.com/NeoM404/GoTools/internal/inventory"
)

// Identity is who the cloud CLI is acting as for a credential fetch.
type Identity struct {
	Principal string `json:"principal"` // AWS caller ARN, or Azure user/service principal
	Account   string `json:"account,omitempty"`
	// Subscription is the resolved Azure subscription ID.
	Subscription string `json:"subscription,omitempty"`
}

// ErrWrongAccount reports active AWS credentials for a different account
// than the cluster's.
type ErrWrongAccount struct {
	Cluster, Want, Got, Principal string
}

func (e *ErrWrongAccount) Error() string {
	return fmt.Sprintf("active AWS credentials are for account %s (%s), but %s is in account %s — "+
		"select the right profile (e.g. AWS_PROFILE=...) and retry", e.Got, e.Principal, e.Cluster, e.Want)
}

// VerifyIdentity confirms the CLI will act in the cluster's own account or
// subscription BEFORE credentials are fetched.
//
// This matters most on AWS: `aws eks update-kubeconfig` uses whatever
// account the active credentials belong to. If that account has a cluster
// with the same name, the result is credentials for the wrong cluster,
// labelled as the right one. Azure calls always pass --subscription, so the
// check there confirms the subscription is reachable and records who is
// acting.
func VerifyIdentity(ctx context.Context, c inventory.Cluster, timeout time.Duration) (Identity, error) {
	switch c.Cloud {
	case inventory.AWS:
		out, err := execx.Output(ctx, timeout, "aws", "sts", "get-caller-identity", "--output", "json")
		if err != nil {
			return Identity{}, fmt.Errorf("checking AWS identity: %w", err)
		}
		var id struct{ Account, Arn string }
		if err := json.Unmarshal(out, &id); err != nil || id.Account == "" {
			return Identity{}, fmt.Errorf("parsing aws sts get-caller-identity: %v", err)
		}
		if id.Account != c.Account {
			return Identity{}, &ErrWrongAccount{Cluster: c.Name, Want: c.Account, Got: id.Account, Principal: id.Arn}
		}
		return Identity{Principal: id.Arn, Account: id.Account}, nil
	case inventory.Azure:
		out, err := execx.Output(ctx, timeout, "az", "account", "show", "--subscription", c.Subscription, "--output", "json", "--only-show-errors")
		if err != nil {
			return Identity{}, fmt.Errorf("checking Azure access to subscription %s: %w", c.Subscription, err)
		}
		var acct struct {
			ID, Name string
			User     struct{ Name, Type string }
		}
		if err := json.Unmarshal(out, &acct); err != nil || acct.ID == "" {
			return Identity{}, fmt.Errorf("parsing az account show: %v", err)
		}
		if !strings.EqualFold(acct.ID, c.Subscription) && !strings.EqualFold(acct.Name, c.Subscription) {
			return Identity{}, fmt.Errorf("az resolved subscription %q to %s (%s), which does not match the inventory", c.Subscription, acct.Name, acct.ID)
		}
		return Identity{Principal: acct.User.Name, Subscription: acct.ID}, nil
	default:
		return Identity{}, fmt.Errorf("unsupported cloud %q", c.Cloud)
	}
}
