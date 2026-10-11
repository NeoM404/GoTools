package app

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"

	"nedctl/internal/ui"
)

// cmdHelp is one command's entry in the help: the overview lists Use and
// Short by group; `nedctl help <cmd>` and `<cmd> --help` add Long, the
// examples and the command's own flags.
type cmdHelp struct {
	Name     string // "kube", "aws login"
	Use      string // arguments after the name
	Short    string
	Long     string
	Examples []string
}

type helpGroup struct {
	Title string
	Cmds  []cmdHelp
}

var helpGroups = []helpGroup{
	{"Everyday", []cmdHelp{
		{"aws login", "[WORDS…]", "Sign in and pick one account and role",
			"Signs in with IAM Identity Center (one browser approval a day), lists the accounts and roles you hold, and writes one AWS CLI profile. Words narrow the picker; one match goes straight in. With the shell integration, this terminal switches to the new profile.",
			[]string{"nedctl aws login", "nedctl aws login lms dev", "nedctl aws login --all --break-glass \"INC0012345 payments down\""}},
		{"kube", "[eks-cluster]", "A shell with kubectl on a cluster; exit closes the tunnel",
			"Opens a tunnel to the cluster (directly when the endpoint answers from here, else through the account's devops instance) and starts a shell with KUBECONFIG set and the cluster in the prompt. With no name, pick from the account's clusters, last used first.",
			[]string{"nedctl kube", "nedctl kube payments-eks-dev", "nedctl kube payments-eks-dev -- kubectl get pods -A"}},
		{"shell", "[FILTER…]", "Session Manager shell on an instance",
			"Lists the account's instances (coloured by environment, with their access level) and opens a Session Manager shell as your own identity. --tab opens it in a new Windows Terminal tab; --via legacy launches sm or SSMshell already signed in.",
			[]string{"nedctl shell", "nedctl shell devops", "nedctl shell devops --tab", "nedctl shell --via legacy"}},
		{"console", "[SERVICE]", "Open the AWS console as the same account and role",
			"Opens the AWS management console in your browser, signed in through IAM Identity Center as the account and role you act with. A service name opens straight on it.",
			[]string{"nedctl console", "nedctl console eks", "nedctl console --print"}},
		{"connect", "[eks-cluster]", "Hold a tunnel to a cluster for kubectl in other terminals",
			"Like kube, but holds the tunnel in this terminal (or a new tab with --tab) and prints the KUBECONFIG to export elsewhere.",
			[]string{"nedctl connect payments-eks-dev", "nedctl connect payments-eks-dev --tab"}},
		{"aws whoami", "", "Who you act as, where, and sign-in time left", "", []string{"nedctl aws whoami", "nedctl aws whoami -o json"}},
		{"status", "", "Your sign-in, current cluster and the commands you use most", "", []string{"nedctl status"}},
	}},
	{"Azure: AKS and machines over SSH", []cmdHelp{
		{"azure kube", "[cluster|words…]", "A shell on the AKS bastion with one cluster selected",
			"Connects to the environment's AKS bastion over SSH and starts a shell there in which kubectl, helm and kubectx use the cluster you chose, for this session only (other sessions are not switched). The prompt and the Windows Terminal tab take the environment's colour. Credentials stay on the bastion: nothing is copied to your machine. Words narrow the list; an environment word (dev, ete, qa, prod) picks the bastion.",
			[]string{"nedctl azure kube", "nedctl azure kube qa payments", "nedctl azure kube acm-k8s-qa-cluster", "nedctl azure kube acm-k8s-qa-cluster -- kubectl get pods -A", "nedctl azure kube payments prod --tab"}},
		{"azure shell", "[name|env]", "SSH to a bastion or Azure machine, coloured and recorded",
			"Opens SSH to an AKS bastion or a machine from azure.hosts, with the environment in the prompt and the tab. --plain leaves the remote prompt alone.",
			[]string{"nedctl azure shell qa", "nedctl azure shell", "nedctl azure shell ete --tab"}},
		{"azure clusters", "[env]", "The AKS clusters on each bastion", "Uses what nedctl remembers; --refresh asks the bastions again.", []string{"nedctl azure clusters", "nedctl azure clusters qa --refresh"}},
		{"azure hosts", "", "The bastions and machines azure shell reaches", "", []string{"nedctl azure hosts"}},
	}},
	{"Instances and clusters", []cmdHelp{
		{"ec2", "<start|stop> <instance>", "Start or stop an instance, recorded", "In production you confirm by typing the instance ID.", []string{"nedctl ec2 start payments-batch"}},
		{"clusters list", "", "The fleet's clusters, or the signed-in account's EKS clusters", "", []string{"nedctl clusters list", "nedctl clusters list --env prod -o json"}},
		{"clusters get", "<name>", "One cluster's details", "", nil},
		{"eks auth", "", "Each cluster's authentication mode and endpoint exposure", "Shows who still needs to move from CONFIG_MAP to access entries.", []string{"nedctl eks auth", "nedctl eks auth --all-profiles --fail-on-configmap"}},
		{"eks access", "<cluster>", "Who can reach a cluster through access entries", "", []string{"nedctl eks access payments-eks-prod"}},
		{"kubeconfig", "<cluster>", "Fetch credentials for an inventory cluster", "", nil},
		{"login", "<cluster>", "kubeconfig plus a production check; on a bastion, switch context", "", nil},
		{"guard", "", "Is the current kube-context production? (--block exits 3)", "", []string{"nedctl guard --block && kubectl apply -f deploy.yaml"}},
		{"current", "", "The current context, its cluster and environment", "", nil},
	}},
	{"Setup", []cmdHelp{
		{"setup", "", "First run: settings, install, prompt and tab colours, health check",
			"Every step asks first, is safe to repeat and never overwrites anything. Running a newer download's setup is also how you update.",
			[]string{"./nedctl-linux-amd64 setup", "nedctl setup --yes"}},
		{"doctor", "", "Check tools, config, proxy, CA bundle, portal and sign-in", "", []string{"nedctl doctor", "nedctl doctor --all", "nedctl doctor --offline -o json"}},
		{"prompt init", "<bash|zsh|powershell>", "Shell code for the prompt, tab colour, completion and login switching", "setup adds it to ~/.bashrc, ~/.zshrc or your PowerShell profile for you.", []string{`eval "$(nedctl prompt init bash)"`, "nedctl prompt init powershell | Out-String | Invoke-Expression"}},
		{"version", "", "This nedctl's version; --check looks for a newer release", "", []string{"nedctl version --check"}},
		{"init", "", "Write a starter config by hand", "", nil},
	}},
	{"Fleet and inventory", []cmdHelp{
		{"fleet versions", "", "Version drift against each environment's target", "", nil},
		{"fleet eol", "", "Support lifecycle and extended-support cost", "", nil},
		{"fleet calendar", "aws", "Generate the EKS support calendar", "", nil},
		{"inventory validate", "", "Check an inventory against the config", "", nil},
		{"inventory diff", "", "Shadow, missing and drifted clusters against the clouds", "", nil},
		{"inventory sync", "", "Write the inventory the clouds imply", "", nil},
		{"sweep", "", "Remove kube-contexts the inventory proves stale", "", nil},
	}},
	{"Audit and credentials", []cmdHelp{
		{"audit verify", "", "Check the audit log's hash chain", "", nil},
		{"evidence", "--period 2026-Q3", "Evidence pack of accesses, change records and exceptions", "", []string{"nedctl evidence --period 2026-Q3 --production"}},
		{"aws env", "", "Short-term keys for tools that need them", "", []string{`eval "$(nedctl aws env)"`}},
		{"prompt", "", "The coloured prompt segment (prompt init uses it)", "", nil},
	}},
}

// aliases are words people type for a command they mean.
var aliases = map[string]string{
	"whoami": "aws whoami", "signin": "aws login", "sign-in": "aws login", "ssh": "shell", "session": "shell",
	"tunnel": "connect", "kubectl": "kube", "k8s": "kube", "k": "kube", "env": "aws env", "home": "status", "update": "version --check",
	"aks": "azure kube", "az": "azure", "ssh-aks": "azure shell",
}

func findHelp(name string) (cmdHelp, bool) {
	for _, g := range helpGroups {
		for _, c := range g.Cmds {
			if c.Name == name {
				return c, true
			}
		}
	}
	return cmdHelp{}, false
}

func helpStyle(w io.Writer) ui.Style { return ui.Style{Color: colorOn(w)} }

// printUsage is the overview: commands by group, daily ones first.
func printUsage(w io.Writer) {
	s := helpStyle(w)
	fmt.Fprintf(w, "%s — secure access to AWS accounts, instances and Kubernetes clusters\n\n", s.Bold("nedctl"))
	fmt.Fprintf(w, "%s  nedctl [--config PATH] <command> [args]\n", s.Heading("Usage"))
	for _, g := range helpGroups {
		fmt.Fprintf(w, "\n%s\n", s.Heading(g.Title))
		for _, c := range g.Cmds {
			name := c.Name
			if c.Use != "" {
				name += " " + c.Use
			}
			fmt.Fprintf(w, "  %s  %s\n", ui.Pad(s.Bold(name), 28), c.Short)
		}
	}
	fmt.Fprintf(w, "\nRun %s for details, examples and flags.\n", s.Bold("nedctl help <command>"))
	fmt.Fprintln(w, s.Dim("Exit codes: 0 ok · 1 failed · 2 usage · 3 production (guard --block) · 130 interrupted"))
}

// wantsHelp reports -h/--help among a command's own arguments (before
// any `--`, after which arguments belong to another program).
func wantsHelp(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if a == "-h" || a == "--help" || a == "-help" {
			return true
		}
	}
	return false
}

// commandPath is the help entry a command line names: "aws login",
// "kube".
func commandPath(args []string) []string {
	if len(args) == 0 {
		return nil
	}
	if subs, ok := subcommands[args[0]]; ok && len(args) > 1 {
		for _, sub := range subs {
			if args[1] == sub {
				return args[:2]
			}
		}
	}
	return args[:1]
}

// printCommandHelp is `nedctl help <cmd>` and `nedctl <cmd> --help`.
func printCommandHelp(ctx context.Context, path []string, w io.Writer) int {
	name := strings.Join(path, " ")
	c, ok := findHelp(name)
	if !ok {
		if subs, has := subcommands[name]; has {
			s := helpStyle(w)
			fmt.Fprintf(w, "%s nedctl %s <%s>\n\n", s.Heading("Usage"), name, strings.Join(subs, "|"))
			for _, sub := range subs {
				if sc, ok := findHelp(name + " " + sub); ok {
					fmt.Fprintf(w, "  %s  %s\n", ui.Pad(s.Bold(name+" "+sub), 20), sc.Short)
				}
			}
			return ExitOK
		}
		return unknownCommand(name, w)
	}
	s := helpStyle(w)
	use := "nedctl " + c.Name
	if c.Use != "" {
		use += " " + c.Use
	}
	defs := flagDefs(ctx, path)
	if len(defs) > 0 {
		use += " [flags]"
	}
	fmt.Fprintf(w, "%s\n\n  %s\n", s.Bold(use), c.Short+".")
	if c.Long != "" {
		fmt.Fprintf(w, "\n%s\n", wrap(c.Long, 76, "  "))
	}
	if len(c.Examples) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Heading("Examples"))
		for _, e := range c.Examples {
			fmt.Fprintf(w, "  %s\n", s.Fg(ui.Blue, e))
		}
	}
	if len(defs) > 0 {
		fmt.Fprintf(w, "\n%s\n", s.Heading("Flags"))
		width := 0
		for _, d := range defs {
			if n := len(d.spelling()); n > width {
				width = n
			}
		}
		for _, d := range defs {
			fmt.Fprintf(w, "  %s  %s\n", ui.Pad(s.Bold(d.spelling()), width), d.usage)
		}
	}
	return ExitOK
}

// unknownCommand suggests what was probably meant.
func unknownCommand(cmd string, w io.Writer) int {
	s := helpStyle(w)
	fmt.Fprintf(w, "%s\n", s.Fail(fmt.Sprintf("unknown command %q", cmd)))
	if sug := suggest(cmd); len(sug) > 0 {
		fmt.Fprintf(w, "  did you mean: %s\n", s.Bold("nedctl "+strings.Join(sug, "  ·  nedctl ")))
	}
	fmt.Fprintf(w, "%s\n", s.Hint("nedctl help lists every command"))
	return ExitUsage
}

// suggest returns commands close to what was typed: aliases first, then
// names within two edits.
func suggest(typed string) []string {
	typed = strings.ToLower(typed)
	if a, ok := aliases[typed]; ok {
		return []string{a}
	}
	seen := map[string]bool{}
	var out []string
	for _, g := range helpGroups {
		for _, c := range g.Cmds {
			first := strings.Fields(c.Name)[0]
			for _, cand := range []string{c.Name, first} {
				if !seen[cand] && editDistance(typed, cand) <= 2 {
					seen[cand] = true
					out = append(out, cand)
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return editDistance(typed, out[i]) < editDistance(typed, out[j]) })
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}

func editDistance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur := make([]int, len(rb)+1)
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev = cur
	}
	return prev[len(rb)]
}

func wrap(text string, width int, indent string) string {
	var lines []string
	line := indent
	for _, word := range strings.Fields(text) {
		if len(line)+len(word)+1 > width && strings.TrimSpace(line) != "" {
			lines = append(lines, line)
			line = indent
		}
		if strings.TrimSpace(line) != "" {
			line += " "
		}
		line += word
	}
	return strings.Join(append(lines, line), "\n")
}

// flagDef is one flag as the command's flag set describes it.
type flagDef struct {
	name, kind, usage string
}

func (d flagDef) spelling() string {
	dash := "--"
	if len(d.name) == 1 {
		dash = "-"
	}
	if d.kind == "" {
		return dash + d.name
	}
	if p, ok := placeholders[d.name]; ok {
		return dash + d.name + " " + p
	}
	if fileFlags[d.name] {
		return dash + d.name + " PATH"
	}
	return dash + d.name + " " + strings.ToUpper(d.kind)
}

// placeholders name a flag's value better than its Go type does.
var placeholders = map[string]string{
	"profile": "NAME", "region": "REGION", "via": "MODE", "via-instance": "INSTANCE", "instance": "INSTANCE",
	"port": "PORT", "change-record": "CHG", "break-glass": "REASON", "o": "FORMAT", "output": "FORMAT",
	"format": "FORMAT", "account": "ACCOUNT", "role": "ROLE", "shell": "SHELL", "env": "ENV", "cloud": "CLOUD",
	"start-url": "URL", "sso-region": "REGION", "mode": "MODE", "context": "NAME", "owner": "NAME", "period": "QUARTER",
	"from": "DATE", "to": "DATE", "warn-days": "N",
}

// rawHelp makes `-h` reach the command's own flag set instead of the help
// page, so flagDefs can read the flags.
var rawHelp bool

var flagDefRe = regexp.MustCompile(`(?m)^  -([A-Za-z][\w-]*)(?: (\S+))?\n((?:    \t.*\n?)*)`)

// flagDefs reads a command's flags from its flag set's own -h output.
func flagDefs(ctx context.Context, path []string) []flagDef {
	var errb bytes.Buffer
	old := rawHelp
	rawHelp = true
	dispatch(ctx, append(append([]string{}, path...), "-h"), io.Discard, &errb)
	rawHelp = old
	var defs []flagDef
	for _, m := range flagDefRe.FindAllStringSubmatch(errb.String(), -1) {
		usage := strings.Join(strings.Fields(strings.ReplaceAll(m[3], "\t", " ")), " ")
		defs = append(defs, flagDef{m[1], m[2], usage})
	}
	return defs
}
