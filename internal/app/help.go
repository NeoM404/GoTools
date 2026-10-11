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
		{"azure cp", "<name|env>:PATH LOCAL|--save", "Copy files to or from a bastion or Azure machine (scp)", "Uses the same SSH settings as azure shell. --save puts the copy in your Downloads folder (from WSL, Windows' Downloads). Recorded.",
			[]string{"nedctl azure cp qa:/tmp/capture.pcap .", "nedctl azure cp qa:/tmp/capture.pcap --save", "nedctl azure cp ./script.sh qa:~/"}},
	}},
	{"For developers (EKS or AKS)", []cmdHelp{
		{"explain", "<pod|deploy/NAME>", "Why is it not working? Findings in plain words, with what to do",
			"Reads the workload, its pods and their events (and the last log lines of a container that keeps crashing) and says what is wrong: image cannot be pulled, crash loop with the exit reason, killed for memory, cannot be scheduled and why, readiness or liveness probe failing, missing Secret or ConfigMap, stuck rollout. Read-only. Exits 1 when something is failing.",
			[]string{"nedctl explain deploy/payments-api -n payments", "nedctl explain payments-api-7f9c-x2x4z -n payments --cluster acm-k8s-qa-cluster", "nedctl explain deploy/payments-api -n payments -o json"}},
		{"logs", "<deploy/NAME|POD>", "Logs of every pod of an app at once, coloured per pod",
			"Reads the logs of all the workload's pods and containers together, each line prefixed with its pod and container in its own colour (like stern). Secrets and personal data (passwords, tokens, keys, card and ID numbers) are hidden; --no-redact shows them outside production only. -f follows; --grep filters; --since and --tail bound it. Recorded in the audit trail.",
			[]string{"nedctl logs deploy/payments-api -n payments", "nedctl logs payments-api -n payments -f --grep error", "nedctl logs deploy/payments-api -n payments --since 10m --cluster acm-k8s-qa-cluster"}},
		{"forward", "<svc/NAME> [LOCAL:]REMOTE", "Reach a service in the cluster from this machine (127.0.0.1)",
			"Port-forwards a service, pod or deployment to 127.0.0.1 here, for a browser, Postman or a database tool. On AKS, kubectl forwards on the bastion and SSH carries the port to you in the same connection. Ctrl-C stops both. Recorded.",
			[]string{"nedctl forward svc/payments-api 8080 -n payments", "nedctl forward svc/payments-db 15432:5432 -n payments --cluster acm-k8s-qa-cluster", "nedctl forward svc/web 443 -n web   # → 127.0.0.1:8443"}},
		{"cp", "POD:/path LOCAL|--save", "Copy files out of a container or node (or into a container)",
			"Streams a tar of the path through the session — on AKS through the bastion, never stored there — and writes it on your machine, refusing paths that escape the target (up to 2 GB). --save puts it in your Downloads folder instead of LOCAL (on WSL, Windows' Downloads, so Explorer shows it), never overwriting. node/NODE:/path reads the node's own files through a short-lived pod that mounts them read-only (shown, dry-run and approved first; removed after). LOCAL POD:/path copies into the container after showing what and asking. Needs tar in the container. Recorded.",
			[]string{"nedctl cp payments-api-7f9c:/tmp/heap.hprof . -n payments", "nedctl cp payments-api-7f9c:/tmp/heap.hprof --save -n payments", "nedctl cp node/aks-pool1-000001:/var/log/syslog --save --cluster acm-k8s-qa-cluster", "nedctl cp ./config.yaml payments-api-7f9c:/tmp/config.yaml -n payments"}},
		{"app", "NAME", "One app in every environment: version, ready replicas, last change",
			"Searches every AKS cluster on the bastions (or --env, --cluster, --aws for EKS) for deployments and statefulsets whose name contains NAME, and shows each one's image version, ready replicas and last update, then a one-line summary of which version runs where. Read-only.",
			[]string{"nedctl app payments-api", "nedctl app payments-api --env qa,prod --match payments", "nedctl app payments-api --exact -o json"}},
		{"diff", "NAME", "Works in QA, fails in prod? The same app side by side, differences marked",
			"Compares a deployment or statefulset (exact name) wherever it runs: images, replicas, update strategy, service account, node selector and tolerations, and per container resources, probes, environment variable names and the ConfigMaps and Secrets it loads (+ added, − missing, against the first). Only names are read, never values. --all shows what is the same too. Read-only.",
			[]string{"nedctl diff payments-api --env qa,prod", "nedctl diff payments-api --env dev,qa -n payments --all", "nedctl diff payments-api -o json"}},
	}},
	{"For DevOps: run the fleet", []cmdHelp{
		{"health", "", "One line per cluster, then what needs attention",
			"Nodes not ready or under pressure, pods crash-looping or stuck pending, workloads below their replicas, volume claims not bound, TLS certificates expiring (default within 30 days), and the version's support status. --env qa checks every QA cluster in one SSH connection per bastion. --board shows them all on a live board that fills in as results arrive; --watch 1m keeps reading (a wall screen). Read-only; exits 1 when a cluster fails or cannot be reached.",
			[]string{"nedctl health --env qa", "nedctl health --env prod --board", "nedctl health --env dev,qa,prod --watch 1m", "nedctl health --env dev,qa --match payments", "nedctl health --cluster acm-k8s-qa-cluster", "nedctl health --aws -o json"}},
		{"run", "<RUNBOOK> [name=value…]", "Run a team runbook: every step shown, changes dry-run and approved",
			"Runbooks are named kubectl steps with parameters (built in: restart-deployment, scale-deployment, rollback-deployment; the team's own in runbooksDir or ./runbooks). nedctl shows the runbook filled in, runs reading steps, and for each changing step runs a server-side dry run, asks, then runs it — recorded. `run ls` lists them, `run show NAME` explains one.",
			[]string{"nedctl run ls", "nedctl run show restart-deployment", "nedctl run restart-deployment deployment=payments-api namespace=payments --cluster acm-k8s-qa-cluster", "nedctl run scale-deployment deployment=api replicas=3 --dry-run"}},
		{"node drain", "NODE", "Drain a node safely: what moves, what blocks, dry run, then ask",
			"Lists the pods that will move, pods no controller will recreate (the drain stops on them; nedctl never forces) and disruption budgets allowing no disruption, has the cluster dry-run the drain, asks, then drains (ignoring DaemonSets, deleting emptyDir data, up to --timeout). Recorded; change control applies.",
			[]string{"nedctl node drain aks-pool1-000001 --cluster acm-k8s-qa-cluster", "nedctl node drain aks-pool1-000001 --dry-run"}},
		{"node cordon", "NODE", "Stop new pods landing on a node (dry run, ask, recorded)", "", []string{"nedctl node cordon aks-pool1-000001"}},
		{"node uncordon", "NODE", "Let pods land on a node again", "", []string{"nedctl node uncordon aks-pool1-000001"}},
		{"fleet run", "-- kubectl …", "One read-only kubectl command on many clusters",
			"Runs a read-only kubectl command (get, describe, logs, top, events, auth can-i, …) on every cluster selected — --env qa runs it on every QA cluster in one SSH connection per bastion — and shows the answers per cluster. Write commands, --context/--kubeconfig and -f/--watch are refused.",
			[]string{"nedctl fleet run --env qa -- kubectl get nodes", "nedctl fleet run --env dev,qa,prod --prefix -- kubectl get deploy -A | grep payments-api", "nedctl fleet run --aws -- kubectl get --raw /version"}},
	}},
	{"For DevSecOps: checks and evidence", []cmdHelp{
		{"posture", "", "Risky settings in what runs: privileged, host access, root, secrets in env, public LBs…",
			"Checks every pod and service for privileged containers, host namespaces and paths, root, dangerous capabilities, missing memory limits, latest tags, unapproved registries (security.approvedRegistries), secrets written into environment variables (names only — values are never read) and public load balancers. Platform namespaces are skipped (security.ignoreNamespaces). Exits 1 on a failing cluster; -o json is the evidence.",
			[]string{"nedctl posture --env prod", "nedctl posture --cluster acm-k8s-qa-cluster", "nedctl posture --env qa,prod -o json > posture-2026-10.json"}},
		{"access review", "", "Who holds cluster-admin, admin or edit — against the approved list",
			"Lists every subject bound to a reviewed role (ClusterRoleBindings and RoleBindings) and marks each approved or unapproved against access/approved.json (or security.approvedAccess); approvals that match nothing are listed for removal. Kubernetes' own subjects are left out. Exits 1 on an unapproved grant or an unreachable cluster.",
			[]string{"nedctl access review --env prod", "nedctl access review --env qa,prod -o json > access-2026-Q4.json", "nedctl access review --cluster acm-k8s-qa-cluster --roles '*'"}},
		{"azure auth", "", "Each AKS cluster: shared local account or per-person Entra ID",
			"Reads each bastion's kubeconfig (kubectl config view, which hides every key) and shows per cluster whether it is reached with a shared local account (clusterUser: the cluster's audit log cannot name the engineer) or Entra ID through kubelogin, with the step to move. --fail-on-local turns it into a gate.",
			[]string{"nedctl azure auth", "nedctl azure auth --env prod -o json", "nedctl azure auth --fail-on-local"}},
		{"images", "", "Every image running, with digests and where — the list for a scanner",
			"Lists each image reference running on the clusters selected, with the digests it runs as, its registry, how many clusters and containers, and flags: unapproved-registry, mutable-tag (latest), several-digests (a re-pushed tag). -o csv feeds trivy, Defender or Inspector.",
			[]string{"nedctl images --env prod", "nedctl images --env qa,prod --flagged", "nedctl images --env prod -o csv > images.csv", "nedctl images --env prod --fail-on-unapproved"}},
	}},
	{"Debugging on a cluster (EKS or AKS)", []cmdHelp{
		{"debug pod", "", "A debug pod (netshoot by default) with a shell; removed when you exit",
			"Shows the pod it will deploy, has the cluster check it (server-side dry run), and deploys it only when you approve. It goes in the default namespace unless you give -n, never gets a service-account token, and is removed when you exit (or at its time limit, 2h). --image takes a short name (netshoot, busybox, alpine, ubuntu, curl) or any image. Profiles: general (default), netadmin (tcpdump), sysadmin (privileged), restricted (non-root).",
			[]string{"nedctl debug pod", "nedctl debug pod --image busybox -n payments", "nedctl debug pod --cluster acm-k8s-qa-cluster --profile netadmin", "nedctl debug pod --dry-run"}},
		{"debug node", "[NODE]", "A shell on a node: its processes, network and files at /host",
			"Picks a node (status, pool, zone, version) and deploys a pod on it with the node's process, network and IPC namespaces and its filesystem at /host; chroot /host runs the node's own tools. Profile general by default; netadmin for packet capture; sysadmin for full (privileged) access. Shown, dry-run and approved first; removed when you exit.",
			[]string{"nedctl debug node", "nedctl debug node aks-pool1-123 --profile sysadmin", "nedctl debug node --cluster payments-eks-dev"}},
		{"debug attach", "<pod>", "A debug container beside a running pod, sharing its processes",
			"Adds an ephemeral container (kubectl debug --target) to a pod whose image has no shell, or that keeps crashing. Shown and approved first. Needs kubectl 1.27 or newer where it runs.",
			[]string{"nedctl debug attach payments-api-7f9c -n payments", "nedctl debug attach payments-api-7f9c -n payments -c api --image busybox"}},
		{"debug net", "<host[:port]>", "Can pods reach it? DNS, TCP, TLS and HTTP from inside the cluster",
			"Runs a short-lived pod that resolves the host, connects to the port, and for web ports shows the certificate and the HTTP status; then removes it.",
			[]string{"nedctl debug net payments-db.internal:5432", "nedctl debug net api.example.com:443 --cluster acm-k8s-qa-cluster"}},
		{"debug ls", "", "Debug pods on a cluster: whose, where, how old", "", []string{"nedctl debug ls --cluster acm-k8s-qa-cluster"}},
		{"debug clean", "", "Remove your leftover debug pods (--all: everyone's)", "Shows what it will remove and asks first.", []string{"nedctl debug clean", "nedctl debug clean --all --dry-run"}},
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
		{"doctor", "", "Check tools, config, proxy, CA bundle, portal and sign-in",
			"--hygiene checks this machine instead for risky leftovers: long-term AWS keys on disk or exported, kubeconfigs with static credentials, SSH keys without a passphrase or readable by others, plain-text git/netrc credentials, and secrets typed into shell history. It says where and how to fix — never the secret.",
			[]string{"nedctl doctor", "nedctl doctor --all", "nedctl doctor --hygiene", "nedctl doctor --offline -o json"}},
		{"prompt init", "<bash|zsh|powershell>", "Shell code for the prompt, tab colour, completion and login switching", "setup adds it to ~/.bashrc, ~/.zshrc or your PowerShell profile for you.", []string{`eval "$(nedctl prompt init bash)"`, "nedctl prompt init powershell | Out-String | Invoke-Expression"}},
		{"version", "", "This nedctl's version; --check looks for a newer release", "", []string{"nedctl version --check"}},
		{"update", "", "Install the latest release — only one signed by the bank",
			"Downloads this platform's binary with SHA256SUMS and its signature from the release location, checks the signature against the key built into this nedctl and the binary against its checksum, runs it to confirm its version, then replaces this nedctl. Anything that fails a check is refused and nothing changes. Recorded.",
			[]string{"nedctl update", "nedctl update --check"}},
		{"verify", "FILE", "Check a downloaded nedctl against the bank's signature",
			"Needs SHA256SUMS and SHA256SUMS.sig next to FILE (they come with every release). setup does this by itself when they are there.",
			[]string{"nedctl verify ~/Downloads/nedctl-linux-amd64"}},
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
	"profile": "NAME", "aws-profile": "PROFILE", "cluster": "CLUSTER", "image": "IMAGE", "n": "NAMESPACE", "namespace": "NAMESPACE", "on-node": "NODE", "c": "CONTAINER", "container": "CONTAINER", "match": "WORD", "region": "REGION", "via": "MODE", "via-instance": "INSTANCE", "instance": "INSTANCE",
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
