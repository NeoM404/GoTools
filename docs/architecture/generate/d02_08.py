from dio import *
import sys
out = sys.argv[1]
which = sys.argv[2:] or ["02", "03", "04", "05", "06", "07", "08"]

def title(d, t, sub):
    d.text(t, 40, 24, 1600, 36, font=24, color=INK, bold=True)
    d.text(sub, 40, 62, 1680, 30, font=15)

def lane(d, label, y, h, fill="#F4F6FA"):
    d.box("", 40, y, 1680, h, fill=fill, stroke="#D5DBE5")
    d.text(label, 60, y + 10, 600, 24, font=15, color=INK, bold=True)

# ---------------------------------------------------------------- 02
if "02" in which:
    d = Diagram("02-aws-sign-in", 1760, 880)
    title(d, "aws login — one sign-in, one account and role, no keys handled",
          "bankctl drives the AWS CLI's own Identity Center flow, lists only your assignments, and writes one profile; the AWS CLI fetches credentials on first use.")
    lane(d, "Engineer machine — bankctl", 110, 220)
    lane(d, "AWS — IAM Identity Center and STS", 400, 260, fill="#FFF6F7")
    W, H, Y = 230, 104, 170
    xs = [70, 350, 630, 910, 1190, 1460]
    b1 = d.box("<b>Managed config</b><br>[sso-session bankctl] in a marked section of ~/.aws/config", xs[0], Y, W, H, font=13)
    b2 = d.box("<b>aws sso login</b><br>browser, or --device-code on a devops box", xs[1], Y, W, H, font=13)
    b3 = d.box("<b>Token cache</b><br>~/.aws/sso/cache — read in memory only", xs[2], Y, W, H, font=13, fill="#FFF8EE", stroke=ORANGE)
    b4 = d.box("<b>Picker</b><br>squad · env · account · role<br>type to filter, number to pick", xs[3], Y, W, H, font=13, stroke=BLUE)
    b5 = d.box("<b>One profile</b><br>bankctl.&lt;account&gt;.&lt;role&gt;<br>other profiles untouched", xs[4], Y, W, H, font=13)
    b6 = d.box("<b>Verify + record</b><br>account must match<br>audit start/end event", xs[5], Y, W, H, font=13)
    for i, x in enumerate(xs):
        d.badge(i + 1, x - 12, Y - 12)
    for a, b in [(b1, b2), (b2, b3), (b3, b4), (b4, b5), (b5, b6)]:
        d.edge(a, b, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    d.text("stdout carries only  <font face='monospace'>export AWS_PROFILE='bankctl.payments-prod.Platform-ReadOnly'</font>  — so  eval \"$(bankctl aws login)\"  works; the picker runs on stderr.", 70, 700, 1600, 30, font=14, color=INK)
    d.text("Never: an access key in a clipboard · the token on a command line · the token written to disk by bankctl · a sign-in to every account (except break-glass)", 70, 738, 1600, 30, font=14, color=RED)
    idc = d.aws("single_sign_on", "IAM Identity Center<br>OIDC sign-in", 433, 480, cat="security")
    api = d.aws("single_sign_on", "Portal API<br>ListAccounts · ListAccountRoles", 713, 480, cat="security")
    cred = d.awsres("temporary_security_credential", "GetRoleCredentials<br>by the AWS CLI, on first use", 1277, 485, color="#DD344C")
    sts = d.aws("sts", "AWS STS<br>GetCallerIdentity", 1543, 480, cat="security")
    d.edge(b2, idc, "approve", color=BLUE, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(b3, api, "bearer token in a header · TLS 1.2+ · no redirects", color=BLUE, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(api, b4, "only your assignments", color=BLUE, exit=(1, 0.5), entry=(0.5, 1), pts=[(1025, 512)])
    d.edge(b5, cred, "", color=QUIET, dashed=1, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(b6, sts, "--profile", color=BLUE, exit=(0.5, 1), entry=(0.5, 0))
    d.box("<b>Break-glass</b> — aws login --all --break-glass \"INC… reason\": only roles in aws.breakGlassRoles, held per Identity Center; every sign-in flagged for review; refusals recorded too.",
          70, 790, 1620, 60, fill="#FDECEC", stroke=RED, font=14, align="left")
    print(d.save(out))

# ---------------------------------------------------------------- 03
if "03" in which:
    d = Diagram("03-shell-session", 1760, 960)
    title(d, "shell — Session Manager under your own identity, beside the existing tools",
          "Instances are picked by name, IP, state and access level; the session opens as your SSO role in a tab coloured by environment. sm and SSMshell keep working, without the paste.")
    lane(d, "Engineer machine", 110, 400)
    lap = d.awsres("client", "bankctl shell devops", 90, 190, size=62)
    pick = d.box("<b>Instance picker</b> (aws ec2 describe-instances)<br><font face='monospace'>NAME · INSTANCE · PRIVATE IP · STATE · TYPE · ZONE · LEVEL</font>", 260, 170, 470, 90, font=13, stroke=BLUE)
    tab = d.box("<b>Windows Terminal tab</b> (--tab, also from WSL)<br>title  payments · PROD · payments-devops", 260, 290, 470, 70, font=13)
    for i, (env, col) in enumerate([("dev", "#22C55E"), ("ete", "#F97316"), ("qa", "#3B82F6"), ("prod", "#EF4444")]):
        d.box(env, 260 + i * 120, 378, 110, 34, fill=col, stroke=col, color="#FFFFFF", bold=True, font=13)
    leg = d.box("<b>--via legacy</b><br>sm / SSMshell launched with this profile's short-term credentials in its environment — no paste", 800, 170, 380, 100, font=13, fill="#FFF8EE", stroke=ORANGE)
    sm = d.box("<b>sm · AWS-EC2-SSMshell.exe</b><br>unchanged", 800, 300, 380, 64, font=13)
    d.edge(lap, pick, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(leg, sm, "", color=ORANGE, exit=(0.5, 1), entry=(0.5, 0))
    d.text("Before the session: change control (when enabled), an audit start event, a banner and terminal title in the environment colour; in prod, a warning that the session is recorded.", 1220, 170, 470, 140, font=14, color=INK)
    d.group("account", "Squad account", 40, 550, 1680, 380)
    ssm = d.aws("systems_manager_session_manager", "Session Manager", 110, 660, cat="mgmt")
    kms = d.aws("key_management_service", "AWS KMS<br>encrypts every session", 300, 800, cat="security")
    d.group("private", "Private subnets", 480, 610, 760, 290)
    i1 = d.aws("ec2", "payments-devops<br>AccessLevel 3", 560, 660, cat="compute")
    i2 = d.aws("ec2", "payments-tools<br>untagged", 800, 660, cat="compute")
    i3 = d.aws("ec2", "payments-batch<br>stopped · AccessLevel 1", 1040, 660, cat="compute")
    ct = d.aws("cloudtrail", "CloudTrail<br>StartSession by your SSO role", 1330, 620, cat="mgmt")
    cw = d.aws("cloudwatch_2", "Session logs<br>(requested control)", 1560, 620, cat="mgmt")
    d.edge(pick, ssm, "aws ssm start-session --profile", color=BLUE, exit=(0, 0.8), entry=(0.5, 0), pts=[(230, 242), (230, 480), (142, 480)])
    d.edge(sm, ssm, "legacy path", color=ORANGE, dashed=1, exit=(0.5, 1), entry=(0, 0.5), pts=[(990, 500), (70, 500), (70, 692)])
    d.edge(ssm, i1, "SSM agent", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.text("Run As (requested): a named Linux user per person instead of root", 560, 810, 600, 24, font=13, color=RED)
    print(d.save(out))

# ---------------------------------------------------------------- 04
if "04" in which:
    d = Diagram("04-connect-tunnel", 1760, 980)
    title(d, "connect — private EKS from the laptop, TLS and identity end to end",
          "A Session Manager port-forward through the devops instance carries kubectl to the private endpoint. TLS is verified against the cluster CA; the token is minted per call as your SSO role.")
    lane(d, "Laptop / WSL", 110, 360)
    kc = d.awsres("client", "kubectl", 80, 190, size=62)
    lp = d.box("<b>127.0.0.1:&lt;free port&gt;</b><br>local listener", 340, 180, 200, 80, font=13)
    plug = d.box("<b>session-manager-plugin</b><br>AWS-StartPortForwarding-<br>SessionToRemoteHost", 600, 175, 260, 90, font=13, stroke=BLUE)
    cfg = d.box("<b>~/.kube/bankctl/payments-eks-prod.json</b> (0600)<br><font face='monospace'>server: https://127.0.0.1:&lt;port&gt;<br>tls-server-name: &lt;id&gt;.gr7.af-south-1.eks.amazonaws.com<br>certificate-authority-data: from describe-cluster<br>exec: aws eks get-token --profile &lt;yours&gt;</font>", 900, 140, 780, 130, font=13, fill="#FFF8EE", stroke=ORANGE, align="left")
    tok = d.box("<b>aws eks get-token</b> — presigned STS GetCallerIdentity as your SSO role; minted per call, never stored", 80, 330, 460, 80, font=13, align="left")
    d.edge(kc, lp, "TLS (SNI = EKS host)", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(lp, plug, "", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(kc, tok, "", color=QUIET, dashed=1, exit=(0.5, 1), entry=(0.1, 0))
    d.group("cloud", "AWS — squad account", 40, 510, 1680, 440)
    ssm = d.aws("systems_manager_session_manager", "Session Manager<br>KMS-encrypted channel", 298, 640, cat="mgmt")
    d.group("vpc", "VPC", 470, 560, 1220, 360)
    d.group("private", "Private subnets", 490, 600, 830, 290)
    ec2 = d.aws("ec2", "Devops instance<br>SSM agent · no keys", 520, 690, cat="compute")
    eni = d.awsres("elastic_network_interface", "EKS endpoint ENIs<br>:443", 860, 694, color="#8C4FFF")
    eks = d.aws("eks", "EKS control plane<br>private endpoint", 1140, 690, cat="containers")
    ae = d.box("<b>Access entry</b> for your SSO role → EKS access policy (view · edit · admin, cluster or namespace scope)", 1350, 650, 320, 110, font=13, stroke=BLUE)
    audit = d.aws("cloudwatch_2", "EKS audit log<br>names your role session", 1450, 800, cat="mgmt")
    d.edge(plug, ssm, "outbound 443 only", color=BLUE, exit=(0.5, 1), entry=(0.5, 0), pts=[(730, 460), (330, 460)])
    d.edge(ssm, ec2, "SSM agent", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(ec2, eni, "host=&lt;endpoint&gt;:443", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(eni, eks, "", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(eks, ae, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    d.text("Tested with the real kubectl: a tampered tls-server-name is refused.", 520, 860, 700, 24, font=13, color=RED)
    print(d.save(out))

# ---------------------------------------------------------------- 05
if "05" in which:
    d = Diagram("05-eks-access-entries", 1760, 920)
    title(d, "EKS access entries — from an in-cluster ConfigMap to access as code",
          "API_AND_CONFIG_MAP keeps aws-auth working on the day; each role then gets its own access entry, managed in Terraform and reviewed by PR. The switch is one-way.")
    m1 = d.box("<b>CONFIG_MAP</b><br>aws-auth ConfigMap only<br>edits inside the cluster", 60, 130, 360, 100, fill="#FDECEC", stroke=RED, font=14)
    m2 = d.box("<b>API_AND_CONFIG_MAP</b><br>access entries + aws-auth<br>nobody loses access", 700, 130, 360, 100, fill="#EAF0FF", stroke=BLUE, font=14)
    m3 = d.box("<b>API</b><br>access entries only<br>after aws-auth is retired", 1340, 130, 360, 100, font=14)
    d.edge(m1, m2, "one-way · start with dev", color=BLUE, width=3, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(m2, m3, "when every mapping is mirrored", color=QUIET, dashed=1, exit=(1, 0.5), entry=(0, 0.5))
    lane(d, "Principals (IAM Identity Center permission sets and the pipeline)", 280, 580)
    r1 = d.awsres("role", "AWSReservedSSO_Platform-ReadOnly", 180, 350, size=52, color="#DD344C")
    r2 = d.awsres("role", "AWSReservedSSO_Squad-Payments", 180, 480, size=52, color="#DD344C")
    r3 = d.awsres("role", "AWSReservedSSO_BreakGlass-Admin", 180, 610, size=52, color="#DD344C")
    ado = d.azure("devops/Azure_DevOps.svg", "devops pipeline role<br>(Azure DevOps, OIDC trust)", 176, 735, size=58)
    eks = d.aws("eks", "payments-eks-prod", 840, 540, cat="containers", size=80)
    p1 = d.box("AmazonEKSViewPolicy · cluster", 470, 352, 300, 48, font=13)
    p2 = d.box("AmazonEKSEditPolicy · namespace payments", 470, 482, 300, 48, font=13)
    p3 = d.box("AmazonEKSClusterAdminPolicy · cluster", 470, 612, 300, 48, font=13, fill="#FDECEC", stroke=RED)
    p4 = d.box("AmazonEKSClusterAdminPolicy · cluster", 470, 740, 300, 48, font=13)
    for r, p in [(r1, p1), (r2, p2), (r3, p3), (ado, p4)]:
        d.edge(r, p, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    for p in [p1, p2, p3, p4]:
        d.edge(p, eks, "", color=BLUE, exit=(1, 0.5), entry=(0, 0.5))
    tf = d.box("<b>deploy/terraform/eks-access-entries</b><br>aws_eks_access_entry + aws_eks_access_policy_association per role, applied by the Azure DevOps pipeline", 1080, 330, 600, 90, font=13, stroke=BLUE, align="left")
    rep = d.box("<b>bankctl eks auth --all-profiles</b><br>mode · endpoint exposure · next step per cluster; --fail-on-configmap gates on it", 1080, 450, 600, 80, font=13, align="left")
    acc = d.box("<b>bankctl eks access payments-eks-prod</b><br>who can reach it, with which policy and scope — the access review", 1080, 560, 600, 80, font=13, align="left")
    d.edge(tf, eks, "", color=QUIET, dashed=1, exit=(0, 0.5), entry=(1, 0.2))
    d.text("Test in dev first: whether SSO role ARNs are mapped with or without /aws-reserved/sso.amazonaws.com/.", 1080, 680, 600, 50, font=13, color=RED)
    print(d.save(out))

# ---------------------------------------------------------------- 06
if "06" in which:
    d = Diagram("06-audit-evidence", 1760, 900)
    title(d, "Audit trail and evidence — recorded before it happens, provable after",
          "Every access writes a start event before acting (no record, no access) and an end event with the outcome. The chain is tamper-evident; the SIEM gets a copy; evidence packs come from it.")
    steps = [("Command", "aws login · shell · connect<br>login · env · ec2"), ("Start event", "who · where · what · change record<br>prevHash → hash"),
             ("Change control", "required? verified? break-glass?<br>(switchable)"), ("Action", "SSO profile · SSM session<br>tunnel · credentials"), ("End event", "outcome · acting principal<br>detail")]
    ids = []
    for i, (h, t) in enumerate(steps):
        ids.append(d.box(f"<b>{h}</b><br>{t}", 60 + i * 335, 150, 290, 96, font=13, stroke=BLUE if i in (1, 4) else "#9AA5B4"))
    for a, b in zip(ids, ids[1:]):
        d.edge(a, b, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    refuse = d.box("Cannot write the start event → the action does not happen", 395, 290, 290, 60, font=13, fill="#FDECEC", stroke=RED)
    d.edge(ids[1], refuse, "", color=RED, exit=(0.5, 1), entry=(0.5, 0))
    log = d.box("<b>audit.jsonl</b> — local, 0600, file-locked<br>each event's hash covers the previous one<br><font face='monospace'>bankctl audit verify</font> detects edits, inserts, deletions", 60, 420, 520, 110, font=13, fill="#FFF8EE", stroke=ORANGE, align="left")
    siem = d.box("<b>SIEM</b> — Splunk HEC or JSON<br>best effort; the local log stays authoritative", 700, 420, 420, 110, font=13, align="left")
    ev = d.box("<b>bankctl evidence --period 2026-Q4</b><br>pack for auditors + SHA-256<br>exceptions: break-glass · prod without a change record · unverified records · incomplete sessions", 1240, 420, 460, 130, font=13, stroke=BLUE, align="left")
    d.edge(ids[4], log, "", color=ORANGE, exit=(0.5, 1), entry=(1, 0.2), pts=[(1485, 380), (640, 380), (640, 442)])
    d.edge(log, siem, "forward", color=ORANGE, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(siem, ev, "", color=QUIET, dashed=1, exit=(1, 0.5), entry=(0, 0.5))
    lane(d, "Authoritative cloud records — bankctl makes them name a person", 600, 260, fill="#FFF6F7")
    d.aws("cloudtrail", "CloudTrail<br>sign-ins, StartSession", 180, 680, cat="mgmt")
    d.aws("cloudwatch_2", "Session Manager logs<br>commands run (requested)", 600, 680, cat="mgmt")
    d.aws("eks", "EKS audit log<br>API calls by role session", 1020, 680, cat="containers")
    d.text("The bankctl trail is attribution of intent from a client; these are the record of what reached the cloud.", 1250, 690, 430, 80, font=14, color=INK)
    print(d.save(out))

# ---------------------------------------------------------------- 07
if "07" in which:
    d = Diagram("07-aks-bastion-inventory", 1760, 930)
    title(d, "AKS — inventory built in Azure DevOps, used on air-gapped bastions",
          "Cloud discovery runs in a read-only pipeline, never on the bastion. A person merges the proposal; CI validates it; bastions get the reviewed fleet.json.")
    d.azgroup("Azure DevOps", 40, 110, 1000, 380)
    repo = d.box("<b>Repo</b> — inventory/fleet.json<br>the reviewed record (changes only by PR)", 80, 170, 300, 90, font=13)
    ci = d.box("<b>CI pipeline</b> — validate on every PR<br>publish the <i>fleet</i> artifact on main", 80, 330, 300, 90, font=13)
    night = d.box("<b>Nightly pipeline</b> — AzureCLI@2, service connection with Reader<br>bankctl inventory diff · sync", 470, 170, 360, 100, font=13, stroke=BLUE)
    prop = d.box("<b>diff.json · proposed-fleet.json</b><br>red run when reality differs", 470, 330, 360, 90, font=13, fill="#FFF8EE", stroke=ORANGE)
    d.azure("devops/Azure_DevOps.svg", "", 930, 380, size=72)
    d.edge(night, prop, "", color=ORANGE, exit=(0.5, 1), entry=(0.5, 0))
    d.edge(prop, repo, "a person reviews + merges", color=QUIET, dashed=1, exit=(0, 0.5), entry=(1, 0.7), pts=[(430, 375), (430, 233)])
    d.edge(repo, ci, "", color=QUIET, exit=(0.5, 1), entry=(0.5, 0))
    d.azgroup("Azure subscriptions — dev · ete · qa · prod", 1100, 110, 620, 380)
    xs = [(1150, "dev", "#22C55E"), (1290, "ete", "#F97316"), (1430, "qa", "#3B82F6"), (1570, "prod", "#EF4444")]
    aks = []
    for x, env, col in xs:
        aks.append(d.azure("containers/Kubernetes_Services.svg", f"&lt;app&gt;-k8s-<br>{env}-cluster", x, 210, size=60))
        d.box(env, x, 350, 60, 30, fill=col, stroke=col, color="#FFFFFF", bold=True, font=12)
    d.edge(night, aks[0], "az aks list (read-only)", color=BLUE, exit=(1, 0.3), entry=(0, 0.5))
    d.azgroup("Bastion network (no internet)", 40, 540, 1680, 360, color="#5A6B7B")
    vm = d.azure("compute/Virtual_Machine.svg", "AKS bastion (RHEL)", 120, 640, size=72)
    bk = d.box("<b>bankctl — mode \"bastion\"</b><br>login &lt;cluster&gt; → kubectl config use-context<br>guard · current · prompt · fleet versions<br>no az, no credentials fetched", 300, 610, 460, 130, font=13, stroke=BLUE, align="left")
    kcfg = d.box("<b>Provisioned kubeconfig</b><br>contexts <i>&lt;app&gt;-k8s-&lt;env&gt;-cluster</i><br>users <i>clusterUser_&lt;rg&gt;_&lt;cluster&gt;</i> (static local accounts)", 830, 610, 460, 110, font=13, align="left")
    note = d.box("<b>Recorded per person</b>: the Linux user who ran login, the context and its kubeconfig user; shared local accounts are flagged — the cluster audit log cannot tell people apart. Fix: Entra ID + kubelogin.", 830, 760, 820, 100, font=13, fill="#FDECEC", stroke=RED, align="left")
    d.edge(vm, bk, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    d.edge(bk, kcfg, "", color=QUIET, exit=(1, 0.5), entry=(0, 0.5))
    d.text("fleet.json — delivery path is the team's choice", 350, 505, 420, 24, font=13, color=QUIET)
    d.edge(ci, vm, "", color=QUIET, dashed=1, exit=(0.85, 1), entry=(0.5, 0), pts=[(335, 610), (156, 610)])
    d.edge(kcfg, aks[3], "kubectl", color="#0078D4", exit=(1, 0.5), entry=(1, 0.5), pts=[(1700, 665), (1700, 240)])
    print(d.save(out))

# ---------------------------------------------------------------- 08
if "08" in which:
    d = Diagram("08-code-architecture", 1760, 940)
    title(d, "Inside bankctl — layered Go packages, one boundary to the outside world",
          "Commands compose small, pure, tested packages. Every subprocess goes through execx (deadline, cancellation, process group); every HTTPS call enforces TLS 1.2+ and refuses downgrades.")
    d.box("<b>cmd/bankctl</b> — main: signals → context, exit code", 60, 120, 1640, 54, font=14, fill="#0F1B2D", stroke="#0F1B2D", color="#FFFFFF")
    d.box("<b>internal/app</b> — dispatch + commands, injected I/O, exit-code contract<br>aws · shell · ec2 · connect · eks · prompt · login/kubeconfig · guard/current · inventory · fleet · sweep · audit · evidence · init · doctor", 60, 196, 1640, 80, font=14, stroke=BLUE)
    pk = [("awssso", "Identity Center portal,<br>token cache, managed profiles"), ("picker", "type-to-filter chooser,<br>no raw mode"), ("kube", "classify, resolve, bastion<br>contexts, sweep"),
          ("inventory", "fleet model, validation,<br>HTTPS + cache"), ("discovery", "EKS/AKS scan, bounded,<br>all-or-nothing scopes"), ("reconcile", "declared vs observed<br>(pure)"),
          ("audit", "hash chain, lock,<br>SIEM forwarder"), ("evidence", "auditor packs<br>(pure)"), ("change", "ServiceNow change<br>verification"), ("support", "lifecycle + extended<br>support cost (pure)"),
          ("config", "load + validate<br>everything up front"), ("tools", "doctor catalogue,<br>version floors")]
    for i, (n, t) in enumerate(pk):
        r, c = divmod(i, 6)
        d.box(f"<b>{n}</b><br>{t}", 60 + c * 276, 306 + r * 120, 256, 100, font=13)
    d.box("<b>internal/execx</b> — the only way out: deadline on every call · Ctrl-C cancels · kill the process group · stderr in errors · interactive mode for sign-in and shells", 60, 556, 1640, 64, font=14, fill="#FFF8EE", stroke=ORANGE)
    ext = [("aws CLI v2", "sso login · sts · ec2 · ssm · eks"), ("session-manager-plugin", "shells + port-forwards"), ("kubectl", "config view · use-context"),
           ("az CLI", "inventory pipeline only"), ("sm / SSMshell", "legacy, launched signed in")]
    for i, (n, t) in enumerate(ext):
        d.box(f"<b>{n}</b><br>{t}", 60 + i * 332, 650, 310, 74, font=13, fill="#F4F6FA", stroke="#D5DBE5")
    https = [("Identity Center portal", "assignments only"), ("ServiceNow Table API", "optional"), ("SIEM collector", "Splunk HEC / JSON"), ("Inventory URL", "optional, cached")]
    for i, (n, t) in enumerate(https):
        d.box(f"<b>{n}</b> — {t}", 60 + i * 415, 760, 395, 50, font=13, fill="#EAF0FF", stroke=BLUE)
    d.text("Go standard library only · CGO off · -trimpath · reproducible · govulncheck · staticcheck · race tests · end-to-end journey", 60, 840, 1640, 30, font=15, color=INK, bold=True, align="center")
    print(d.save(out))
