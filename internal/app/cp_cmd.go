package app

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
	"nedctl/internal/inventory"
)

// `nedctl cp` copies files between this machine and a container, on EKS
// or AKS: tar runs in the container and the archive streams through the
// session (on AKS through the bastion, never stored there); this side
// reads or writes it itself, refusing paths that would escape the target.
// `nedctl azure cp` copies to and from a bastion or Azure machine with scp.

// maxCopyBytes bounds a download, so a wrong path cannot fill the disk.
const maxCopyBytes = 2 << 30

var remotePathRe = regexp.MustCompile(`^[A-Za-z0-9._/~+@-][A-Za-z0-9._/~+@ -]{0,1000}$`)

// splitRemote reads NAME:PATH; a Windows drive (C:\x) is not remote.
func splitRemote(s string) (name, p string, ok bool) {
	name, p, ok = strings.Cut(s, ":")
	if !ok || len(name) <= 1 || p == "" {
		return "", "", false
	}
	return name, p, true
}

func cmdCp(ctx context.Context, cfgPath string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("cp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var sel clusterSel
	addClusterSel(fs, &sel, false)
	ns := addNamespaceFlag(fs)
	container := fs.String("c", "", "the container (default: the pod's first)")
	yes := fs.Bool("yes", false, "copy into the pod, or deploy the node helper pod, without asking (after showing what)")
	save := fs.Bool("save", false, "save the copy in your Downloads folder (on WSL: Windows' Downloads), instead of naming LOCAL")
	image := fs.String("image", "", "node copies: the helper pod's image (default: the debug image)")
	dryRun := fs.Bool("dry-run", false, "node copies: show the helper pod and check it with the cluster; copy nothing")
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl cp POD:/path LOCAL | POD:/path --save | node/NODE:/path LOCAL|--save | LOCAL POD:/path [-n NS] [-c CONTAINER] [--cluster C]"
	if err != nil || !(len(pos) == 2 || len(pos) == 1 && *save) || !config.ValidNamespace(*ns) || (*container != "" && !podNameRe.MatchString(*container)) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if *save && len(pos) == 2 {
		fmt.Fprintln(stderr, "give LOCAL or --save, not both")
		return ExitUsage
	}
	pod, rpath, download := "", "", false
	if n, p, ok := splitRemote(pos[0]); ok {
		pod, rpath, download = n, p, true
	} else if len(pos) == 2 {
		if n, p, ok := splitRemote(pos[1]); ok {
			pod, rpath = n, p
		}
	}
	if *save && !download {
		fmt.Fprintln(stderr, "--save is for copies from a pod or node: nedctl cp POD:/path --save")
		return ExitUsage
	}
	node := ""
	if n, ok := strings.CutPrefix(pod, "node/"); ok {
		node, pod = n, ""
		if !download {
			fmt.Fprintln(stderr, "copying onto a node is not supported — nedctl debug node gives you a shell on it")
			return ExitUsage
		}
		if !nodeNameRe.MatchString(node) {
			fmt.Fprintf(stderr, "%q is not a node name\n", node)
			return ExitUsage
		}
	} else if pod == "" || !podNameRe.MatchString(pod) {
		fmt.Fprintln(stderr, "give the remote side as POD:/absolute/path or node/NODE:/absolute/path")
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	if !strings.HasPrefix(rpath, "/") || !remotePathRe.MatchString(rpath) || path.Clean(rpath) == "/" {
		fmt.Fprintln(stderr, "give the remote path as an absolute path (not /)")
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	rpath = path.Clean(rpath)
	dir, base := path.Dir(rpath), path.Base(rpath)
	local := ""
	switch {
	case *save:
		if local, err = saveTarget(ctx, base); err != nil {
			fmt.Fprintf(stderr, "finding your Downloads folder: %v — name LOCAL instead\n", err)
			return ExitFailure
		}
	case download:
		local = pos[1]
	default:
		local = pos[0]
	}
	cfg, _, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(stderr, "config error: %v\n", err)
		return ExitFailure
	}
	s, code := openKubeSession(ctx, cfg, sessionFlags{cluster: sel.cluster, env: sel.env, awsProfile: sel.awsProfile}, stderr)
	if code != ExitOK {
		return code
	}
	defer s.close()
	if node != "" {
		nsSet := false
		fs.Visit(func(f *flag.Flag) { nsSet = nsSet || f.Name == "n" || f.Name == "namespace" })
		helperNS := cfg.Debug.DebugNamespace()
		if nsSet {
			helperNS = *ns
		}
		return copyFromNode(ctx, cfg, s, node, rpath, local, helperNS, *image, &debugFlags{yes: *yes, dryRun: *dryRun}, stderr)
	}
	exec := []string{"exec", "-n", *ns, pod}
	if *container != "" {
		exec = append(exec, "-c", *container)
	}

	if download {
		ev := audit.Event{Action: "cp-download", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
			Detail: fmt.Sprintf("%s:%s in %s to %s, %s", pod, rpath, *ns, local, s.where)}
		tr, err := beginAuditEvent(ctx, cfg, ev, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
			return ExitFailure
		}
		files, size, err := streamDownload(ctx, s, exec, dir, base, rpath, local, stderr)
		if err != nil {
			msg := err.Error()
			if strings.Contains(msg, "executable file not found") || strings.Contains(msg, "\"tar\"") {
				msg += " — the container has no tar; nedctl debug attach " + pod + " gives you a shell beside it"
			}
			tr.end(ctx, audit.OutcomeFailure, s.pc.Role, msg, stderr)
			fmt.Fprintf(stderr, "copy failed: %s\n", msg)
			return ExitFailure
		}
		tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, fmt.Sprintf("%s; %d file(s), %d bytes", ev.Detail, files, size), stderr)
		fmt.Fprintf(stderr, "copied %s:%s → %s (%d file(s), %s)\n", pod, rpath, local, files, byteSize(size))
		savedHint(local, stderr)
		return ExitOK
	}

	// Upload: show, ask, record, stream.
	var archive bytes.Buffer
	files, size, err := tarFrom(local, base, &archive)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	fmt.Fprintf(stderr, "\nTo copy %s (%d file(s), %s) into %s:%s in %s on %s\n", local, files, byteSize(size), pod, rpath, *ns, s.label())
	if !confirmProduction(cfg, s.pc, s.cluster, false, stderr) {
		return ExitFailure
	}
	if !*yes {
		if !stdinIsTerminal() {
			fmt.Fprintln(stderr, "nothing copied: pass --yes to copy without a terminal")
			return ExitUsage
		}
		fmt.Fprint(stderr, "Copy it? [y/N] ")
		line, _ := bufio.NewReader(stdin).ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
			fmt.Fprintln(stderr, "nothing copied")
			return ExitFailure
		}
	}
	up := audit.Event{Action: "cp-upload", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("%s to %s:%s in %s (%d file(s), %d bytes), %s", local, pod, rpath, *ns, files, size, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, up, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every change must be recorded\n", err)
		return ExitFailure
	}
	exec = append([]string{"exec", "-i"}, exec[1:]...)
	var errb bytes.Buffer
	if err := s.kubectl(ctx, append(exec, "--", "tar", "xf", "-", "-C", dir), &archive, io.Discard, &errb, false); err != nil {
		msg := firstNonBlank(strings.TrimSpace(errb.String()), err.Error())
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, msg, stderr)
		fmt.Fprintf(stderr, "copy failed: %s\n", msg)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, up.Detail, stderr)
	fmt.Fprintf(stderr, "copied %s → %s:%s\n", local, pod, rpath)
	return ExitOK
}

// streamDownload runs tar in the container (exec is the kubectl exec
// prefix) and unpacks the archive at local as it arrives.
func streamDownload(ctx context.Context, s *kubeSession, exec []string, dir, base, rpath, local string, stderr io.Writer) (int, int64, error) {
	pr, pw := io.Pipe()
	done := make(chan error, 1)
	var files int
	var size int64
	go func() {
		var xerr error
		files, size, xerr = untarTo(pr, rpath, local)
		pr.CloseWithError(xerr)
		done <- xerr
	}()
	var errb bytes.Buffer
	sp := spinning(stderr, "Copying "+rpath+"…")
	kerr := s.kubectl(ctx, append(exec, "--", "tar", "cf", "-", "-C", dir, base), strings.NewReader(""), pw, &errb, false)
	pw.CloseWithError(kerr)
	xerr := <-done
	sp.Stop()
	if kerr != nil || xerr != nil {
		return files, size, errors.New(firstNonBlank(strings.TrimSpace(errb.String()), fmt.Sprint(firstErr(xerr, kerr))))
	}
	return files, size, nil
}

// copyFromNode copies a path from a node's own filesystem: a short-lived
// pod on that node mounts the node's root read-only at /host (no host
// network, processes or privilege), shown, dry-run and approved like every
// deployment; tar runs in it and the pod is removed afterwards.
func copyFromNode(ctx context.Context, cfg config.Config, s *kubeSession, node, rpath, local, ns, image string, d *debugFlags, stderr io.Writer) int {
	ref := cfg.Debug.ImageFor(firstNonBlank(image, cfg.Debug.DefaultImage()))
	if !config.ValidImageRef(ref) || !config.ValidNamespace(ns) {
		fmt.Fprintf(stderr, "--image %q is not an image reference\n", image)
		return ExitUsage
	}
	sp := spinning(stderr, "Looking up "+node+" on "+s.label()+"…")
	_, err := s.output(ctx, "", "get", "node", node, "-o", "name")
	sp.Stop()
	if err != nil {
		fmt.Fprintf(stderr, "node %s on %s: %v\n", node, s.label(), err)
		return ExitFailure
	}
	p := debugPod{Name: "nedctl-cp-" + debugOwner() + "-" + randomSuffix(), Namespace: ns, Image: ref, Owner: debugOwner(),
		Kind: "cp", Profile: "general", Node: node, TTL: min(cfg.Debug.DebugTTL(), 15*time.Minute)}
	manifest := p.manifest()
	if code := approveDeploy(ctx, cfg, s, "a pod on node "+node+" to read "+rpath+" (the node's files, read-only)", manifest, true, d, stderr); code != ExitOK || d.dryRun {
		return code
	}
	base := audit.Event{Action: "cp-node", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
		Detail: fmt.Sprintf("node %s:%s to %s, through pod %s/%s, %s", node, rpath, local, ns, p.Name, s.where)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	if code := applyChangeControl(ctx, cfg, inventory.Cluster{Name: s.cluster, Environment: s.env}, "", "", tr, stderr); code != ExitOK {
		return code
	}
	if _, err := s.output(ctx, manifest, "create", "-f", "-"); err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "creating the pod: %v\n", err)
		return ExitFailure
	}
	defer removeDebugPod(ctx, s, ns, p.Name, stderr)
	sp = working(stderr, fmt.Sprintf("Waiting for %s to start…", p.Name))
	err = waitDebugPod(ctx, s, ns, p.Name)
	sp.Stop()
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintln(stderr, err)
		return ExitFailure
	}
	files, size, err := streamDownload(ctx, s, []string{"exec", "-n", ns, p.Name}, path.Join("/host", path.Dir(rpath)), path.Base(rpath), rpath, local, stderr)
	if err != nil {
		tr.end(ctx, audit.OutcomeFailure, s.pc.Role, err.Error(), stderr)
		fmt.Fprintf(stderr, "copy failed: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, fmt.Sprintf("%s; %d file(s), %d bytes", base.Detail, files, size), stderr)
	fmt.Fprintf(stderr, "copied %s:%s → %s (%d file(s), %s)\n", node, rpath, local, files, byteSize(size))
	savedHint(local, stderr)
	return ExitOK
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

func byteSize(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d bytes", n)
}

// untarTo writes the archive of remote path rpath to local: into it when
// it is an existing directory, else as that name. Entries must stay inside
// the target; links and devices are skipped.
func untarTo(r io.Reader, rpath, local string) (int, int64, error) {
	base := path.Base(rpath)
	target := local
	if fi, err := os.Stat(local); err == nil && fi.IsDir() {
		target = filepath.Join(local, base)
	}
	tr := tar.NewReader(r)
	files, total := 0, int64(0)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return files, total, fmt.Errorf("reading the archive: %w", err)
		}
		name := path.Clean(strings.TrimPrefix(h.Name, "./"))
		rel := strings.TrimPrefix(strings.TrimPrefix(name, base), "/")
		if name != base && !strings.HasPrefix(name, base+"/") || strings.Contains(rel, "..") {
			return files, total, fmt.Errorf("refusing %q: outside %s", h.Name, base)
		}
		dest := filepath.Join(target, filepath.FromSlash(rel))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dest, 0o755); err != nil {
				return files, total, err
			}
		case tar.TypeReg:
			if total += h.Size; total > maxCopyBytes {
				return files, total, fmt.Errorf("more than %s — copy a smaller path", byteSize(maxCopyBytes))
			}
			if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
				return files, total, err
			}
			f, err := os.OpenFile(dest, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
			if err != nil {
				return files, total, err
			}
			_, err = io.Copy(f, io.LimitReader(tr, h.Size))
			f.Close()
			if err != nil {
				return files, total, err
			}
			files++
		}
	}
	if files == 0 && total == 0 {
		if _, err := os.Stat(target); err != nil {
			return 0, 0, fmt.Errorf("nothing was copied (%s is empty or missing)", rpath)
		}
	}
	return files, total, nil
}

// tarFrom archives local (a file or a directory) under the name base.
func tarFrom(local, base string, w io.Writer) (int, int64, error) {
	fi, err := os.Stat(local)
	if err != nil {
		return 0, 0, err
	}
	tw := tar.NewWriter(w)
	files, total := 0, int64(0)
	add := func(p string, info os.FileInfo, name string) error {
		h, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		h.Name, h.Uname, h.Gname, h.Uid, h.Gid = name, "", "", 0, 0
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			f, err := os.Open(p)
			if err != nil {
				return err
			}
			defer f.Close()
			if _, err := io.Copy(tw, f); err != nil {
				return err
			}
			files++
			total += info.Size()
		}
		return nil
	}
	if !fi.IsDir() {
		err = add(local, fi, base)
	} else {
		err = filepath.Walk(local, func(p string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && !info.Mode().IsRegular() {
				return nil // links, devices: not copied
			}
			rel, _ := filepath.Rel(local, p)
			return add(p, info, path.Join(base, filepath.ToSlash(rel)))
		})
	}
	if err != nil {
		return files, total, fmt.Errorf("reading %s: %w", local, err)
	}
	return files, total, tw.Close()
}

// azureCp is `nedctl azure cp`: scp to or from a bastion or Azure machine
// named as it is in `azure hosts` (or by environment).
func azureCp(ctx context.Context, cfgPath string, args []string, stderr io.Writer) int {
	fs := flag.NewFlagSet("azure cp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	save := fs.Bool("save", false, "save the copy in your Downloads folder (on WSL: Windows' Downloads), instead of naming LOCAL")
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl azure cp <name|env>:PATH LOCAL | <name|env>:PATH --save | LOCAL <name|env>:PATH"
	if err != nil || !(len(pos) == 2 && !*save || len(pos) == 1 && *save) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	cfg, ok := loadAzure(cfgPath, stderr)
	if !ok {
		return ExitFailure
	}
	name, rpath, download := "", "", false
	if n, p, ok := splitRemote(pos[0]); ok {
		name, rpath, download = n, p, true
	} else if len(pos) == 2 {
		if n, p, ok := splitRemote(pos[1]); ok {
			name, rpath = n, p
		}
	}
	if name == "" || !remotePathRe.MatchString(rpath) || (*save && !download) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	localDst := ""
	if *save {
		if localDst, err = saveTarget(ctx, path.Base(path.Clean(rpath))); err != nil {
			fmt.Fprintf(stderr, "finding your Downloads folder: %v — name LOCAL instead\n", err)
			return ExitFailure
		}
	} else if download {
		localDst = pos[1]
	}
	env, terms := takeEnv(cfg, []string{name})
	t, code := chooseTarget(cfg, env, terms, stderr)
	if code != ExitOK {
		return code
	}
	opts := []string{"-r", "-o", "ServerAliveInterval=30"}
	if cfg.Azure.User != "" && !strings.Contains(t.Dest, "@") {
		opts = append(opts, "-o", "User="+cfg.Azure.User)
	}
	if t.Jump != "" {
		opts = append(opts, "-o", "ProxyJump="+t.Jump)
	}
	remote := t.Dest + ":" + rpath
	src, dst := remote, localDst
	if !download {
		src, dst = pos[0], remote
	}
	if strings.HasPrefix(src, "-") || strings.HasPrefix(dst, "-") {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	action := "scp-download"
	if !download {
		action = "scp-upload"
	}
	base := audit.Event{Action: action, Cloud: "azure", Environment: t.Env, Production: cfg.IsProdEnvironment(t.Env),
		Detail: fmt.Sprintf("%s → %s", src, dst)}
	tr, err := beginAuditEvent(ctx, cfg, base, stderr)
	if err != nil {
		fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
		return ExitFailure
	}
	err = execx.Interactive(ctx, execx.Spec{Stdin: childStdin(), Name: "scp", Args: append(opts, "--", src, dst), Timeout: cfg.AWS.Timeout()})
	if err != nil {
		err = sshError(t, err)
		tr.end(ctx, audit.OutcomeFailure, "ssh:"+t.Dest, err.Error(), stderr)
		fmt.Fprintf(stderr, "copy failed: %v\n", err)
		return ExitFailure
	}
	tr.end(ctx, audit.OutcomeSuccess, "ssh:"+t.Dest, base.Detail, stderr)
	fmt.Fprintf(stderr, "copied %s → %s\n", src, dst)
	if download {
		savedHint(dst, stderr)
	}
	return ExitOK
}

// saveTarget is where --save puts a copy of base: the user's Downloads
// folder (Windows' own when running in WSL, so it opens in Explorer), under
// a name not already taken.
func saveTarget(ctx context.Context, base string) (string, error) {
	dir, err := downloadsDir(ctx)
	if err != nil {
		return "", err
	}
	return uniquePath(dir, base), nil
}

// windowsProfile is %USERPROFILE% as a WSL path (/mnt/c/Users/x); a var
// for tests.
var windowsProfile = func(ctx context.Context) string {
	out, err := execx.Output(ctx, 5*time.Second, "cmd.exe", "/c", "echo %USERPROFILE%")
	if err != nil {
		return ""
	}
	p := wslPath(strings.TrimSpace(string(out)))
	if !strings.HasPrefix(p, "/mnt/") {
		return ""
	}
	return p
}

func downloadsDir(ctx context.Context) (string, error) {
	if inWSL() {
		if prof := windowsProfile(ctx); prof != "" {
			d := filepath.Join(prof, "Downloads")
			if fi, err := os.Stat(d); err == nil && fi.IsDir() {
				return d, nil
			}
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, "Downloads")
	return d, os.MkdirAll(d, 0o755)
}

// uniquePath is dir/base, or dir/name-1.ext, name-2.ext… when taken.
func uniquePath(dir, base string) string {
	p := filepath.Join(dir, base)
	if _, err := os.Lstat(p); os.IsNotExist(err) {
		return p
	}
	ext := filepath.Ext(base)
	stem := strings.TrimSuffix(base, ext)
	if stem == "" {
		stem, ext = base, ""
	}
	for i := 1; i < 10000; i++ {
		p = filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, i, ext))
		if _, err := os.Lstat(p); os.IsNotExist(err) {
			return p
		}
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, now().UnixNano(), ext))
}

// windowsForm is /mnt/c/Users/x/f as C:\Users\x\f, for WSL users to find
// a saved file in Explorer; "" for any other path.
func windowsForm(p string) string {
	rest, ok := strings.CutPrefix(p, "/mnt/")
	if !ok || len(rest) < 2 || rest[1] != '/' || rest[0] < 'a' || rest[0] > 'z' {
		return ""
	}
	return strings.ToUpper(rest[:1]) + ":\\" + strings.ReplaceAll(rest[2:], "/", "\\")
}

// savedHint says where a copy landed in Windows terms, from WSL.
func savedHint(local string, stderr io.Writer) {
	if !inWSL() {
		return
	}
	abs, err := filepath.Abs(local)
	if err != nil {
		return
	}
	if w := windowsForm(abs); w != "" {
		fmt.Fprintf(stderr, "  in Windows: %s\n", w)
	}
}
