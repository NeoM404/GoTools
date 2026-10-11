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

	"nedctl/internal/audit"
	"nedctl/internal/config"
	"nedctl/internal/execx"
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
	yes := fs.Bool("yes", false, "copy into the pod without asking (after showing what)")
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl cp POD:/path LOCAL | LOCAL POD:/path [-n NS] [-c CONTAINER] [--cluster C]"
	if err != nil || len(pos) != 2 || !config.ValidNamespace(*ns) || (*container != "" && !podNameRe.MatchString(*container)) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	pod, rpath, download := "", "", false
	if n, p, ok := splitRemote(pos[0]); ok {
		pod, rpath, download = n, p, true
	} else if n, p, ok := splitRemote(pos[1]); ok {
		pod, rpath = n, p
	}
	local := pos[1]
	if !download {
		local = pos[0]
	}
	if pod == "" || !podNameRe.MatchString(pod) || !strings.HasPrefix(rpath, "/") || !remotePathRe.MatchString(rpath) || path.Clean(rpath) == "/" {
		fmt.Fprintln(stderr, "give the pod side as POD:/absolute/path (not /)")
		fmt.Fprintln(stderr, usage)
		return ExitUsage
	}
	rpath = path.Clean(rpath)
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
	exec := []string{"exec", "-n", *ns, pod}
	if *container != "" {
		exec = append(exec, "-c", *container)
	}
	dir, base := path.Dir(rpath), path.Base(rpath)

	if download {
		ev := audit.Event{Action: "cp-download", Cloud: s.cloud, Cluster: s.cluster, Account: s.pc.AccountID, Environment: s.env, Production: s.pc.Production,
			Detail: fmt.Sprintf("%s:%s in %s to %s, %s", pod, rpath, *ns, local, s.where)}
		tr, err := beginAuditEvent(ctx, cfg, ev, stderr)
		if err != nil {
			fmt.Fprintf(stderr, "%v — refusing: every access must be recorded\n", err)
			return ExitFailure
		}
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
		kerr := s.kubectl(ctx, append(exec, "--", "tar", "cf", "-", "-C", dir, path.Base(rpath)), strings.NewReader(""), pw, &errb, false)
		pw.CloseWithError(kerr)
		xerr := <-done
		if kerr != nil || xerr != nil {
			msg := firstNonBlank(strings.TrimSpace(errb.String()), fmt.Sprint(firstErr(xerr, kerr)))
			if strings.Contains(msg, "executable file not found") || strings.Contains(msg, "\"tar\"") {
				msg += " — the container has no tar; nedctl debug attach " + pod + " gives you a shell beside it"
			}
			tr.end(ctx, audit.OutcomeFailure, s.pc.Role, msg, stderr)
			fmt.Fprintf(stderr, "copy failed: %s\n", msg)
			return ExitFailure
		}
		tr.end(ctx, audit.OutcomeSuccess, s.pc.Role, fmt.Sprintf("%s; %d file(s), %d bytes", ev.Detail, files, size), stderr)
		fmt.Fprintf(stderr, "copied %s:%s → %s (%d file(s), %s)\n", pod, rpath, local, files, byteSize(size))
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
	pos, err := parseInterspersed(fs, args)
	usage := "usage: nedctl azure cp <name|env>:PATH LOCAL | LOCAL <name|env>:PATH"
	if err != nil || len(pos) != 2 {
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
	} else if n, p, ok := splitRemote(pos[1]); ok {
		name, rpath = n, p
	}
	if name == "" || !remotePathRe.MatchString(rpath) {
		fmt.Fprintln(stderr, usage)
		return ExitUsage
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
	src, dst := remote, pos[1]
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
	return ExitOK
}
