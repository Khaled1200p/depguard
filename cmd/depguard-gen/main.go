// depguard-gen: builds a cryptographic baseline (depguard.baseline.json) from
// lockfiles + the actual on-disk installation (site-packages / node_modules).
//
//	depguard-gen keygen -out ./keys
//	depguard-gen -root ./app -out depguard.baseline.json [-sign-key keys/depguard.key]
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/depguard/depguard/pkg/baseline"
)

var execExt = map[string]bool{".py": true, ".js": true, ".cjs": true, ".mjs": true, ".so": true, ".node": true, ".pyd": true}
var soVersioned = regexp.MustCompile(`\.so(\.\d+)+$`)

func isExecutable(name string) bool {
	return execExt[strings.ToLower(filepath.Ext(name))] || soVersioned.MatchString(name)
}

type pkgRef struct{ Name, Version, Ecosystem string }
type job struct {
	path string
	ref  pkgRef
}
type nodePkg struct {
	dir string
	ref pkgRef
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		runKeygen(os.Args[2:])
		return
	}
	fl := flag.NewFlagSet("depguard-gen", flag.ExitOnError)
	root := fl.String("root", ".", "project root containing the lockfiles")
	out := fl.String("out", "depguard.baseline.json", "output baseline path")
	sites := fl.String("site-packages", "", "comma-separated site-packages dirs (default: ask the interpreter)")
	pyBin := fl.String("python", "", "python interpreter (default: <root>/.venv/bin/python, then python3)")
	signKey := fl.String("sign-key", "", "ed25519 private key (PKCS#8 PEM) used to sign the baseline")
	workers := fl.Int("workers", runtime.NumCPU(), "parallel hashing workers")
	strict := fl.Bool("strict", false, "exit non-zero if any locked package is missing/mismatched on disk")
	_ = fl.Parse(os.Args[1:])

	rootAbs, err := filepath.Abs(*root)
	must(err)
	rootAbs, err = filepath.EvalSymlinks(rootAbs)
	must(err)

	var jobs []job
	var warns []string
	seen := map[string]bool{}
	found := false

	// ---- Python ------------------------------------------------------
	var pyRefs []pkgRef
	if refs, w := parseRequirements(filepath.Join(rootAbs, "requirements.txt")); refs != nil || w != nil {
		pyRefs, warns, found = append(pyRefs, refs...), append(warns, w...), true
	}
	if refs := parsePoetryLock(filepath.Join(rootAbs, "poetry.lock")); refs != nil {
		pyRefs, found = append(pyRefs, refs...), true
	}
	if len(pyRefs) > 0 {
		var siteDirs []string
		if *sites != "" {
			siteDirs = strings.Split(*sites, ",")
		} else {
			siteDirs, err = detectSitePackages(pickPython(*pyBin, rootAbs))
			if err != nil {
				warns = append(warns, "python: cannot detect site-packages: "+err.Error())
			}
		}
		for i, s := range siteDirs {
			if r, e := filepath.EvalSymlinks(s); e == nil {
				siteDirs[i], _ = filepath.Abs(r)
			}
		}
		for _, ref := range pyRefs {
			site, distInfo, installed, ok := findDistInfo(siteDirs, ref)
			if !ok {
				if installed != "" {
					warns = append(warns, fmt.Sprintf("python: %s locked at %s but %s installed (version drift) - not baselined", ref.Name, ref.Version, installed))
				} else {
					warns = append(warns, fmt.Sprintf("python: %s==%s not installed - not baselined", ref.Name, ref.Version))
				}
				continue
			}
			for _, p := range readRecord(site, distInfo) {
				addFile(&jobs, seen, p, ref)
			}
		}
	}

	// ---- Node.js -----------------------------------------------------
	nodePkgs, err := parseNodeLock(rootAbs)
	must(err)
	if nodePkgs != nil {
		found = true
	}
	for _, np := range nodePkgs {
		if _, e := os.Stat(np.dir); e != nil {
			warns = append(warns, fmt.Sprintf("npm: %s@%s not on disk (%s) - not baselined", np.ref.Name, np.ref.Version, np.dir))
			continue
		}
		_ = filepath.WalkDir(np.dir, func(p string, d fs.DirEntry, werr error) error {
			if werr != nil {
				return nil
			}
			if d.IsDir() {
				if p != np.dir && d.Name() == "node_modules" {
					return filepath.SkipDir // nested packages have their own lock entries
				}
				return nil
			}
			if isExecutable(d.Name()) {
				addFile(&jobs, seen, p, np.ref)
			}
			return nil
		})
	}

	if !found {
		fatalf("no supported lockfile found in %s (requirements.txt, poetry.lock, package-lock.json)", rootAbs)
	}

	files, hw := hashAll(jobs, *workers)
	warns = append(warns, hw...)

	b := &baseline.Baseline{
		SchemaVersion: baseline.SchemaVersion,
		GeneratedAt:   time.Now().UTC().Format(time.RFC3339),
		Root:          rootAbs,
		Files:         files,
		Warnings:      warns,
	}
	var priv ed25519.PrivateKey
	if *signKey != "" {
		priv, err = baseline.LoadPrivateKey(*signKey)
		must(err)
	}
	b.Seal(priv)
	must(b.WriteFile(*out))

	fmt.Fprintf(os.Stderr, "depguard-gen: %d files baselined -> %s (merkle %s, signed=%v)\n", len(files), *out, b.MerkleRoot[:16], priv != nil)
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "  warning:", w)
	}
	if *strict && len(warns) > 0 {
		os.Exit(2)
	}
}

func runKeygen(args []string) {
	fl := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fl.String("out", ".", "directory for depguard.key / depguard.pub")
	_ = fl.Parse(args)
	must(os.MkdirAll(*dir, 0o700))
	priv, pub, err := baseline.GenerateKeyPair(*dir)
	must(err)
	fmt.Printf("private key: %s (keep offline/CI-secret)\npublic key:  %s\n", priv, pub)
}

// ---------------------------------------------------------------- python

var reqRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.!+*-]+)`)
var tomlKV = regexp.MustCompile(`^(name|version)\s*=\s*"([^"]*)"\s*$`)
var nameSep = regexp.MustCompile(`[-_.]+`)

func normName(s string) string { return nameSep.ReplaceAllString(strings.ToLower(s), "-") }
func normVer(s string) string  { return strings.TrimPrefix(strings.ToLower(s), "v") }

func parseRequirements(path string) ([]pkgRef, []string) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	var refs []pkgRef
	var warns []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if i := strings.Index(line, ";"); i >= 0 { // environment markers
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		if m := reqRe.FindStringSubmatch(line); m != nil {
			refs = append(refs, pkgRef{m[1], m[2], "pypi"})
		} else {
			warns = append(warns, "requirements.txt: unpinned/unsupported line ignored: "+line)
		}
	}
	return refs, warns
}

func parsePoetryLock(path string) []pkgRef {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var refs []pkgRef
	cur := pkgRef{Ecosystem: "pypi"}
	have, reading := false, false
	flush := func() {
		if have && cur.Name != "" && cur.Version != "" {
			refs = append(refs, cur)
		}
		cur = pkgRef{Ecosystem: "pypi"}
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "[[package]]":
			flush()
			have, reading = true, true
		case strings.HasPrefix(line, "["):
			reading = false
		case reading:
			if m := tomlKV.FindStringSubmatch(line); m != nil {
				if m[1] == "name" {
					cur.Name = m[2]
				} else {
					cur.Version = m[2]
				}
			}
		}
	}
	flush()
	if refs == nil {
		refs = []pkgRef{}
	}
	return refs
}

func pickPython(flagVal, root string) string {
	if flagVal != "" {
		return flagVal
	}
	if v := filepath.Join(root, ".venv", "bin", "python"); fileExists(v) {
		return v
	}
	return "python3"
}

func detectSitePackages(py string) ([]string, error) {
	out, err := exec.Command(py, "-c", "import sysconfig;p=sysconfig.get_paths();print(p['purelib']);print(p['platlib'])").Output()
	if err != nil {
		return nil, err
	}
	uniq := map[string]bool{}
	var res []string
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if l = strings.TrimSpace(l); l != "" && !uniq[l] {
			uniq[l] = true
			res = append(res, l)
		}
	}
	return res, nil
}

// findDistInfo locates <name>-<version>.dist-info. On a version mismatch it
// returns ok=false with the installed version (drift).
func findDistInfo(sites []string, ref pkgRef) (site, dir, installed string, ok bool) {
	want := normName(ref.Name)
	for _, s := range sites {
		ents, err := os.ReadDir(s)
		if err != nil {
			continue
		}
		for _, e := range ents {
			n := e.Name()
			if !strings.HasSuffix(n, ".dist-info") {
				continue
			}
			base := strings.TrimSuffix(n, ".dist-info")
			i := strings.LastIndex(base, "-")
			if i <= 0 || normName(base[:i]) != want {
				continue
			}
			if v := base[i+1:]; normVer(v) == normVer(ref.Version) {
				return s, filepath.Join(s, n), v, true
			} else {
				installed, site = v, s
			}
		}
	}
	return site, "", installed, false
}

// readRecord returns absolute paths of executable files listed in RECORD.
func readRecord(site, distInfo string) []string {
	f, err := os.Open(filepath.Join(distInfo, "RECORD"))
	if err != nil {
		return nil
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	var res []string
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(rec) == 0 {
			continue
		}
		abs := filepath.Join(site, filepath.FromSlash(rec[0]))
		if !strings.HasPrefix(abs, site+string(filepath.Separator)) || !isExecutable(abs) {
			continue
		}
		res = append(res, abs)
	}
	return res
}

// ---------------------------------------------------------------- node

type lockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Link    bool   `json:"link"`
}
type v1Dep struct {
	Version      string            `json:"version"`
	Dependencies map[string]*v1Dep `json:"dependencies"`
}
type lockfile struct {
	Packages     map[string]lockPkg `json:"packages"`
	Dependencies map[string]*v1Dep  `json:"dependencies"`
}

func parseNodeLock(root string) ([]nodePkg, error) {
	data, err := os.ReadFile(filepath.Join(root, "package-lock.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var lf lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("package-lock.json: %w", err)
	}
	out := []nodePkg{}
	if len(lf.Packages) > 0 { // lockfileVersion 2/3
		const nm = "node_modules/"
		for key, p := range lf.Packages {
			if key == "" || p.Link || !strings.Contains(key, nm) {
				continue
			}
			name := p.Name
			if name == "" {
				name = key[strings.LastIndex(key, nm)+len(nm):]
			}
			out = append(out, nodePkg{filepath.Join(root, filepath.FromSlash(key)), pkgRef{name, p.Version, "npm"}})
		}
	} else { // lockfileVersion 1
		walkV1(filepath.Join(root, "node_modules"), lf.Dependencies, &out)
	}
	return out, nil
}

func walkV1(base string, deps map[string]*v1Dep, out *[]nodePkg) {
	for name, d := range deps {
		dir := filepath.Join(base, filepath.FromSlash(name))
		*out = append(*out, nodePkg{dir, pkgRef{name, d.Version, "npm"}})
		walkV1(filepath.Join(dir, "node_modules"), d.Dependencies, out)
	}
}

// ---------------------------------------------------------------- hashing

func addFile(jobs *[]job, seen map[string]bool, p string, ref pkgRef) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return
	}
	if real, err = filepath.Abs(real); err != nil {
		return
	}
	if fi, err := os.Stat(real); err != nil || !fi.Mode().IsRegular() || seen[real] {
		return
	}
	seen[real] = true
	*jobs = append(*jobs, job{real, ref})
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func hashAll(jobs []job, workers int) (map[string]baseline.Entry, []string) {
	if workers < 1 {
		workers = 1
	}
	files := make(map[string]baseline.Entry, len(jobs))
	var warns []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	ch := make(chan job)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				sum, err := hashFile(j.path)
				mu.Lock()
				if err != nil {
					warns = append(warns, "cannot hash "+j.path+": "+err.Error())
				} else {
					files[j.path] = baseline.Entry{Package: j.ref.Name, Version: j.ref.Version, Ecosystem: j.ref.Ecosystem, SHA256: sum}
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		ch <- j
	}
	close(ch)
	wg.Wait()
	return files, warns
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}
func fatalf(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "depguard-gen: "+f+"\n", a...)
	os.Exit(1)
}
