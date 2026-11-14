// depguard-sensor: Tier-B user-space daemon. Loads the eBPF probe, receives
// "code file opened" events, resolves the path inside the target's mount
// namespace (/proc/<pid>/root), checks it against depguard.baseline.json and emits
// JSON alerts. In --mode=enforce the probe has SIGSTOPped the caller; we
// SIGCONT on success and SIGKILL on violation.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -cflags "-O2 -g -Wall" bpf openat.bpf.c --

import (
	"container/list"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/depguard/depguard/pkg/baseline"
)

const atFDCWD = -100

var thirdParty = []string{"/site-packages/", "/dist-packages/", "/node_modules/"}

type rawEvent struct {
	tgid, tid uint32
	dfd       int32
	comm      string
	path      string
}

type alert struct {
	Timestamp string  `json:"timestamp"`
	Agent     string  `json:"agent"`
	Type      string  `json:"type"`
	Severity  string  `json:"severity"`
	Mode      string  `json:"mode"`
	Action    string  `json:"action"`
	PID       uint32  `json:"pid"`
	TID       uint32  `json:"tid"`
	Process   string  `json:"process"`
	Host      string  `json:"host"`
	File      string  `json:"file"`
	Package   string  `json:"package,omitempty"`
	Version   string  `json:"version,omitempty"`
	Expected  *string `json:"expected_sha256"`
	Actual    *string `json:"actual_sha256"`
}

// dgConfig mirrors struct dg_config in openat.bpf.c (8 bytes, no implicit padding).
type dgConfig struct {
	WatchAll uint8
	Enforce  uint8
	Pad      uint16
	SelfTgid uint32
}

type verRec struct{ version, file string }

type agent struct {
	base       *baseline.Baseline
	enforce    bool
	firstParty []string
	allow      []string
	hostname   string

	cache *lru

	mu     sync.Mutex
	loaded map[uint32]map[string]verRec

	outMu sync.Mutex
	out   io.Writer
}

func main() {
	var (
		basePath  = flag.String("baseline", "depguard.baseline.json", "baseline file")
		mode      = flag.String("mode", "audit", "audit | enforce")
		pids      = flag.String("pid", "", "comma-separated PIDs to monitor (children are followed)")
		cgroups   = flag.String("cgroup", "", "comma-separated cgroup v2 dirs to monitor (containers)")
		all       = flag.Bool("all", false, "monitor every process on the host (audit only recommended)")
		pubKey    = flag.String("pubkey", "", "ed25519 public key (PEM) to verify the baseline signature")
		logPath   = flag.String("log", "", "append JSON alerts to this file (default stdout)")
		firstP    = flag.String("first-party", "", "extra first-party roots, comma-separated")
		allowDirs = flag.String("allow", "/usr/lib,/lib,/usr/lib64,/lib64,/usr/local/lib,/usr/libexec", "system dirs allowed without baseline entry")
		workers   = flag.Int("workers", 4, "verification workers")
		cacheSize = flag.Int("cache", 65536, "verified-hash LRU entries")
	)
	flag.Parse()
	if *mode != "audit" && *mode != "enforce" {
		fatal("mode must be audit or enforce")
	}

	b, err := baseline.Load(*basePath)
	check(err)
	var pub ed25519.PublicKey
	if *pubKey != "" {
		pub, err = baseline.LoadPublicKey(*pubKey)
		check(err)
	}
	check(b.Verify(pub)) // merkle consistency (+ signature when --pubkey given)

	out := io.Writer(os.Stdout)
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		check(err)
		defer f.Close()
		out = f
	}
	host, _ := os.Hostname()
	a := &agent{
		base: b, enforce: *mode == "enforce", hostname: host, cache: newLRU(*cacheSize),
		loaded: map[uint32]map[string]verRec{}, out: out,
		firstParty: splitList(b.Root + "," + *firstP), allow: splitList(*allowDirs),
	}

	check(rlimit.RemoveMemlock())
	var objs bpfObjects
	check(loadBpfObjects(&objs, nil))
	defer objs.Close()
	check(objs.ConfigMap.Put(uint32(0), dgConfig{WatchAll: boolU8(*all), Enforce: boolU8(a.enforce), SelfTgid: uint32(os.Getpid())}))

	for _, s := range splitList(*pids) {
		n, err := strconv.ParseUint(s, 10, 32)
		check(err)
		check(objs.TargetPids.Put(uint32(n), uint8(1)))
	}
	for _, c := range splitList(*cgroups) {
		var st syscall.Stat_t
		check(syscall.Stat(c, &st))
		check(objs.TargetCgroups.Put(st.Ino, uint8(1))) // cgroup v2 id == inode of its directory
	}
	if !*all && *pids == "" && *cgroups == "" {
		fatal("nothing to monitor: pass --pid, --cgroup or --all")
	}

	l1, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TpOpenat, nil)
	check(err)
	defer l1.Close()
	if l2, err := link.Tracepoint("syscalls", "sys_enter_openat2", objs.TpOpenat2, nil); err == nil {
		defer l2.Close()
	} else {
		fmt.Fprintln(os.Stderr, "depguard-sensor: openat2 tracepoint unavailable:", err)
	}
	l3, err := link.Tracepoint("sched", "sched_process_fork", objs.TpFork, nil)
	check(err)
	defer l3.Close()

	rd, err := ringbuf.NewReader(objs.Events)
	check(err)

	// Never leave a stopped process behind if we exit.
	pending := &pendingSet{m: map[uint32]int{}}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		pending.resumeAll()
		rd.Close()
	}()

	fmt.Fprintf(os.Stderr, "depguard-sensor: %d baseline files, mode=%s, watching...\n", len(b.Files), *mode)
	ch := make(chan rawEvent, 4096)
	var wg sync.WaitGroup
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ev := range ch {
				v := a.inspect(ev)
				if a.enforce {
					if v {
						_ = syscall.Kill(int(ev.tgid), syscall.SIGKILL)
					} else {
						_ = syscall.Kill(int(ev.tgid), syscall.SIGCONT)
					}
					pending.done(ev.tgid)
				}
			}
		}()
	}
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			continue
		}
		ev, err := parseEvent(rec.RawSample)
		if err != nil {
			continue
		}
		if a.enforce {
			pending.add(ev.tgid)
		}
		ch <- ev
	}
	close(ch)
	wg.Wait()
	var dropped uint64
	var zero uint32
	if err := objs.Dropped.Lookup(&zero, &dropped); err == nil && dropped > 0 {
		fmt.Fprintf(os.Stderr, "depguard-sensor: WARNING %d events dropped (ring buffer full); those loads were NOT verified\n", dropped)
	}
}

// ---------------------------------------------------------------- inspection

// inspect returns true when the event is a violation.
func (a *agent) inspect(ev rawEvent) bool {
	procRoot := fmt.Sprintf("/proc/%d/root", ev.tgid)
	p := ev.path
	if !path.IsAbs(p) {
		var base string
		var err error
		if ev.dfd == atFDCWD {
			base, err = os.Readlink(fmt.Sprintf("/proc/%d/cwd", ev.tgid))
		} else {
			base, err = os.Readlink(fmt.Sprintf("/proc/%d/fd/%d", ev.tgid, ev.dfd))
		}
		if err != nil {
			return false // process/fd already gone
		}
		p = path.Join(base, p)
	}
	real, hostPath, err := resolveInRoot(procRoot, path.Clean(p))
	if err != nil {
		return false // ENOENT probe (e.g. Python searching sys.path): nothing was loaded
	}
	fi, err := os.Stat(hostPath)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}

	if entry, ok := a.base.Files[real]; ok {
		okHash, actual := a.verify(hostPath, fi, entry.SHA256)
		if !okHash {
			a.emit(ev, "CACHE_TAMPERING", "high", real, &entry.SHA256, actual, &entry)
			return true
		}
		return a.trackVersion(ev, real, &entry)
	}
	if !hasAny(real, thirdParty) && (underAny(real, a.firstParty) || underAny(real, a.allow)) {
		return false
	}
	actual, _ := hashFile(hostPath)
	a.emit(ev, "SHADOW_DEPENDENCY", "high", real, nil, strPtr(actual), nil)
	return true
}

func (a *agent) trackVersion(ev rawEvent, real string, e *baseline.Entry) bool {
	key := e.Ecosystem + ":" + e.Package
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.loaded) > 8192 {
		a.loaded = map[uint32]map[string]verRec{}
	}
	m := a.loaded[ev.tgid]
	if m == nil {
		m = map[string]verRec{}
		a.loaded[ev.tgid] = m
	}
	prev, seen := m[key]
	if !seen {
		m[key] = verRec{e.Version, real}
		return false
	}
	if prev.version != e.Version {
		pv := prev.version
		a.emitLocked(ev, "VERSION_CONFLICT", "medium", real, &pv, &e.Version, e) // never kills: legit for nested npm trees
	}
	return false
}

func (a *agent) verify(hostPath string, fi os.FileInfo, expected string) (bool, *string) {
	sig := statSig(fi)
	if a.cache.hit(hostPath, sig) {
		return true, &expected
	}
	actual, err := hashFile(hostPath)
	if err != nil {
		return false, nil
	}
	if actual == expected {
		a.cache.put(hostPath, sig)
	}
	return actual == expected, &actual
}

func (a *agent) emit(ev rawEvent, typ, sev, file string, exp, act *string, e *baseline.Entry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.emitLocked(ev, typ, sev, file, exp, act, e)
}

func (a *agent) emitLocked(ev rawEvent, typ, sev, file string, exp, act *string, e *baseline.Entry) {
	al := alert{
		Timestamp: time.Now().UTC().Format("2006-01-02T15:04:05.000Z07:00"), Agent: "depguard-ebpf",
		Type: typ, Severity: sev, Mode: map[bool]string{true: "enforce", false: "audit"}[a.enforce],
		Action: "logged", PID: ev.tgid, TID: ev.tid, Process: ev.comm, Host: a.hostname, File: file,
		Expected: exp, Actual: act,
	}
	if a.enforce && typ != "VERSION_CONFLICT" {
		al.Action = "killed"
	}
	if e != nil {
		al.Package, al.Version = e.Package, e.Version
	}
	line, _ := json.Marshal(al)
	a.outMu.Lock()
	fmt.Fprintf(a.out, "%s\n", line)
	a.outMu.Unlock()
}

// resolveInRoot resolves p as the process in `root` would (symlinks relative to
// that root), returning the container-view real path and a host-accessible path.
func resolveInRoot(root, p string) (string, string, error) {
	cur := "/"
	parts := strings.Split(strings.Trim(p, "/"), "/")
	links := 0
	for i := 0; i < len(parts); i++ {
		part := parts[i]
		switch part {
		case "", ".":
			continue
		case "..":
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, part)
		fi, err := os.Lstat(root + next)
		if err != nil {
			return "", "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if links++; links > 40 {
				return "", "", errors.New("too many symlinks")
			}
			t, err := os.Readlink(root + next)
			if err != nil {
				return "", "", err
			}
			if path.IsAbs(t) {
				cur = "/"
			}
			parts = append(strings.Split(strings.Trim(t, "/"), "/"), parts[i+1:]...)
			i = -1
			continue
		}
		cur = next
	}
	return cur, root + cur, nil
}

// ------------------------------------------------------------------- helpers

func parseEvent(b []byte) (rawEvent, error) {
	if len(b) < 34 {
		return rawEvent{}, errors.New("short event")
	}
	return rawEvent{
		tgid: binary.NativeEndian.Uint32(b[0:4]),
		tid:  binary.NativeEndian.Uint32(b[4:8]),
		dfd:  int32(binary.NativeEndian.Uint32(b[8:12])),
		comm: cstr(b[16:32]),
		path: cstr(b[32:]),
	}, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func hashFile(p string) (string, error) {
	f, err := os.Open(p)
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

func statSig(fi os.FileInfo) string {
	st := fi.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%d:%d:%d", st.Dev, st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano())
}

func underAny(p string, roots []string) bool {
	for _, r := range roots {
		r = strings.TrimRight(r, "/")
		if r != "" && (p == r || strings.HasPrefix(p, r+"/")) {
			return true
		}
	}
	return false
}
func hasAny(p string, marks []string) bool {
	for _, m := range marks {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}
func splitList(s string) []string {
	var r []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			r = append(r, x)
		}
	}
	return r
}
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
func boolU8(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}
func check(err error) {
	if err != nil {
		fatal(err.Error())
	}
}
func fatal(m string) { fmt.Fprintln(os.Stderr, "depguard-sensor:", m); os.Exit(1) }

// ---- tiny LRU keyed by host path, value = stat signature of last verified state
type lru struct {
	mu  sync.Mutex
	max int
	ll  *list.List
	m   map[string]*list.Element
}
type lruItem struct{ key, sig string }

func newLRU(n int) *lru { return &lru{max: n, ll: list.New(), m: map[string]*list.Element{}} }
func (c *lru) hit(k, sig string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok && e.Value.(*lruItem).sig == sig {
		c.ll.MoveToFront(e)
		return true
	}
	return false
}
func (c *lru) put(k, sig string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.m[k]; ok {
		e.Value.(*lruItem).sig = sig
		c.ll.MoveToFront(e)
		return
	}
	c.m[k] = c.ll.PushFront(&lruItem{k, sig})
	for c.ll.Len() > c.max {
		last := c.ll.Back()
		delete(c.m, last.Value.(*lruItem).key)
		c.ll.Remove(last)
	}
}

// ---- stopped-process bookkeeping (enforce mode)
type pendingSet struct {
	mu sync.Mutex
	m  map[uint32]int
}

func (p *pendingSet) add(pid uint32)  { p.mu.Lock(); p.m[pid]++; p.mu.Unlock() }
func (p *pendingSet) done(pid uint32) {
	p.mu.Lock()
	if p.m[pid]--; p.m[pid] <= 0 {
		delete(p.m, pid)
	}
	p.mu.Unlock()
}
func (p *pendingSet) resumeAll() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for pid := range p.m {
		_ = syscall.Kill(int(pid), syscall.SIGCONT)
	}
}
