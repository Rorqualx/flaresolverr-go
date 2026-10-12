package browser

import (
	"bytes"
	"fmt"
	"strconv"
	"time"

	"github.com/rs/zerolog/log"
)

// Memory monitoring.
//
// MAX_MEMORY_MB is compared against the memory the whole service is using:
// this process plus every Chrome process it launched (pool browsers, the
// session browser, dedicated browsers). The Go heap alone, which is what used
// to be measured, is a few megabytes and never approached the limit, so the
// monitor could not protect against the thing that actually grows.

const (
	// memoryCheckInterval is how often memory usage is sampled.
	memoryCheckInterval = 30 * time.Second

	// memoryRecycleCooldown is the minimum time between two memory-pressure
	// recycles. Recycling only frees what idle pool browsers were holding; if
	// usage is still over the limit afterwards (open sessions, requests in
	// flight) recycling again every tick would just churn browsers.
	memoryRecycleCooldown = 5 * time.Minute
)

// memorySample is one reading of the service's memory usage.
type memorySample struct {
	bytes  uint64
	source string // where the number came from, for logs
}

// memoryReader returns the service's current memory usage. ok is false when
// the platform offers no way to measure it.
type memoryReader func() (sample memorySample, ok bool)

// checkMemory takes one sample and recycles idle browsers if usage is over the
// limit and the cooldown has passed. lastRecycle is the time of the previous
// memory-pressure recycle (zero if none). It returns the updated lastRecycle
// and whether the platform supports measurement at all.
func (p *Pool) checkMemory(now time.Time, lastRecycle time.Time) (time.Time, bool) {
	sample, ok := p.readMemory()
	if !ok {
		return lastRecycle, false
	}

	usedMB := sample.bytes / (1024 * 1024)
	limitMB := uint64(p.config.MaxMemoryMB)

	log.Debug().
		Uint64("used_mb", usedMB).
		Uint64("max_mb", limitMB).
		Str("source", sample.source).
		Msg("Memory stats")

	if usedMB <= limitMB {
		return lastRecycle, true
	}

	if !lastRecycle.IsZero() && now.Sub(lastRecycle) < memoryRecycleCooldown {
		log.Debug().
			Uint64("used_mb", usedMB).
			Uint64("max_mb", limitMB).
			Dur("cooldown_remaining", memoryRecycleCooldown-now.Sub(lastRecycle)).
			Msg("Memory still over limit, waiting for recycle cooldown")
		return lastRecycle, true
	}

	log.Warn().
		Uint64("used_mb", usedMB).
		Uint64("max_mb", limitMB).
		Str("source", sample.source).
		Msg("Memory threshold exceeded, recycling idle browsers")

	// Idle browsers are replaced now; ones in use are flagged and replaced
	// when released, so no request or session loses its browser.
	p.recycleAll()
	return now, true
}

// parseCgroupWorkingSet computes working-set memory from a cgroup's usage and
// its memory.stat contents: usage minus inactive file cache, which the kernel
// drops freely and which would otherwise make a container that has merely read
// a lot of files look like it is out of memory. inactiveKey is "inactive_file"
// for cgroup v2 and "total_inactive_file" for v1.
func parseCgroupWorkingSet(usage, stat []byte, inactiveKey string) (uint64, error) {
	used, err := strconv.ParseUint(string(bytes.TrimSpace(usage)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse cgroup memory usage: %w", err)
	}

	for _, line := range bytes.Split(stat, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) != 2 || string(fields[0]) != inactiveKey {
			continue
		}
		inactive, err := strconv.ParseUint(string(fields[1]), 10, 64)
		if err != nil {
			break // unreadable stat: fall back to raw usage
		}
		if inactive < used {
			return used - inactive, nil
		}
		return 0, nil
	}
	return used, nil
}

// procStat is the part of /proc/<pid>/stat the process-tree fallback needs.
type procStat struct {
	pid      int
	ppid     int
	rssPages uint64
}

// parseProcStat parses one /proc/<pid>/stat line. The command name (field 2)
// is in parentheses and may itself contain spaces and parentheses, so fields
// are counted from the last ')'.
func parseProcStat(data []byte) (procStat, error) {
	open := bytes.IndexByte(data, '(')
	closeIdx := bytes.LastIndexByte(data, ')')
	if open < 0 || closeIdx < open {
		return procStat{}, fmt.Errorf("malformed stat line")
	}

	pid, err := strconv.Atoi(string(bytes.TrimSpace(data[:open])))
	if err != nil {
		return procStat{}, fmt.Errorf("parse pid: %w", err)
	}

	// After the command: state(3) ppid(4) ... rss(24). Index 0 here is field 3.
	rest := bytes.Fields(data[closeIdx+1:])
	const ppidIdx, rssIdx = 1, 21
	if len(rest) <= rssIdx {
		return procStat{}, fmt.Errorf("stat line has %d fields after the command, need %d", len(rest), rssIdx+1)
	}

	ppid, err := strconv.Atoi(string(rest[ppidIdx]))
	if err != nil {
		return procStat{}, fmt.Errorf("parse ppid: %w", err)
	}
	rss, err := strconv.ParseUint(string(rest[rssIdx]), 10, 64)
	if err != nil {
		return procStat{}, fmt.Errorf("parse rss: %w", err)
	}
	return procStat{pid: pid, ppid: ppid, rssPages: rss}, nil
}

// sumProcessTreeRSS adds up the resident pages of root and all its descendants.
func sumProcessTreeRSS(procs []procStat, root int) (pages uint64) {
	children := make(map[int][]int, len(procs))
	rss := make(map[int]uint64, len(procs))
	for _, proc := range procs {
		children[proc.ppid] = append(children[proc.ppid], proc.pid)
		rss[proc.pid] = proc.rssPages
	}

	// Bounded walk: each pid is visited once even if /proc changed under us
	seen := make(map[int]struct{}, len(procs))
	queue := []int{root}
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		if _, dup := seen[pid]; dup {
			continue
		}
		seen[pid] = struct{}{}
		pages += rss[pid]
		queue = append(queue, children[pid]...)
	}
	return pages
}
