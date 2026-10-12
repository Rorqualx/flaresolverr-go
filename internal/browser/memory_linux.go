//go:build linux

package browser

import (
	"os"
	"path/filepath"
)

// Cgroup files as seen from inside a container. On a host outside any
// container these do not exist at the cgroup root, and the process-tree
// fallback is used instead.
const (
	cgroupV2Usage = "/sys/fs/cgroup/memory.current"
	cgroupV2Stat  = "/sys/fs/cgroup/memory.stat"
	cgroupV1Usage = "/sys/fs/cgroup/memory/memory.usage_in_bytes"
	cgroupV1Stat  = "/sys/fs/cgroup/memory/memory.stat"
	cgroupV2Limit = "/sys/fs/cgroup/memory.max"
	cgroupV1Limit = "/sys/fs/cgroup/memory/memory.limit_in_bytes"
)

// containerMemoryLimit returns the memory limit set on this container. ok is
// false when there is none (or this is not a container).
func containerMemoryLimit() (limitBytes uint64, ok bool) {
	for _, path := range []string{cgroupV2Limit, cgroupV1Limit} {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if limit, ok := parseCgroupLimit(data); ok {
			return limit, true
		}
	}
	return 0, false
}

// systemMemoryReader measures the memory used by this service on Linux.
//
// Inside a container the cgroup is authoritative: it is exactly what the
// container's memory limit is enforced against, and it covers every Chrome
// process however it was started. Outside a container it falls back to the
// resident memory of this process and all its descendants.
func systemMemoryReader() (memorySample, bool) {
	if bytes, ok := readCgroup(cgroupV2Usage, cgroupV2Stat, "inactive_file"); ok {
		return memorySample{bytes: bytes, source: "cgroup v2 working set"}, true
	}
	if bytes, ok := readCgroup(cgroupV1Usage, cgroupV1Stat, "total_inactive_file"); ok {
		return memorySample{bytes: bytes, source: "cgroup v1 working set"}, true
	}
	if bytes, ok := readProcessTree(); ok {
		return memorySample{bytes: bytes, source: "process tree RSS"}, true
	}
	return memorySample{}, false
}

func readCgroup(usagePath, statPath, inactiveKey string) (uint64, bool) {
	usage, err := os.ReadFile(usagePath)
	if err != nil {
		return 0, false
	}
	// Ignore error: a missing stat file just means raw usage is reported
	stat, _ := os.ReadFile(statPath)

	bytes, err := parseCgroupWorkingSet(usage, stat, inactiveKey)
	if err != nil {
		return 0, false
	}
	return bytes, true
}

func readProcessTree() (uint64, bool) {
	statFiles, err := filepath.Glob("/proc/[0-9]*/stat")
	if err != nil || len(statFiles) == 0 {
		return 0, false
	}

	procs := make([]procStat, 0, len(statFiles))
	for _, path := range statFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			continue // process exited between the glob and the read
		}
		proc, err := parseProcStat(data)
		if err != nil {
			continue
		}
		procs = append(procs, proc)
	}

	pages := sumProcessTreeRSS(procs, os.Getpid())
	if pages == 0 {
		return 0, false
	}
	return pages * uint64(os.Getpagesize()), true
}
