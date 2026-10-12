//go:build !linux

package browser

// systemMemoryReader reports that memory cannot be measured on this platform.
// The service ships as a Linux container; elsewhere (development machines) the
// memory monitor is a no-op rather than a guess.
func systemMemoryReader() (memorySample, bool) {
	return memorySample{}, false
}
