package captcha

import (
	"sort"
	"sync"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

func init() {
	// Wire dynamic captcha solver validation into the types package
	types.CaptchaSolverValidator = func(name string) bool {
		registryMu.RLock()
		defer registryMu.RUnlock()
		_, exists := registry[name]
		return exists
	}
}

// ProviderFactory creates a CaptchaSolver given an API key and timeout.
type ProviderFactory func(apiKey string, timeout time.Duration) CaptchaSolver

var (
	registryMu sync.RWMutex
	registry   = make(map[string]ProviderFactory)
)

// Register adds a provider factory to the global registry.
// Call from init() in each provider file. Panics on duplicate registration.
func Register(name string, factory ProviderFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[name]; exists {
		panic("captcha provider already registered: " + name)
	}
	registry[name] = factory
}

// GetFactory returns a provider factory by name, or nil if not found.
func GetFactory(name string) ProviderFactory {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return registry[name]
}

// Available returns all registered provider names in sorted order.
func Available() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for name := range registry {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// BuildPriorityOrder returns provider names ordered with primary first,
// followed by the remaining available providers in sorted order.
func BuildPriorityOrder(primary string, available []string) []string {
	order := make([]string, 0, len(available))
	// Primary first
	for _, name := range available {
		if name == primary {
			order = append(order, name)
			break
		}
	}
	// Then the rest
	for _, name := range available {
		if name != primary {
			order = append(order, name)
		}
	}
	return order
}
