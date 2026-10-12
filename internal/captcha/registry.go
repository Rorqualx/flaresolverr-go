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

// ProviderOptions is what a provider needs to be constructed. The zero value of
// BaseURL and PollInterval selects the provider's own defaults.
type ProviderOptions struct {
	APIKey       string
	Timeout      time.Duration
	BaseURL      string        // Override for testing and self-hosted gateways
	PollInterval time.Duration // Override for testing
}

// ProviderFactory creates a CaptchaSolver from the given options.
type ProviderFactory func(opts ProviderOptions) CaptchaSolver

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
