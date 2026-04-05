// Package solver provides Cloudflare challenge detection and resolution.
package solver

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/rs/zerolog/log"

	"github.com/Rorqualx/flaresolverr-go/internal/selectors"
)

var (
	// ErrShadowHostNotFound indicates no shadow host element was found on the page.
	ErrShadowHostNotFound = errors.New("shadow host element not found")

	// ErrShadowRootNotAccessible indicates the shadow root could not be accessed.
	ErrShadowRootNotAccessible = errors.New("shadow root not accessible")

	// ErrCheckboxNotFound indicates no checkbox was found in the shadow DOM.
	ErrCheckboxNotFound = errors.New("checkbox not found in shadow DOM")
)

// ShadowRootTraverser provides methods for traversing closed shadow roots
// using CDP-native access. This bypasses JavaScript's closed shadow root
// restrictions by using debugger-level DOM access.
type ShadowRootTraverser struct {
	page    *rod.Page
	timeout time.Duration
}

// NewShadowRootTraverser creates a new traverser for the given page.
func NewShadowRootTraverser(page *rod.Page) *ShadowRootTraverser {
	return &ShadowRootTraverser{
		page:    page,
		timeout: 5 * time.Second,
	}
}

// WithTimeout sets the timeout for shadow root operations.
func (t *ShadowRootTraverser) WithTimeout(timeout time.Duration) *ShadowRootTraverser {
	t.timeout = timeout
	return t
}

// FindTurnstileCheckbox locates the Turnstile checkbox element, traversing
// through closed shadow roots if necessary. Uses CDP-native shadow root
// access which bypasses JavaScript restrictions.
//
// The method tries multiple strategies:
// 1. Direct shadow host -> shadow root -> checkbox
// 2. Shadow host -> shadow root -> iframe -> shadow root -> checkbox (nested)
// 3. Fallback to iframe-based checkbox location
func (t *ShadowRootTraverser) FindTurnstileCheckbox(ctx context.Context) (*rod.Element, error) {
	sel := selectors.Get()

	// Try each shadow host selector
	for _, hostSelector := range sel.ShadowHosts {
		// Check context cancellation to respect timeouts
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		element, err := t.findCheckboxViaHost(ctx, hostSelector)
		if err == nil && element != nil {
			log.Debug().
				Str("host_selector", hostSelector).
				Msg("Found checkbox via shadow host")
			return element, nil
		}
		log.Debug().
			Str("host_selector", hostSelector).
			Err(err).
			Msg("Shadow host selector did not yield checkbox")
	}

	// Try the landmark approach: find input[name="cf-turnstile-response"] and navigate to parent
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	element, err := t.findCheckboxViaLandmark(ctx)
	if err == nil && element != nil {
		log.Debug().Msg("Found checkbox via cf-turnstile-response landmark")
		return element, nil
	}

	// Check context before iframe search
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	// Try finding Turnstile iframes and checking their shadow roots
	element, err = t.findCheckboxInTurnstileIframes(ctx)
	if err == nil && element != nil {
		log.Debug().Msg("Found checkbox in Turnstile iframe shadow root")
		return element, nil
	}

	// Last resort: full DOM tree scan with pierce to find checkbox in any shadow root
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	element, err = t.findCheckboxViaFullTree(ctx)
	if err == nil && element != nil {
		log.Debug().Msg("Found checkbox via full DOM tree scan")
		return element, nil
	}

	return nil, ErrCheckboxNotFound
}

// findCheckboxViaHost attempts to find the checkbox through a shadow host element.
func (t *ShadowRootTraverser) findCheckboxViaHost(ctx context.Context, hostSelector string) (*rod.Element, error) {
	// Check if host exists
	has, _, _ := t.page.Has(hostSelector)
	if !has {
		return nil, ErrShadowHostNotFound
	}

	// Get the shadow host element with timeout
	host, err := t.page.Timeout(t.timeout).Element(hostSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get shadow host: %w", err)
	}
	defer func() {
		if err := host.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release shadow host element")
		}
	}()

	// Try to access the shadow root using CDP-native method
	// Rod's ShadowRoot() uses DOM.describeNode which can access closed shadow roots
	shadowRoot, err := host.ShadowRoot()
	if err != nil {
		log.Debug().
			Str("host_selector", hostSelector).
			Err(err).
			Msg("Failed to access shadow root (may not exist or be closed)")
		return nil, ErrShadowRootNotAccessible
	}

	if shadowRoot == nil {
		return nil, ErrShadowRootNotAccessible
	}

	// Search for checkbox within shadow root
	sel := selectors.Get()
	for _, checkboxSelector := range sel.ShadowInnerSelectors {
		checkbox, err := shadowRoot.Element(checkboxSelector)
		if err == nil && checkbox != nil {
			log.Debug().
				Str("checkbox_selector", checkboxSelector).
				Msg("Found checkbox in shadow root")
			return checkbox, nil
		}
	}

	// Check for nested iframe within shadow root
	iframe, err := shadowRoot.Element("iframe")
	if err == nil && iframe != nil {
		defer func() {
			if err := iframe.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release iframe element")
			}
		}()

		frame, err := iframe.Frame()
		if err == nil && frame != nil {
			// Look for checkbox in iframe
			for _, checkboxSelector := range sel.ShadowInnerSelectors {
				checkbox, err := frame.Timeout(t.timeout).Element(checkboxSelector)
				if err == nil && checkbox != nil {
					log.Debug().
						Str("checkbox_selector", checkboxSelector).
						Msg("Found checkbox in iframe within shadow root")
					return checkbox, nil
				}
			}

			// Check for nested shadow root in iframe
			nestedCheckbox, err := t.findCheckboxInNestedShadow(ctx, frame)
			if err == nil && nestedCheckbox != nil {
				return nestedCheckbox, nil
			}
		}
	}

	return nil, ErrCheckboxNotFound
}

// findCheckboxViaLandmark locates the Turnstile checkbox by finding the hidden
// input[name="cf-turnstile-response"] element and navigating to its parent container.
// This input is structurally required by Cloudflare for form submission, making it
// one of the most stable anchors for locating the Turnstile widget.
func (t *ShadowRootTraverser) findCheckboxViaLandmark(ctx context.Context) (*rod.Element, error) {
	const landmarkSelector = "input[name='cf-turnstile-response']"

	has, _, _ := t.page.Has(landmarkSelector)
	if !has {
		return nil, fmt.Errorf("landmark input not found")
	}

	// Find the landmark input
	input, err := t.page.Timeout(t.timeout).Element(landmarkSelector)
	if err != nil {
		return nil, fmt.Errorf("failed to get landmark input: %w", err)
	}
	defer func() {
		if err := input.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release landmark input element")
		}
	}()

	// Navigate to parent element via JS eval — the parent container typically
	// holds the shadow root containing the Turnstile iframe and checkbox
	parent, err := input.Parent()
	if err != nil {
		return nil, fmt.Errorf("failed to get landmark parent: %w", err)
	}
	defer func() {
		if err := parent.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release landmark parent element")
		}
	}()

	// Check if the parent has a shadow root
	shadowRoot, err := parent.ShadowRoot()
	if err != nil || shadowRoot == nil {
		// Try grandparent — some layouts nest the input deeper
		grandparent, gpErr := parent.Parent()
		if gpErr != nil {
			return nil, ErrShadowRootNotAccessible
		}
		defer func() {
			if err := grandparent.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release landmark grandparent element")
			}
		}()

		shadowRoot, err = grandparent.ShadowRoot()
		if err != nil || shadowRoot == nil {
			return nil, ErrShadowRootNotAccessible
		}
	}

	// Search for checkbox within the shadow root
	sel := selectors.Get()
	for _, checkboxSelector := range sel.ShadowInnerSelectors {
		checkbox, err := shadowRoot.Element(checkboxSelector)
		if err == nil && checkbox != nil {
			log.Debug().
				Str("checkbox_selector", checkboxSelector).
				Msg("Found checkbox via landmark parent shadow root")
			return checkbox, nil
		}
	}

	// Check for iframe within shadow root
	iframe, err := shadowRoot.Element("iframe")
	if err == nil && iframe != nil {
		defer func() {
			if err := iframe.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release landmark iframe element")
			}
		}()

		frame, err := iframe.Frame()
		if err == nil && frame != nil {
			for _, checkboxSelector := range sel.ShadowInnerSelectors {
				checkbox, err := frame.Timeout(t.timeout).Element(checkboxSelector)
				if err == nil && checkbox != nil {
					log.Debug().
						Str("checkbox_selector", checkboxSelector).
						Msg("Found checkbox in iframe via landmark")
					return checkbox, nil
				}
			}

			// Check nested shadow roots in the iframe
			nestedCheckbox, err := t.findCheckboxInNestedShadow(ctx, frame)
			if err == nil && nestedCheckbox != nil {
				return nestedCheckbox, nil
			}
		}
	}

	return nil, ErrCheckboxNotFound
}

// findCheckboxInNestedShadow searches for checkbox in nested shadow roots within a frame.
// Includes a maximum depth limit to prevent infinite recursion in deeply nested shadow roots.
func (t *ShadowRootTraverser) findCheckboxInNestedShadow(ctx context.Context, frame *rod.Page) (*rod.Element, error) {
	sel := selectors.Get()

	// Look for shadow hosts within the frame
	for _, hostSelector := range sel.ShadowHosts {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		has, _, _ := frame.Has(hostSelector)
		if !has {
			continue
		}

		host, err := frame.Timeout(t.timeout).Element(hostSelector)
		if err != nil {
			continue
		}

		// Use inline function with defer to ensure proper release after ShadowRoot check
		shadowRoot, err := func() (*rod.Element, error) {
			defer func() {
				if releaseErr := host.Release(); releaseErr != nil {
					log.Debug().Err(releaseErr).Msg("Failed to release nested shadow host element")
				}
			}()
			return host.ShadowRoot()
		}()
		if err != nil || shadowRoot == nil {
			continue
		}

		for _, checkboxSelector := range sel.ShadowInnerSelectors {
			checkbox, err := shadowRoot.Element(checkboxSelector)
			if err == nil && checkbox != nil {
				log.Debug().
					Str("checkbox_selector", checkboxSelector).
					Msg("Found checkbox in nested shadow root")
				return checkbox, nil
			}
		}
	}

	return nil, ErrCheckboxNotFound
}

// findCheckboxInTurnstileIframes searches for the checkbox in Turnstile iframes.
// Maximum of 20 iframes are checked to prevent resource exhaustion.
func (t *ShadowRootTraverser) findCheckboxInTurnstileIframes(ctx context.Context) (*rod.Element, error) {
	const maxIframesToCheck = 20

	sel := selectors.Get()

	iframes, err := t.page.Elements("iframe")
	if err != nil {
		return nil, fmt.Errorf("failed to get iframes: %w", err)
	}
	defer func() {
		for _, iframe := range iframes {
			if err := iframe.Release(); err != nil {
				log.Debug().Err(err).Msg("Failed to release iframe element in cleanup")
			}
		}
	}()

	iframesToCheck := iframes
	if len(iframesToCheck) > maxIframesToCheck {
		iframesToCheck = iframesToCheck[:maxIframesToCheck]
		log.Debug().Int("total", len(iframes)).Int("checking", maxIframesToCheck).Msg("Limiting iframe check count")
	}

	for _, iframe := range iframesToCheck {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		src, err := iframe.Attribute("src")
		if err != nil || src == nil {
			continue
		}

		// Check if this is a Turnstile iframe
		if !containsTurnstilePattern(*src, sel.TurnstileFramePattern) {
			continue
		}

		frame, err := iframe.Frame()
		if err != nil {
			continue
		}

		// Look for shadow hosts in the Turnstile iframe
		for _, hostSelector := range sel.ShadowHosts {
			has, _, _ := frame.Has(hostSelector)
			if !has {
				continue
			}

			host, err := frame.Timeout(t.timeout).Element(hostSelector)
			if err != nil {
				continue
			}

			// Use inline function with defer to ensure proper release after ShadowRoot check
			shadowRoot, err := func() (*rod.Element, error) {
				defer func() {
					if releaseErr := host.Release(); releaseErr != nil {
						log.Debug().Err(releaseErr).Msg("Failed to release Turnstile iframe shadow host element")
					}
				}()
				return host.ShadowRoot()
			}()
			if err != nil || shadowRoot == nil {
				continue
			}

			for _, checkboxSelector := range sel.ShadowInnerSelectors {
				checkbox, err := shadowRoot.Element(checkboxSelector)
				if err == nil && checkbox != nil {
					log.Debug().
						Str("frame_src", *src).
						Str("checkbox_selector", checkboxSelector).
						Msg("Found checkbox in Turnstile iframe shadow root")
					return checkbox, nil
				}
			}
		}

		// Also try direct checkbox search without shadow root
		for _, checkboxSelector := range sel.ShadowInnerSelectors {
			checkbox, err := frame.Timeout(t.timeout).Element(checkboxSelector)
			if err == nil && checkbox != nil {
				log.Debug().
					Str("frame_src", *src).
					Str("checkbox_selector", checkboxSelector).
					Msg("Found checkbox directly in Turnstile iframe")
				return checkbox, nil
			}
		}
	}

	return nil, ErrCheckboxNotFound
}

// findCheckboxViaFullTree uses DOM.getDocument with depth:-1 and pierce:true to get
// the entire DOM tree including closed shadow roots, then walks it looking for
// checkbox elements within Turnstile-related subtrees. This is the last resort
// when all selector-based approaches fail.
func (t *ShadowRootTraverser) findCheckboxViaFullTree(ctx context.Context) (*rod.Element, error) {
	const maxNodes = 50000

	depth := -1
	result, err := proto.DOMGetDocument{
		Depth:  &depth,
		Pierce: true,
	}.Call(t.page)
	if err != nil {
		return nil, fmt.Errorf("failed to get full DOM tree: %w", err)
	}

	if result == nil || result.Root == nil {
		return nil, fmt.Errorf("DOM tree is empty")
	}

	// Walk the tree to find checkbox backend node IDs within Turnstile-related subtrees
	var checkboxNodeID proto.DOMBackendNodeID
	nodesVisited := 0
	found := false

	var walkNode func(node *proto.DOMNode, inTurnstileContext bool)
	walkNode = func(node *proto.DOMNode, inTurnstileContext bool) {
		if found || node == nil {
			return
		}

		// Check context cancellation periodically
		nodesVisited++
		if nodesVisited > maxNodes {
			return
		}
		if nodesVisited%1000 == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

		// Check if this node is Turnstile-related (activates context for children)
		isTurnstile := inTurnstileContext
		if !isTurnstile {
			isTurnstile = isNodeTurnstileRelated(node)
		}

		// If we're in a Turnstile context, check if this node is a checkbox
		if isTurnstile && isNodeCheckbox(node) {
			checkboxNodeID = node.BackendNodeID
			found = true
			return
		}

		// Walk shadow roots (these are the closed roots we can see via pierce)
		for _, shadow := range node.ShadowRoots {
			walkNode(shadow, isTurnstile)
			if found {
				return
			}
		}

		// Walk content document (for iframes)
		if node.ContentDocument != nil {
			walkNode(node.ContentDocument, isTurnstile)
			if found {
				return
			}
		}

		// Walk template content
		if node.TemplateContent != nil {
			walkNode(node.TemplateContent, isTurnstile)
			if found {
				return
			}
		}

		// Walk children
		for _, child := range node.Children {
			walkNode(child, isTurnstile)
			if found {
				return
			}
		}
	}

	walkNode(result.Root, false)

	if !found {
		return nil, ErrCheckboxNotFound
	}

	// Resolve the found node into an interactive element
	resolveResult, err := proto.DOMResolveNode{
		BackendNodeID: checkboxNodeID,
	}.Call(t.page)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve checkbox node: %w", err)
	}

	element, err := t.page.ElementFromObject(resolveResult.Object)
	if err != nil {
		return nil, fmt.Errorf("failed to create element from resolved node: %w", err)
	}

	log.Info().
		Int("nodes_visited", nodesVisited).
		Msg("Found Turnstile checkbox via full DOM tree scan")
	return element, nil
}

// isNodeTurnstileRelated checks if a DOM node is related to Cloudflare Turnstile.
func isNodeTurnstileRelated(node *proto.DOMNode) bool {
	if node == nil {
		return false
	}

	localName := node.LocalName

	// Check for Turnstile custom element
	if localName == "cf-turnstile" {
		return true
	}

	// Check attributes (flat array: [name1, value1, name2, value2, ...])
	for i := 0; i+1 < len(node.Attributes); i += 2 {
		name := node.Attributes[i]
		value := node.Attributes[i+1]

		switch name {
		case "class":
			if contains(value, "cf-turnstile") || contains(value, "turnstile") {
				return true
			}
		case "id":
			if contains(value, "turnstile") || contains(value, "cf-challenge") {
				return true
			}
		case "data-sitekey", "data-cf-turnstile":
			return true
		case "name":
			if value == "cf-turnstile-response" {
				return true
			}
		case "src":
			if contains(value, "challenges.cloudflare.com") {
				return true
			}
		}
	}

	return false
}

// isNodeCheckbox checks if a DOM node represents a checkbox element.
func isNodeCheckbox(node *proto.DOMNode) bool {
	const elementNode = 1
	if node == nil || node.NodeType != elementNode {
		return false
	}

	localName := node.LocalName

	// Check input[type="checkbox"]
	if localName == "input" {
		for i := 0; i+1 < len(node.Attributes); i += 2 {
			if node.Attributes[i] == "type" && node.Attributes[i+1] == "checkbox" {
				return true
			}
		}
	}

	// Check elements with role="checkbox"
	for i := 0; i+1 < len(node.Attributes); i += 2 {
		if node.Attributes[i] == "role" && node.Attributes[i+1] == "checkbox" {
			return true
		}
		if node.Attributes[i] == "aria-checked" {
			return true
		}
	}

	return false
}

// containsTurnstilePattern checks if a URL contains the Turnstile frame pattern.
func containsTurnstilePattern(url, pattern string) bool {
	return len(url) > 0 && len(pattern) > 0 && contains(url, pattern)
}

// contains is a simple string contains check.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && findSubstring(s, substr) >= 0
}

// findSubstring returns the index of substr in s, or -1 if not found.
func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

// GetCheckboxPosition returns the center coordinates of a checkbox element.
// Used for positional clicking when element references cannot be maintained.
func (t *ShadowRootTraverser) GetCheckboxPosition(ctx context.Context) (x, y float64, err error) {
	checkbox, err := t.FindTurnstileCheckbox(ctx)
	if err != nil {
		return 0, 0, err
	}
	defer func() {
		if err := checkbox.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release checkbox element")
		}
	}()

	// Fix 2.14: Add timeout to Shape() call to prevent hanging
	box, err := checkbox.Timeout(t.timeout).Shape()
	if err != nil {
		return 0, 0, fmt.Errorf("failed to get checkbox position: %w", err)
	}

	if box == nil || len(box.Quads) == 0 {
		return 0, 0, fmt.Errorf("failed to get checkbox position: checkbox has no bounding box")
	}

	// Calculate center from quad points
	// Quad format: [x1, y1, x2, y2, x3, y3, x4, y4] - 8 values for 4 corners
	quad := box.Quads[0]
	if len(quad) < 8 {
		return 0, 0, fmt.Errorf("failed to get checkbox position: quad has insufficient points (%d, need 8)", len(quad))
	}
	x = (quad[0] + quad[2] + quad[4] + quad[6]) / 4
	y = (quad[1] + quad[3] + quad[5] + quad[7]) / 4

	return x, y, nil
}

// ClickCheckbox finds and clicks the Turnstile checkbox.
// Returns nil on success, or an error if the checkbox couldn't be found or clicked.
// Includes panic recovery to prevent DOM traversal panics from crashing the process.
func (t *ShadowRootTraverser) ClickCheckbox(ctx context.Context) (err error) {
	// Add panic recovery for DOM traversal operations
	defer func() {
		if r := recover(); r != nil {
			log.Error().Interface("panic", r).Msg("Recovered from panic in shadow DOM checkbox click")
			err = fmt.Errorf("panic during shadow DOM click: %v", r)
		}
	}()

	checkbox, err := t.FindTurnstileCheckbox(ctx)
	if err != nil {
		return err
	}
	defer func() {
		if err := checkbox.Release(); err != nil {
			log.Debug().Err(err).Msg("Failed to release checkbox element after click")
		}
	}()

	// Try to click the checkbox
	if err := checkbox.Click(proto.InputMouseButtonLeft, 1); err != nil {
		return fmt.Errorf("failed to click checkbox via shadow DOM: %w", err)
	}

	log.Info().Msg("Successfully clicked Turnstile checkbox via shadow DOM traversal")
	return nil
}

// GetTurnstileContainerBounds returns the bounding box of the Turnstile container.
// Used for positional click fallback when the checkbox cannot be directly accessed.
func (t *ShadowRootTraverser) GetTurnstileContainerBounds(ctx context.Context) (*proto.DOMRect, error) {
	sel := selectors.Get()

	// Try each shadow host selector as container
	for _, hostSelector := range sel.ShadowHosts {
		has, _, _ := t.page.Has(hostSelector)
		if !has {
			continue
		}

		element, err := t.page.Timeout(t.timeout).Element(hostSelector)
		if err != nil {
			continue
		}

		// Use inline function with defer to ensure proper release after Shape call
		box, err := func() (*proto.DOMGetContentQuadsResult, error) {
			defer func() {
				if releaseErr := element.Release(); releaseErr != nil {
					log.Debug().Err(releaseErr).Msg("Failed to release container bounds element")
				}
			}()
			return element.Shape()
		}()
		if err != nil {
			continue
		}

		// Quad format: [x1, y1, x2, y2, x3, y3, x4, y4] - 8 values for 4 corners
		if box != nil && len(box.Quads) > 0 && len(box.Quads[0]) >= 8 {
			quad := box.Quads[0]
			return &proto.DOMRect{
				X:      quad[0],
				Y:      quad[1],
				Width:  quad[2] - quad[0],
				Height: quad[5] - quad[1],
			}, nil
		}
	}

	// Fallback: try standard Turnstile selectors
	turnstileSelectors := []string{
		"#turnstile-wrapper",
		".cf-turnstile",
		"[data-sitekey]",
	}

	for _, selector := range turnstileSelectors {
		has, _, _ := t.page.Has(selector)
		if !has {
			continue
		}

		element, err := t.page.Timeout(t.timeout).Element(selector)
		if err != nil {
			continue
		}

		// Use inline function with defer to ensure proper release after Shape call
		box, err := func() (*proto.DOMGetContentQuadsResult, error) {
			defer func() {
				if releaseErr := element.Release(); releaseErr != nil {
					log.Debug().Err(releaseErr).Msg("Failed to release turnstile selector element")
				}
			}()
			return element.Shape()
		}()
		if err != nil {
			continue
		}

		// Quad format: [x1, y1, x2, y2, x3, y3, x4, y4] - 8 values for 4 corners
		if box != nil && len(box.Quads) > 0 && len(box.Quads[0]) >= 8 {
			quad := box.Quads[0]
			return &proto.DOMRect{
				X:      quad[0],
				Y:      quad[1],
				Width:  quad[2] - quad[0],
				Height: quad[5] - quad[1],
			}, nil
		}
	}

	return nil, fmt.Errorf("could not find Turnstile container bounds")
}
