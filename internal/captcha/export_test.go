package captcha

import "github.com/go-rod/rod"

// InterceptorListenerDone returns the channel that is closed when the page's
// OOPIF listener goroutine has exited, or nil if no listener was started.
func InterceptorListenerDone(page *rod.Page) <-chan struct{} {
	st, ok := loadState(page)
	if !ok || st == nil {
		return nil
	}
	return st.done
}

// InterceptorChildCount returns how many OOPIF child sessions are tracked for
// the page, or -1 if the page is not instrumented.
func InterceptorChildCount(page *rod.Page) int {
	st, ok := loadState(page)
	if !ok || st == nil {
		return -1
	}
	return len(st.snapshot())
}
