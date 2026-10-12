package captcha

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/Rorqualx/flaresolverr-go/internal/types"
)

// Timing used by provider tests: polls every few milliseconds so a whole solve
// takes well under a second.
const (
	testPollInterval = 5 * time.Millisecond
	testTimeout      = 5 * time.Second
)

// reply is one scripted HTTP response of the fake provider.
type reply struct {
	status int
	body   string
}

func ok(body string) reply { return reply{status: http.StatusOK, body: body} }

// readyToken is a successful getTaskResult response.
func readyToken(token string) reply {
	return ok(`{"errorId":0,"status":"ready","solution":{"token":"` + token + `"}}`)
}

const processing = `{"errorId":0,"status":"processing"}`

// fakeProvider is an httptest server speaking the createTask/getTaskResult
// protocol shared by 2Captcha, anti-captcha and CapSolver. It records every
// call and answers from a script; the last entry of a script repeats.
type fakeProvider struct {
	*httptest.Server

	mu          sync.Mutex
	creates     []map[string]any // decoded createTask bodies
	createTimes []time.Time
	pollTimes   []time.Time
	createReply []reply
	pollReply   []reply
}

// newFakeProvider starts a fake provider. With no script it accepts the task
// (numeric id, as 2Captcha and anti-captcha send) and solves it on the first poll.
func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	f := &fakeProvider{
		createReply: []reply{ok(`{"errorId":0,"taskId":1001}`)},
		pollReply:   []reply{readyToken("fake-token")},
	}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeProvider) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))

	f.mu.Lock()
	var out reply
	switch r.URL.Path {
	case "/createTask":
		var decoded map[string]any
		_ = json.Unmarshal(body, &decoded)
		f.creates = append(f.creates, decoded)
		f.createTimes = append(f.createTimes, time.Now())
		out = pick(f.createReply, len(f.creates))
	case "/getTaskResult":
		f.pollTimes = append(f.pollTimes, time.Now())
		out = pick(f.pollReply, len(f.pollTimes))
	case "/getBalance":
		out = ok(`{"errorId":0,"balance":5.5}`)
	default:
		out = reply{status: http.StatusNotFound, body: "not found"}
	}
	f.mu.Unlock()

	w.WriteHeader(out.status)
	_, _ = w.Write([]byte(out.body))
}

// pick returns the n-th (1-based) scripted reply, repeating the last one.
func pick(script []reply, n int) reply {
	if n > len(script) {
		n = len(script)
	}
	return script[n-1]
}

func (f *fakeProvider) onCreate(script ...reply) *fakeProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createReply = script
	return f
}

func (f *fakeProvider) onPoll(script ...reply) *fakeProvider {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pollReply = script
	return f
}

func (f *fakeProvider) createCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.creates)
}

func (f *fakeProvider) pollCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.pollTimes)
}

// lastTask returns the task object of the most recent createTask call.
func (f *fakeProvider) lastTask(t *testing.T) map[string]any {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		t.Fatal("no createTask call was recorded")
	}
	task, _ := f.creates[len(f.creates)-1]["task"].(map[string]any)
	return task
}

// lastClientKey returns the API key sent with the most recent createTask call.
func (f *fakeProvider) lastClientKey(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.creates) == 0 {
		t.Fatal("no createTask call was recorded")
	}
	key, _ := f.creates[len(f.creates)-1]["clientKey"].(string)
	return key
}

// firstPollDelay returns how long after createTask the first poll arrived.
func (f *fakeProvider) firstPollDelay(t *testing.T) time.Duration {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.createTimes) == 0 || len(f.pollTimes) == 0 {
		t.Fatal("need at least one createTask and one poll")
	}
	return f.pollTimes[0].Sub(f.createTimes[0])
}

// closedServerURL returns the URL of a server that is no longer listening.
func closedServerURL() string {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	return server.URL
}

// containsCaptchaError checks if err contains a CaptchaError
func containsCaptchaError(err error, target **types.CaptchaError) bool {
	for err != nil {
		if ce, ok := err.(*types.CaptchaError); ok {
			*target = ce
			return true
		}
		if unwrapper, ok := err.(interface{ Unwrap() error }); ok {
			err = unwrapper.Unwrap()
		} else {
			break
		}
	}
	return false
}
