package browser

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/proto"
)

// canvasProbeTimeout bounds each in-page probe so a stuck renderer fails the
// test instead of hanging it.
const canvasProbeTimeout = 60 * time.Second

// canvasProbeJS draws a fixed picture on a canvas of the given size, reads it
// back several times through every patched API, and reports what it saw.
//
// "Raw" pixels are read by drawing the canvas onto an OffscreenCanvas, whose
// read-back is not patched, so the test can see the real contents of the
// page's canvas, not the noised view.
//
// The canvases are CPU-backed (willReadFrequently). The probe awaits toBlob,
// and reading a GPU-backed canvas back after yielding to the event loop hangs
// in headless Chrome on some hosts, with or without the stealth script.
// TestCanvasNoiseIdempotent covers a default canvas separately, read the way
// fingerprinting scripts read it: synchronously, right after drawing.
const canvasProbeJS = `async (size, mimeType) => {
	const canvas = document.createElement('canvas');
	canvas.width = size;
	canvas.height = size;
	const ctx = canvas.getContext('2d', { willReadFrequently: true });
	ctx.fillStyle = 'rgb(200, 30, 30)';
	ctx.fillRect(0, 0, size, size);
	ctx.fillStyle = 'rgb(30, 30, 200)';
	ctx.fillRect(size / 4, size / 4, size / 2, size / 2);
	ctx.font = '14px sans-serif';
	ctx.fillStyle = 'rgb(240, 240, 240)';
	ctx.fillText('fingerprint', 2, 20);

	const raw = () => {
		const offscreen = new OffscreenCanvas(size, size);
		const offscreenCtx = offscreen.getContext('2d', { willReadFrequently: true });
		offscreenCtx.drawImage(canvas, 0, 0);
		return Array.from(offscreenCtx.getImageData(0, 0, size, size).data);
	};
	const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
	const blobText = () => new Promise((resolve, reject) => {
		canvas.toBlob((blob) => {
			if (!blob) { reject(new Error('toBlob produced no blob')); return; }
			const reader = new FileReader();
			reader.onload = () => resolve(reader.result);
			reader.onerror = () => reject(reader.error);
			reader.readAsDataURL(blob);
		}, mimeType);
	});

	const rawBefore = raw();

	const urls = [canvas.toDataURL(mimeType), canvas.toDataURL(mimeType), canvas.toDataURL(mimeType)];
	const blobs = [await blobText(), await blobText()];
	const reads = [
		Array.from(ctx.getImageData(0, 0, size, size).data),
		Array.from(ctx.getImageData(0, 0, size, size).data),
	];

	// A read of a sub-rectangle must agree with the same pixels of a full read
	const offset = Math.floor(size / 3);
	const part = ctx.getImageData(offset, offset, size - offset, size - offset);
	let partMatchesFull = true;
	for (let y = 0; y < part.height && partMatchesFull; y++) {
		for (let x = 0; x < part.width; x++) {
			const p = (y * part.width + x) * 4;
			const f = ((y + offset) * size + (x + offset)) * 4;
			if (part.data[p] !== reads[0][f] || part.data[p + 1] !== reads[0][f + 1] ||
				part.data[p + 2] !== reads[0][f + 2] || part.data[p + 3] !== reads[0][f + 3]) {
				partMatchesFull = false;
				break;
			}
		}
	}

	const rawAfter = raw();

	let changedPixels = 0;
	let maxDelta = 0;
	let alphaChanged = false;
	for (let i = 0; i < rawBefore.length; i += 4) {
		const delta = Math.max(
			Math.abs(reads[0][i] - rawBefore[i]),
			Math.abs(reads[0][i + 1] - rawBefore[i + 1]),
			Math.abs(reads[0][i + 2] - rawBefore[i + 2]));
		if (delta > 0) changedPixels++;
		if (delta > maxDelta) maxDelta = delta;
		if (reads[0][i + 3] !== rawBefore[i + 3]) alphaChanged = true;
	}

	return {
		seed: window.__canvasSeed,
		seedType: typeof window.__canvasSeed,
		dataURLStable: urls[0] === urls[1] && urls[1] === urls[2],
		blobStable: blobs[0] === blobs[1],
		blobMatchesDataURL: blobs[0] === urls[0],
		imageDataStable: same(reads[0], reads[1]),
		partMatchesFull: partMatchesFull,
		canvasUntouched: same(rawBefore, rawAfter),
		changedPixels: changedPixels,
		maxDelta: maxDelta,
		alphaChanged: alphaChanged,
		patched: HTMLCanvasElement.prototype.toDataURL._stealth === true &&
			HTMLCanvasElement.prototype.toBlob._stealth === true &&
			CanvasRenderingContext2D.prototype.getImageData._stealth === true,
	};
}`

// TestCanvasNoiseIdempotent runs the stealth script in a real browser and
// checks the three properties the canvas noise must have: repeated reads of an
// untouched canvas are identical, the page's canvas is never modified, and the
// noise is applied exactly once however often the script is injected.
//
// It lives here rather than in tests/probe because that suite is skipped
// whenever CI is set; this one only skips in -short mode, so CI runs it.
func TestCanvasNoiseIdempotent(t *testing.T) {
	skipCI(t)

	cfg := testConfig()
	cfg.BrowserPoolSize = 1
	pool, err := NewPool(cfg)
	if err != nil {
		t.Fatalf("Failed to create pool: %v", err)
	}
	defer pool.Close()

	poolBrowser, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("Failed to acquire browser: %v", err)
	}
	defer pool.Release(poolBrowser)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><html><body><p>canvas</p></body></html>")
	}))
	defer server.Close()

	page, err := poolBrowser.Page(proto.TargetCreateTarget{URL: "about:blank"})
	if err != nil {
		t.Fatalf("Failed to create page: %v", err)
	}
	defer func() {
		// Ignore error: cleanup should not affect the test result
		_ = page.Close()
	}()

	// Register the script twice before navigating and run it once more
	// afterwards: a session page that has stealth applied repeatedly must not
	// stack the noise.
	for i := 0; i < 2; i++ {
		if err := ApplyStealthToPage(page); err != nil {
			t.Fatalf("ApplyStealthToPage failed: %v", err)
		}
	}
	if err := page.Navigate(server.URL); err != nil {
		t.Fatalf("Navigation failed: %v", err)
	}
	if err := page.WaitLoad(); err != nil {
		t.Fatalf("WaitLoad failed: %v", err)
	}
	if err := ApplyStealthToPage(page); err != nil {
		t.Fatalf("ApplyStealthToPage after navigation failed: %v", err)
	}

	tests := []struct {
		name      string
		size      int
		mimeType  string
		wantNoise bool // big enough that some pixel must carry noise
	}{
		{name: "typical fingerprint canvas", size: 100, mimeType: "image/png", wantNoise: true},
		{name: "small canvas", size: 16, mimeType: "image/png", wantNoise: true},
		{name: "single pixel", size: 1, mimeType: "image/png"},
		{name: "larger than the noise region", size: 600, mimeType: "image/png", wantNoise: true},
		{name: "jpeg export", size: 100, mimeType: "image/jpeg", wantNoise: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := page.Timeout(canvasProbeTimeout).Eval(canvasProbeJS, tt.size, tt.mimeType)
			if err != nil {
				t.Fatalf("canvas probe failed: %v", err)
			}
			got := result.Value.Map()

			if !got["patched"].Bool() {
				t.Fatal("canvas read-back APIs are not patched")
			}
			seed := got["seed"].Int()
			if got["seedType"].Str() != "number" || seed < 1 || seed > 255 {
				t.Errorf("canvas seed = %v (%s), want a number in 1..255", got["seed"], got["seedType"].Str())
			}
			if !got["dataURLStable"].Bool() {
				t.Error("three consecutive toDataURL reads of an untouched canvas differ")
			}
			if !got["blobStable"].Bool() {
				t.Error("two consecutive toBlob reads of an untouched canvas differ")
			}
			// PNG is lossless and deterministic, so both export paths must agree
			if tt.mimeType == "image/png" && !got["blobMatchesDataURL"].Bool() {
				t.Error("toBlob and toDataURL disagree for the same canvas")
			}
			if !got["imageDataStable"].Bool() {
				t.Error("two consecutive getImageData reads of an untouched canvas differ")
			}
			if !got["partMatchesFull"].Bool() {
				t.Error("getImageData of a sub-rectangle disagrees with the full read")
			}
			if !got["canvasUntouched"].Bool() {
				t.Error("reading the canvas modified its pixels")
			}
			if got["alphaChanged"].Bool() {
				t.Error("noise changed the alpha channel")
			}
			if delta := got["maxDelta"].Int(); delta > 2 {
				t.Errorf("largest per-channel noise = %d, want at most 2 (noise applied more than once?)", delta)
			}
			if tt.wantNoise && got["changedPixels"].Int() == 0 {
				t.Error("no pixel carries noise: canvas fingerprint is not protected")
			}
		})
	}

	t.Run("default canvas read right after drawing", func(t *testing.T) {
		result, err := page.Timeout(canvasProbeTimeout).Eval(`() => {
			const canvas = document.createElement('canvas');
			canvas.width = 220;
			canvas.height = 30;
			const ctx = canvas.getContext('2d');
			ctx.fillStyle = '#f60';
			ctx.fillRect(100, 1, 62, 20);
			ctx.fillStyle = '#069';
			ctx.font = '11pt Arial';
			ctx.fillText('Cwm fjordbank glyphs vext quiz', 2, 15);

			const urls = [canvas.toDataURL(), canvas.toDataURL(), canvas.toDataURL()];
			const first = ctx.getImageData(0, 0, 220, 30).data;
			const second = ctx.getImageData(0, 0, 220, 30).data;
			return {
				dataURLStable: urls[0] === urls[1] && urls[1] === urls[2],
				imageDataStable: first.every((v, i) => v === second[i]),
				dataURLAfterReads: canvas.toDataURL() === urls[0],
			};
		}`)
		if err != nil {
			t.Fatalf("default canvas probe failed: %v", err)
		}
		got := result.Value.Map()

		if !got["dataURLStable"].Bool() {
			t.Error("three consecutive toDataURL reads of an untouched canvas differ")
		}
		if !got["imageDataStable"].Bool() {
			t.Error("two consecutive getImageData reads of an untouched canvas differ")
		}
		if !got["dataURLAfterReads"].Bool() {
			t.Error("toDataURL changed after getImageData reads: the canvas was modified")
		}
	})

	t.Run("transparent pixels stay transparent black", func(t *testing.T) {
		// Whatever the seed, an untouched (fully transparent) canvas must read
		// back as all zeroes through every API.
		result, err := page.Timeout(canvasProbeTimeout).Eval(`() => {
			const canvas = document.createElement('canvas');
			canvas.width = 64;
			canvas.height = 64;
			const ctx = canvas.getContext('2d', { willReadFrequently: true });
			ctx.fillStyle = 'rgb(10, 200, 90)';
			ctx.fillRect(32, 0, 32, 64);

			const direct = ctx.getImageData(0, 0, 32, 64).data;

			const exported = new OffscreenCanvas(64, 64);
			const exportedCtx = exported.getContext('2d', { willReadFrequently: true });
			return new Promise((resolve, reject) => {
				const image = new Image();
				image.onload = () => {
					exportedCtx.drawImage(image, 0, 0);
					const viaExport = exportedCtx.getImageData(0, 0, 32, 64).data;
					resolve({
						directClean: direct.every((v) => v === 0),
						exportClean: viaExport.every((v) => v === 0),
					});
				};
				image.onerror = () => reject(new Error('exported PNG did not load'));
				image.src = canvas.toDataURL();
			});
		}`)
		if err != nil {
			t.Fatalf("transparent pixel probe failed: %v", err)
		}
		got := result.Value.Map()

		if !got["directClean"].Bool() {
			t.Error("getImageData put color into transparent pixels")
		}
		if !got["exportClean"].Bool() {
			t.Error("toDataURL put color into transparent pixels")
		}
	})

	t.Run("reading a canvas does not claim its context", func(t *testing.T) {
		// toDataURL on a canvas with no context yet must not create a 2d one,
		// or a later getContext('webgl') on that canvas returns null.
		result, err := page.Timeout(canvasProbeTimeout).Eval(`() => {
			const control = document.createElement('canvas');
			const webglAvailable = control.getContext('webgl') !== null;

			const canvas = document.createElement('canvas');
			canvas.width = 32;
			canvas.height = 32;
			const first = canvas.toDataURL();
			const second = canvas.toDataURL();
			return {
				webglAvailable: webglAvailable,
				webglAfterRead: canvas.getContext('webgl') !== null,
				stable: first === second,
			};
		}`)
		if err != nil {
			t.Fatalf("context probe failed: %v", err)
		}
		got := result.Value.Map()

		if !got["stable"].Bool() {
			t.Error("toDataURL of a context-less canvas is not stable")
		}
		if got["webglAvailable"].Bool() != got["webglAfterRead"].Bool() {
			t.Errorf("getContext('webgl') after toDataURL = %v, want %v",
				got["webglAfterRead"].Bool(), got["webglAvailable"].Bool())
		}
	})
}

// TestCanvasNoiseScriptContent is a browser-free guard that runs in -short
// mode too: the canvas section must not write to the page's canvas and must
// never produce a zero seed.
func TestCanvasNoiseScriptContent(t *testing.T) {
	start := strings.Index(stealthScript, "12. Canvas fingerprinting protection")
	end := strings.Index(stealthScript, "13. AudioContext fingerprinting protection")
	if start < 0 || end < start {
		t.Fatal("canvas section not found in stealthScript")
	}
	section := stealthScript[start:end]

	tests := []struct {
		name     string
		fragment string
		want     bool
	}{
		{name: "seed starts at 1", fragment: "1 + Math.floor(Math.random() * 255)", want: true},
		{name: "old seed that could be 0", fragment: "Math.floor(Math.random() * 256)", want: false},
		{name: "falsy seed check that re-rolls 0", fragment: "if (!window.__canvasSeed)", want: false},
		{name: "exports encode a private copy", fragment: "originalToDataURL.call(copy || this", want: true},
		{name: "copy is read with the original getImageData", fragment: "originalGetImageData.call(copyCtx", want: true},
		{name: "noise written into the page canvas", fragment: "ctx.putImageData(", want: false},
		{name: "context claimed on the page canvas", fragment: "this.getContext(", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strings.Contains(section, tt.fragment); got != tt.want {
				t.Errorf("canvas section contains %q = %v, want %v", tt.fragment, got, tt.want)
			}
		})
	}
}
