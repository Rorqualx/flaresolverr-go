// Package handlers provides HTTP request handlers for the FlareSolverr API.
package handlers

import (
	"bytes"
	"sync"

	"github.com/rs/zerolog/log"
)

// jsonBufferPool provides reusable byte buffers for JSON decoding.
// This reduces GC pressure by avoiding frequent allocation of buffers.
var jsonBufferPool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate 4KB buffer, typical JSON request size
		return bytes.NewBuffer(make([]byte, 0, 4096))
	},
}

// getBuffer retrieves a buffer from the pool.
// Bug 7: Use safe type assertion to prevent panics.
func getBuffer() *bytes.Buffer {
	v := jsonBufferPool.Get()
	buf, ok := v.(*bytes.Buffer)
	if !ok {
		// This should never happen with our New func, but handle defensively
		log.Warn().Interface("got_type", v).Msg("Unexpected type from json buffer pool")
		return bytes.NewBuffer(make([]byte, 0, 4096))
	}
	return buf
}

// putBuffer returns a buffer to the pool after resetting it.
func putBuffer(buf *bytes.Buffer) {
	buf.Reset()
	jsonBufferPool.Put(buf)
}

// responseBufferPool provides reusable byte buffers for JSON encoding.
var responseBufferPool = sync.Pool{
	New: func() interface{} {
		// Pre-allocate 8KB buffer for responses (HTML content can be large)
		return bytes.NewBuffer(make([]byte, 0, 8192))
	},
}

// getResponseBuffer retrieves a response buffer from the pool.
// Bug 7: Use safe type assertion to prevent panics.
func getResponseBuffer() *bytes.Buffer {
	v := responseBufferPool.Get()
	buf, ok := v.(*bytes.Buffer)
	if !ok {
		// This should never happen with our New func, but handle defensively
		log.Warn().Interface("got_type", v).Msg("Unexpected type from response buffer pool")
		return bytes.NewBuffer(make([]byte, 0, 8192))
	}
	return buf
}

// putResponseBuffer returns a response buffer to the pool after resetting it.
func putResponseBuffer(buf *bytes.Buffer) {
	buf.Reset()
	responseBufferPool.Put(buf)
}
