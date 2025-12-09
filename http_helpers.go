package main

import (
	"io"

	http "github.com/bogdanfinn/fhttp"
)

// PseudoHeaderOrder is the standard HTTP/2 pseudo-header order for all requests.
var PseudoHeaderOrder = []string{
	":method",
	":authority",
	":scheme",
	":path",
}

// readResponseBody decompresses and reads the full response body.
// Caller should defer resp.Body.Close() before calling this.
func readResponseBody(resp *http.Response) ([]byte, error) {
	body := http.DecompressBody(resp)
	defer body.Close()
	return io.ReadAll(body)
}
