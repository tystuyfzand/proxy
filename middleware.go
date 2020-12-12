// Copyright 2020 Lauris BH. All rights reserved.
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file.

package proxy

// Ported from Goji's middleware, source:
// https://github.com/zenazn/goji/tree/master/web/middleware

import (
	"net"
	"net/http"
	"strings"
)

var (
	xForwardedFor   = http.CanonicalHeaderKey("X-Forwarded-For")
	xForwardedProto = http.CanonicalHeaderKey("X-Forwarded-Proto")
	xRealIP         = http.CanonicalHeaderKey("X-Real-IP")
)

// ForwardedHeaders is a middleware that sets a http.Request's RemoteAddr to the results
// of parsing either the X-Real-IP header or the X-Forwarded-For header (in that
// order).
func ForwardedHeaders(options ...*ForwardedHeadersOptions) func(h http.Handler) http.Handler {
	opt := defaultOptions
	if len(options) > 0 {
		opt = options[0]
	}
	return func(h http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if opt.isTrustedProxy(r.RemoteAddr) {
				if rip := realIP(r, opt); len(rip) > 0 {
					r.RemoteAddr = net.JoinHostPort(rip, "0")
				}

				if scheme := forwardedScheme(r); len(scheme) > 0 {
					r.URL.Scheme = scheme
				}
			}

			h.ServeHTTP(w, r)
		}

		return http.HandlerFunc(fn)
	}
}

func realIP(r *http.Request, options *ForwardedHeadersOptions) string {
	var ip string

	if xrip := r.Header.Get(xRealIP); xrip != "" {
		ip = xrip
	} else if xff := r.Header.Get(xForwardedFor); xff != "" {
		p := 0
		for i := options.ForwardLimit; i > 0; i-- {
			if p > 0 {
				xff = xff[:p-2]
			}
			p = strings.LastIndex(xff, ", ")
			if p < 0 {
				p = 0
				break
			} else {
				p += 2
			}
		}

		ip = xff[p:]
	}

	return ip
}

func forwardedScheme(r *http.Request) string {
	var scheme string

	if xproto := r.Header.Get(xForwardedProto); xproto != "" {
		scheme = xproto
	}

	return scheme
}
