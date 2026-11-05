// Package mcp serves Knotwork's Model Context Protocol surface through the
// official Go SDK.
//
// The pinned module is github.com/modelcontextprotocol/go-sdk v1.8.0
// (commit 3f3b699b2b67e1ed033a63d6651671dab53c2d32, tagged 2026-09-04).
// That release is the newest stable tag. It requires Go 1.25, which Knotwork's
// Go 1.27 toolchain satisfies, and it is the maintained SDK published with the
// protocol project (MIT contributions transitioning to Apache-2.0; the module
// LICENSE is authoritative). Its supported protocol versions, newest first, are
// 2026-07-28, 2025-11-25, 2025-06-18, 2025-03-26, and 2024-11-05.
//
// v1.8.0 is selected instead of the SDK main branch and instead of
// github.com/mark3labs/mcp-go because this release already exposes Streamable
// HTTP, stdio, the legacy HTTP+SSE server transport, and the RFC 9728 protected
// resource metadata helpers. Streamable HTTP serves 2026-07-28 only when the
// handler is stateless. The legacy SSE transport does not advertise 2026-07-28.
// Knotwork does not vendor the module and does not relicense it.
package mcp
