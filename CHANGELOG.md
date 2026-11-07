# Changelog

## 2.1.0 — 2026-11-07

- Restrict the HTTP control endpoint to loopback so pairing and bearer tokens are never exposed directly on LAN interfaces. Direct pairing now requires PhoenixBox and Burp on the same machine.
- Bound unauthenticated control connections and immediately close excess connections. Close active and queued control sockets on unload without interrupting an admitted Burp settings import.

- Highlight and label text and binary WebSocket messages in both directions using the opening HTTP handshake’s container attribution.
- Preserve existing user notes and message payloads. Keep attribution fixed for each connection and leave ambiguous handshakes unchanged.
- Bound pending handshake state and retain bounded fingerprints to prevent expired or rejected handshakes from borrowing another container’s label.
- Keep malformed HTTP requests on the normal annotation and header-cleaning path when WebSocket classification cannot parse them.
- Prevent pinned listeners from overlapping wildcard listeners belonging to another container or Burp’s main/control interfaces.
- Fence in-flight sync and listener ownership during unload/reload, and perform listener/WebSocket cleanup without blocking Burp’s UI thread.
- Let admitted control-server requests finish without interrupting an outstanding Burp UI import.

## 2.0.0

- Pair PhoenixBox with Burp and attribute container traffic through dedicated proxy listeners without adding attribution headers in paired mode.
