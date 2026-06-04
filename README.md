# amalgame-net-stream

Raw **L4 TCP stream proxy** for the Amalgame / Mosaic stack — the
nginx `stream {}` / HAProxy TCP-mode slice. Forward a local TCP port to
a fixed upstream `host:port`, splicing raw bytes both ways without
parsing the payload. Use it to front a database, a message broker, or
any opaque TCP protocol.

```amalgame
import Amalgame.Net.Stream

TcpProxy.New()
    .Listen(6432)                          // local port clients hit
    .Forward("pg-primary.internal", 5432)  // fixed upstream host:port
    .Serve()                               // blocks until SIGINT/SIGTERM
```

## Why a dedicated C splice (binary-safety)

The bundled `Amalgame.Net` `TcpConn`/`TcpClient` primitives send with
`send(fd, data, strlen(data), 0)` and receive into a NUL-terminated
string — both **truncate at the first NUL byte**, which corrupts every
binary stream (TLS records, the Postgres / Redis / MQTT wire protocols,
anything with embedded NULs). A raw L4 proxy must move bytes with
explicit lengths, so the byte pump lives in C
(`runtime/Amalgame_Net_Stream.h`) at the `recv()`/`send()` boundary.
Everything that is **not** a syscall — configuration, validation, the
security-policy thresholds — stays in pure Amalgame (`facade.am`).

The test suite proves this: a payload containing every one of the 256
byte values plus embedded NULs round-trips **byte-for-byte** through the
proxy.

## Security — wired in by default, not bolted on

| Defense | Behaviour |
|---|---|
| **SIGPIPE ignored** | A write to a peer that already closed returns `EPIPE`, never kills the proxy. |
| **Idle timeout** | A stream with no traffic either way for `IdleTimeout(ms)` is torn down (slowloris / zombie defense). Default 60 s. |
| **Connect timeout** | A hung backend cannot pin a worker — the upstream dial is bounded (`ConnectTimeout(ms)`, default 5 s). |
| **Global connection cap** | `MaxConnections(n)` (default 1024). Over-cap connections are closed immediately — no queue growth, no OOM. |
| **Per-source-IP cap** | `MaxPerIp(n)` (default 64) blunts single-source connection floods. |
| **Bounded splice buffer** | `BufferSize(bytes)` clamped to 1 KiB .. 1 MiB by the engine. |
| **Graceful shutdown** | `SIGINT` / `SIGTERM` stop accepting and let in-flight streams drain. |
| **No fd leaks** | Every accept path closes both fds and decrements the counters exactly once. |

### A note on SSRF

`amalgame-net-stream` deliberately does **not** apply the "deny RFC1918"
guard that `HttpClient.GetGuarded` uses. The upstream is fixed by the
operator at configuration time and is **never derived from client
input**, so blocking private addresses would be actively wrong — a
stream proxy's whole job is to front an internal (private-IP) service.

## API

```amalgame
TcpProxy.New() : TcpProxy
  .Listen(port: int)              // local TCP port to bind (1-65535)
  .Forward(host: string, port: int)  // fixed upstream
  .ConnectTimeout(ms: int)        // upstream dial timeout (0 = block)
  .IdleTimeout(ms: int)           // per-stream idle teardown (0 = none)
  .MaxConnections(n: int)         // global concurrent cap (0 = unlimited)
  .MaxPerIp(n: int)               // per-source-IP cap (0 = unlimited)
  .ListenBacklog(n: int)          // listen() backlog
  .BufferSize(bytes: int)         // splice buffer (engine clamps)
  .Validate() : string            // "" if serveable, else an error message
  .Serve() : int                  // blocks; 0 = clean shutdown, <0 = error
```

## End-to-end

```bash
# Terminal 1: a backend to front
nc -l 5432

# Terminal 2: the proxy (see examples/tcp_forward.am)
NS_LISTEN=6432 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=5432 ./tcp_forward

# Terminal 3: hit the proxy — bytes appear on the backend and vice-versa
nc 127.0.0.1 6432
```

## Limitations (v0.1.0 — honest scope)

- **TCP only.** UDP forwarding (the `/U` half of nginx `stream {}`) is
  the v0.2 target.
- **Single fixed upstream.** Load balancing across N upstreams (pools,
  health checks, round-robin / least-conn) is the v0.2 target —
  mirrors the `amalgame-net-proxy` v0.1 → v0.2 cadence.
- **IPv4 listener.** The upstream dial already accepts IPv6; only the
  *listen* side is IPv4 today. Dual-stack bind is tracked.
- **No TLS at the edge.** TLS termination / origination is the v0.3
  target (would compose `amalgame-tls`).
- **Per-IP table is bounded** to 4096 distinct source IPs; once full, a
  new IP is admitted but not per-IP-tracked (the global cap still bounds
  total load). Documented, not silent.

## Build & test

```bash
./tests/run_tests.sh            # unit + binary-safety + cap + shutdown
```

Requires `amc`, a C toolchain, and `python3` (for the integration
probes). The package is self-contained — no sibling-package dependencies
beyond the Amalgame runtime; links only `-lpthread`.

## License

Apache-2.0.
