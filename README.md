# amalgame-net-stream

Raw **L4 TCP + UDP stream proxy** for the Amalgame / Mosaic stack — the
nginx `stream {}` / HAProxy TCP+UDP-mode slice. Forward a local port to
one or more upstreams without parsing the payload: raw bytes both ways
for TCP, datagrams both ways for UDP. Use it to front a database, a
message broker, a DNS resolver, a game server, or any opaque protocol.

```amalgame
import Amalgame.Net.Stream

// TCP — binary-safe byte splice
TcpProxy.New()
    .Listen(6432)                          // local port clients hit
    .Forward("pg-primary.internal", 5432)  // fixed upstream host:port
    .Serve()                               // blocks until SIGINT/SIGTERM

// UDP — per-client session forwarding (datagram boundaries preserved)
UdpProxy.New()
    .Listen(5300)
    .Forward("resolver.internal", 53)
    .Serve()

// Load-balanced pool (round-robin default; ip_hash / least_conn too)
TcpProxy.New()
    .Listen(6432)
    .Forward("db-a.internal", 5432)        // first upstream
    .AddUpstream("db-b.internal", 5432)    // + more
    .LeastConnections()                    // strategy
    .Serve()
```

The listener is **IPv6 dual-stack** (it accepts both IPv6 and
IPv4-mapped clients) with an automatic IPv4 fallback where IPv6 is
unavailable.

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
proxy — for both the TCP splice and the UDP datagram path. (UDP forwarding
also goes through the C engine for the same reason, and additionally to
preserve datagram boundaries — one client datagram in, one upstream
datagram out.)

## Security — wired in by default, not bolted on

| Defense | Behaviour |
|---|---|
| **SIGPIPE ignored** | A write to a peer that already closed returns `EPIPE`, never kills the proxy. |
| **Idle timeout** | TCP: a stream idle both ways for `IdleTimeout(ms)` is torn down (slowloris / zombie defense; default 60 s). UDP: idle teardown is *mandatory* — with no FIN it is the only way a session ends (default 30 s). |
| **Connect timeout** | A hung backend cannot pin a worker — the upstream dial is bounded (`ConnectTimeout(ms)`, default 5 s; TCP only). |
| **Global cap** | `MaxConnections(n)` — TCP connections (default 1024) / UDP sessions (default 1024). Over-cap is dropped immediately — no queue growth, no OOM. |
| **Per-source-IP cap** | `MaxPerIp(n)` (default 64) blunts single-source floods. |
| **Bounded buffer** | `BufferSize(bytes)` — TCP splice clamped 1 KiB .. 1 MiB; UDP datagram clamped 2 KiB .. 64 KiB (covers the max IPv4 UDP payload, so no silent truncation). |
| **Graceful shutdown** | `SIGINT` / `SIGTERM` stop accepting and let in-flight streams / sessions drain. |
| **No fd leaks** | Every path closes its fds and decrements the counters exactly once. |

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

UdpProxy.New() : UdpProxy
  .Listen(port: int)              // local UDP port to bind (1-65535)
  .Forward(host: string, port: int)  // fixed upstream
  .IdleTimeout(ms: int)           // per-session idle reap (0 = none)
  .MaxConnections(n: int)         // global session cap (0 = engine hard cap)
  .MaxPerIp(n: int)               // per-source-IP session cap (0 = unlimited)
  .BufferSize(bytes: int)         // datagram buffer (engine clamps 2K..64K)
  .Validate() : string            // "" if serveable, else an error message
  .Serve() : int                  // blocks; 0 = clean shutdown, <0 = error
```

### Load-balancing across a pool (both proxies)

```amalgame
  .Forward(host, port)            // sets / resets the pool to one upstream
  .AddUpstream(host, port)        // append another upstream to the pool
  .RoundRobin()                   // strategy: rotate (default)
  .IpHash()                       // strategy: sticky per client IP
  .LeastConnections()             // strategy: fewest in-flight (TCP conns /
                                  //           UDP sessions)
  .Strategy("round_robin" | "ip_hash" | "least_conn")   // by name
```

TCP dials with **failover**: if the chosen upstream won't connect, the
remaining upstreams are tried before the connection is dropped. For UDP,
the strategy picks an upstream per *session* and the client sticks to it
for the session's lifetime (ip_hash is naturally sticky per client IP).

## End-to-end

```bash
# Terminal 1: a backend to front
nc -l 5432

# Terminal 2: the proxy (see examples/tcp_forward.am)
NS_LISTEN=6432 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=5432 ./tcp_forward

# Terminal 3: hit the proxy — bytes appear on the backend and vice-versa
nc 127.0.0.1 6432

# UDP variant (see examples/udp_forward.am) — front a DNS resolver:
NS_LISTEN=5300 NS_UPSTREAM_HOST=1.1.1.1 NS_UPSTREAM_PORT=53 ./udp_forward
dig @127.0.0.1 -p 5300 example.com
```

## Limitations (v0.3.0 — honest scope)

- **No active health checks.** Load balancing is shipped (round-robin /
  ip-hash / least-conn, TCP with dial failover), but there is no
  background `/healthz` probe or outlier ejection yet — a dead upstream
  is only skipped at TCP dial time (UDP, being connectionless, can't tell
  a black-holing upstream from a quiet one). Tracked follow-up.
- **No TLS at the edge.** TLS termination / origination (and DTLS for
  UDP) is the next target (would compose `amalgame-tls`).
- **Up to 64 upstreams** per proxy (`AMNETSTREAM_MAX_UPSTREAMS`).
- **TCP per-IP table is bounded** to 4096 distinct source IPs; once full,
  a new IP is admitted but not per-IP-tracked (the global cap still
  bounds total load). Documented, not silent.
- **UDP session table is linear.** Session lookup and the poll set are
  O(sessions) per wakeup; fine for moderate fan-out, but a hashed table
  + `epoll` is the follow-up for very high session counts. The table is
  capped (`MaxConnections`, default 1024); over the cap a new client's
  datagram is dropped (fail-closed).

## Build & test

```bash
./tests/run_tests.sh            # unit + binary-safety + cap + shutdown
```

Requires `amc`, a C toolchain, and `python3` (for the integration
probes). The package is self-contained — no sibling-package dependencies
beyond the Amalgame runtime; links only `-lpthread`.

## License

Apache-2.0.
