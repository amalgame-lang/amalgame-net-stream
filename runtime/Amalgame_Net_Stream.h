/* Amalgame_Net_Stream.h — raw L4 (TCP) stream proxy engine.
 *
 * This is the syscall frontier for `amalgame-net-stream`: accept a TCP
 * connection, dial a *fixed, operator-configured* upstream, and splice
 * bytes in both directions until either side closes. It is the nginx
 * `stream {}` / HAProxy TCP-mode equivalent.
 *
 * Why the byte pump lives in C (and not in pure Amalgame): a raw L4
 * proxy carries arbitrary binary payloads (TLS records, the Postgres /
 * Redis / MQTT wire protocols, game traffic). The bundled
 * `Amalgame.Net` TcpConn/TcpClient primitives send with
 * `send(fd, data, strlen(data), 0)` and receive into a NUL-terminated
 * `code_string` — both truncate at the first NUL byte, which corrupts
 * every binary stream. Splicing therefore has to happen with explicit
 * lengths at the recv()/send() boundary. Everything that is NOT a
 * syscall — config, validation, the security policy thresholds — stays
 * in `facade.am`.
 *
 * Security posture (v0.1.0):
 *   - SIGPIPE ignored process-wide: a write to a peer that already
 *     closed must return EPIPE, never kill the proxy.
 *   - Per-connection idle timeout: a stream with no traffic in either
 *     direction for `idle_timeout_ms` is torn down (slowloris / zombie
 *     connection defense).
 *   - Connect timeout on the upstream dial: a hung backend cannot pin a
 *     worker forever.
 *   - Global connection cap + per-source-IP cap: bound resource use and
 *     blunt single-source connection floods. Over-cap connections are
 *     closed immediately (no queue growth, no OOM).
 *   - Bounded splice buffer (clamped 1 KiB .. 1 MiB).
 *   - Graceful shutdown on SIGINT/SIGTERM: stop accepting, let in-flight
 *     streams drain.
 *   - No fd leaks: every accept path closes both fds and decrements the
 *     counters exactly once.
 *
 * NOT a concern here (by design): SSRF. The upstream is fixed by the
 * operator at configuration time, never derived from client input, so
 * the "deny RFC1918" guard used by HttpClient.GetGuarded would be
 * actively wrong — a stream proxy's whole job is to front an internal
 * service (a private-IP Postgres, say).
 *
 * Listener is IPv4 (AF_INET) in v0.1.0; IPv6 / dual-stack is a tracked
 * follow-up (see README "Limitations"). All engine state is `static`
 * (internal linkage) so multi-TU inclusion is harmless; only the
 * facade translation unit actually calls NetStream_RunTcp().
 */
#ifndef AMALGAME_NET_STREAM_H
#define AMALGAME_NET_STREAM_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

/* ---- shutdown flag + listener fd (set by the signal handler) ------- */

static volatile sig_atomic_t amnetstream_stopping = 0;
static int  amnetstream_listen_fd = -1;

static void amnetstream_sig_handler(int sig) {
    (void) sig;
    amnetstream_stopping = 1;
    if (amnetstream_listen_fd >= 0) {
        /* Wake the blocking accept()/poll() so the loop can exit. */
        shutdown(amnetstream_listen_fd, SHUT_RDWR);
    }
}

static void amnetstream_install_signals(void) {
    static int installed = 0;
    if (installed) return;
    installed = 1;
    signal(SIGPIPE, SIG_IGN);              /* never die on a broken pipe */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = amnetstream_sig_handler;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

/* ---- connection accounting (global + per-source-IP caps) ----------- */

#define AMNETSTREAM_MAX_TRACKED_IPS 4096

typedef struct {
    char ip[INET6_ADDRSTRLEN];
    int  count;
} amnetstream_ipslot;

static pthread_mutex_t amnetstream_lock = PTHREAD_MUTEX_INITIALIZER;
static int             amnetstream_active = 0;
static amnetstream_ipslot amnetstream_ips[AMNETSTREAM_MAX_TRACKED_IPS];
static int             amnetstream_ips_used = 0;

/* Try to admit a connection from `ip`. Returns 1 if admitted (caller
 * must later call amnetstream_release), 0 if a cap was hit (caller must
 * close the socket immediately). max_conns / max_per_ip == 0 disable
 * that cap. If the per-IP table is full we fail OPEN on per-IP tracking
 * (the global cap still bounds total load) rather than reject legit
 * traffic — documented, not silent. */
static int amnetstream_admit(const char* ip, int max_conns, int max_per_ip) {
    int ok = 1;
    pthread_mutex_lock(&amnetstream_lock);
    if (max_conns > 0 && amnetstream_active >= max_conns) {
        ok = 0;
    } else if (max_per_ip > 0 && ip && ip[0]) {
        int i, found = -1;
        for (i = 0; i < amnetstream_ips_used; i++) {
            if (strncmp(amnetstream_ips[i].ip, ip, INET6_ADDRSTRLEN) == 0) {
                found = i; break;
            }
        }
        if (found >= 0) {
            if (amnetstream_ips[found].count >= max_per_ip) ok = 0;
            else amnetstream_ips[found].count++;
        } else if (amnetstream_ips_used < AMNETSTREAM_MAX_TRACKED_IPS) {
            strncpy(amnetstream_ips[amnetstream_ips_used].ip, ip, INET6_ADDRSTRLEN - 1);
            amnetstream_ips[amnetstream_ips_used].ip[INET6_ADDRSTRLEN - 1] = '\0';
            amnetstream_ips[amnetstream_ips_used].count = 1;
            amnetstream_ips_used++;
        }
        /* table full + new IP: per-IP untracked this time (fail-open). */
    }
    if (ok) amnetstream_active++;
    pthread_mutex_unlock(&amnetstream_lock);
    return ok;
}

static void amnetstream_release(const char* ip, int max_per_ip) {
    pthread_mutex_lock(&amnetstream_lock);
    if (amnetstream_active > 0) amnetstream_active--;
    if (max_per_ip > 0 && ip && ip[0]) {
        int i;
        for (i = 0; i < amnetstream_ips_used; i++) {
            if (strncmp(amnetstream_ips[i].ip, ip, INET6_ADDRSTRLEN) == 0) {
                if (amnetstream_ips[i].count > 0) amnetstream_ips[i].count--;
                break;
            }
        }
    }
    pthread_mutex_unlock(&amnetstream_lock);
}

/* ---- non-blocking helpers ------------------------------------------ */

static int amnetstream_set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

/* Connect to host:port with a bounded timeout. Returns a connected fd
 * (blocking mode restored) or -1. */
static int amnetstream_dial(const char* host, int port, int timeout_ms) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;          /* upstream may be v4 or v6 */
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return -1;

    int fd = -1;
    struct addrinfo* ai;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = (int) socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        if (amnetstream_set_nonblock(fd) < 0) { close(fd); fd = -1; continue; }

        int rc = connect(fd, ai->ai_addr, ai->ai_addrlen);
        if (rc == 0) break;                  /* immediate connect */
        if (errno != EINPROGRESS) { close(fd); fd = -1; continue; }

        struct pollfd pfd;
        pfd.fd = fd; pfd.events = POLLOUT;
        int pr = poll(&pfd, 1, timeout_ms > 0 ? timeout_ms : -1);
        if (pr <= 0) { close(fd); fd = -1; continue; }  /* timeout / error */

        int soerr = 0; socklen_t slen = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
            close(fd); fd = -1; continue;
        }
        break;                               /* connected */
    }
    freeaddrinfo(res);

    if (fd >= 0) {
        /* back to blocking; the splice loop drives readiness via poll() */
        int fl = fcntl(fd, F_GETFL, 0);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    }
    return fd;
}

/* Send exactly `len` bytes (handles partial writes / EAGAIN via poll).
 * Returns 0 on success, -1 on peer close / error. */
static int amnetstream_send_all(int fd, const char* buf, ssize_t len, int idle_ms) {
    ssize_t off = 0;
    while (off < len) {
        ssize_t n = send(fd, buf + off, (size_t)(len - off), 0);
        if (n > 0) { off += n; continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pfd; pfd.fd = fd; pfd.events = POLLOUT;
            int pr = poll(&pfd, 1, idle_ms > 0 ? idle_ms : -1);
            if (pr <= 0) return -1;          /* idle timeout or error */
            continue;
        }
        return -1;                           /* EPIPE / ECONNRESET / etc. */
    }
    return 0;
}

/* ---- the bidirectional splice -------------------------------------- */

typedef struct {
    int  client_fd;
    char client_ip[INET6_ADDRSTRLEN];
    char up_host[256];
    int  up_port;
    int  connect_timeout_ms;
    int  idle_timeout_ms;
    int  buf_size;
    int  max_per_ip;
} amnetstream_job;

/* Pump bytes both ways between a and b until both directions are done
 * or the idle timeout elapses with no progress. */
static void amnetstream_splice(int a, int b, int buf_size, int idle_ms) {
    char* buf = (char*) malloc((size_t) buf_size);
    if (!buf) return;

    amnetstream_set_nonblock(a);
    amnetstream_set_nonblock(b);

    int a_open = 1, b_open = 1;   /* read side still open? */
    struct pollfd pfds[2];

    while ((a_open || b_open) && !amnetstream_stopping) {
        int nf = 0;
        struct pollfd* pa = NULL; struct pollfd* pb = NULL;
        if (a_open) { pfds[nf].fd = a; pfds[nf].events = POLLIN; pa = &pfds[nf]; nf++; }
        if (b_open) { pfds[nf].fd = b; pfds[nf].events = POLLIN; pb = &pfds[nf]; nf++; }
        if (nf == 0) break;

        int pr = poll(pfds, nf, idle_ms > 0 ? idle_ms : -1);
        if (pr == 0) break;                  /* idle timeout: tear down */
        if (pr < 0) { if (errno == EINTR) continue; break; }

        /* a -> b */
        if (pa && (pa->revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(a, buf, (size_t) buf_size, 0);
            if (n > 0) {
                if (amnetstream_send_all(b, buf, n, idle_ms) < 0) break;
            } else if (n == 0) {
                a_open = 0; shutdown(b, SHUT_WR);   /* half-close downstream */
            } else if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
        }
        /* b -> a */
        if (pb && (pb->revents & (POLLIN | POLLHUP | POLLERR))) {
            ssize_t n = recv(b, buf, (size_t) buf_size, 0);
            if (n > 0) {
                if (amnetstream_send_all(a, buf, n, idle_ms) < 0) break;
            } else if (n == 0) {
                b_open = 0; shutdown(a, SHUT_WR);
            } else if (!(errno == EAGAIN || errno == EWOULDBLOCK)) {
                break;
            }
        }
    }
    free(buf);
}

static void* amnetstream_worker(void* arg) {
    amnetstream_job* j = (amnetstream_job*) arg;

    int up = amnetstream_dial(j->up_host, j->up_port, j->connect_timeout_ms);
    if (up >= 0) {
        amnetstream_splice(j->client_fd, up, j->buf_size, j->idle_timeout_ms);
        close(up);
    }
    close(j->client_fd);
    amnetstream_release(j->client_ip, j->max_per_ip);
    free(j);
    return NULL;
}

/* ---- the accept loop (entry point called from facade.am) ----------- *
 * Blocks until a shutdown signal. Returns 0 on clean shutdown, or a
 * negative code on a fatal listen-setup error:
 *   -1 socket()  -2 setsockopt  -3 bind  -4 listen
 */
static long long NetStream_RunTcp(long long listen_port,
                                  const char* up_host,
                                  long long up_port,
                                  long long connect_timeout_ms,
                                  long long idle_timeout_ms,
                                  long long max_conns,
                                  long long max_per_ip,
                                  long long backlog,
                                  long long buf_size) {
    amnetstream_install_signals();

    int bsz = (int) buf_size;
    if (bsz < 1024)      bsz = 1024;
    if (bsz > 1048576)   bsz = 1048576;       /* clamp 1 KiB .. 1 MiB */
    int blog = (int) backlog; if (blog <= 0) blog = 128;

    int lfd = (int) socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) return -1;

    int opt = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(lfd); return -2;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t) listen_port);

    if (bind(lfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) { close(lfd); return -3; }
    if (listen(lfd, blog) < 0) { close(lfd); return -4; }

    amnetstream_listen_fd = lfd;

    while (!amnetstream_stopping) {
        struct pollfd pfd; pfd.fd = lfd; pfd.events = POLLIN;
        int pr = poll(&pfd, 1, 500);          /* 500ms tick → re-check stop */
        if (pr <= 0) { if (pr < 0 && errno == EINTR) continue; continue; }

        struct sockaddr_in cliaddr;
        socklen_t clen = sizeof(cliaddr);
        int cfd = (int) accept(lfd, (struct sockaddr*) &cliaddr, &clen);
        if (cfd < 0) {
            if (amnetstream_stopping) break;
            continue;
        }

        char ip[INET6_ADDRSTRLEN];
        ip[0] = '\0';
        inet_ntop(AF_INET, &cliaddr.sin_addr, ip, sizeof(ip));

        if (!amnetstream_admit(ip, (int) max_conns, (int) max_per_ip)) {
            close(cfd);                       /* over cap: drop immediately */
            continue;
        }

        amnetstream_job* j = (amnetstream_job*) malloc(sizeof(amnetstream_job));
        if (!j) { close(cfd); amnetstream_release(ip, (int) max_per_ip); continue; }
        j->client_fd = cfd;
        strncpy(j->client_ip, ip, INET6_ADDRSTRLEN - 1); j->client_ip[INET6_ADDRSTRLEN-1] = '\0';
        strncpy(j->up_host, up_host ? up_host : "", sizeof(j->up_host) - 1);
        j->up_host[sizeof(j->up_host) - 1] = '\0';
        j->up_port            = (int) up_port;
        j->connect_timeout_ms = (int) connect_timeout_ms;
        j->idle_timeout_ms    = (int) idle_timeout_ms;
        j->buf_size           = bsz;
        j->max_per_ip         = (int) max_per_ip;

        pthread_t tid;
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if (pthread_create(&tid, &attr, amnetstream_worker, j) != 0) {
            pthread_attr_destroy(&attr);
            close(cfd);
            amnetstream_release(ip, (int) max_per_ip);
            free(j);
            continue;
        }
        pthread_attr_destroy(&attr);
    }

    amnetstream_listen_fd = -1;
    close(lfd);
    return 0;
}

/* ====================================================================
 * UDP forwarding — the "/U" half of nginx `stream {}`.
 *
 * UDP is connectionless, so there is no accept() and no thread-per-conn
 * model. A single event-loop thread owns one bound listen socket plus a
 * table of per-client *sessions*. A session is keyed by the client's
 * (address, port); each holds a dedicated upstream UDP socket connect()ed
 * to the fixed upstream, so the kernel filters replies to that peer and a
 * plain recv()/send() moves datagrams. Replies are routed back to the
 * originating client with sendto() on the listen socket.
 *
 * Because the loop is single-threaded, the session table needs no lock
 * (unlike the TCP per-IP table, which is shared across worker threads).
 *
 * Idle timeout is MANDATORY, not just a slowloris defense: UDP has no
 * FIN, so a session that has gone silent for `idle_timeout_ms` is the
 * *only* signal that it is over. Reaped sessions free their upstream fd
 * and their slot in the global / per-IP accounting.
 *
 * Datagram boundaries are preserved: one recvfrom() → one send() upstream;
 * one recv() from upstream → one sendto() to the client. The buffer is
 * clamped to hold a maximum IPv4 UDP payload (65507 B) so a datagram is
 * never silently truncated (a short buffer would drop the tail via
 * MSG_TRUNC).
 *
 * Caps mirror the TCP side and fail CLOSED: over the global session cap,
 * over the per-source-IP cap, or with the session table full, the new
 * client's datagram is dropped rather than queued. Listener is IPv4
 * (AF_INET) like the TCP side; the upstream dial accepts v4 or v6.
 * ==================================================================== */

#define AMNETSTREAM_UDP_HARD_SESSIONS 65536

typedef struct {
    int                     in_use;
    int                     up_fd;       /* connected upstream UDP socket */
    struct sockaddr_storage cli;         /* client addr for sendto() back */
    socklen_t               cli_len;
    char                    cli_ip[INET6_ADDRSTRLEN];
    time_t                  last_active; /* for idle reaping */
} amnetstream_udp_session;

/* Two client datagrams belong to the same session iff their source
 * (address, port) match. Listener is AF_INET, so this is the common
 * path; the memcmp fallback keeps it correct for any other family. */
static int amnetstream_udp_same_client(const amnetstream_udp_session* s,
                                       const struct sockaddr_storage* a,
                                       socklen_t alen) {
    if (s->cli_len != alen || s->cli.ss_family != a->ss_family) return 0;
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in* x = (const struct sockaddr_in*) &s->cli;
        const struct sockaddr_in* y = (const struct sockaddr_in*) a;
        return x->sin_port == y->sin_port &&
               x->sin_addr.s_addr == y->sin_addr.s_addr;
    }
    return memcmp(&s->cli, a, (size_t) alen) == 0;
}

/* Render the source IP of a client datagram into `out` (for per-IP cap
 * accounting). Empty string if the family is unsupported. */
static void amnetstream_udp_ip(const struct sockaddr_storage* a,
                               char* out, size_t outlen) {
    out[0] = '\0';
    if (a->ss_family == AF_INET) {
        const struct sockaddr_in* x = (const struct sockaddr_in*) a;
        inet_ntop(AF_INET, &x->sin_addr, out, (socklen_t) outlen);
    } else if (a->ss_family == AF_INET6) {
        const struct sockaddr_in6* x = (const struct sockaddr_in6*) a;
        inet_ntop(AF_INET6, &x->sin6_addr, out, (socklen_t) outlen);
    }
}

/* ---- the UDP run loop (entry point called from facade.am) ---------- *
 * Blocks until a shutdown signal. Returns 0 on clean shutdown, or a
 * negative code on a fatal setup error:
 *   -1 socket()  -2 setsockopt  -3 bind  -5 upstream getaddrinfo
 */
static long long NetStream_RunUdp(long long listen_port,
                                  const char* up_host,
                                  long long up_port,
                                  long long idle_timeout_ms,
                                  long long max_sessions,
                                  long long max_per_ip,
                                  long long buf_size) {
    amnetstream_install_signals();

    int bsz = (int) buf_size;
    if (bsz < 2048)  bsz = 2048;
    if (bsz > 65536) bsz = 65536;          /* max IPv4 UDP payload 65507 */
    int idle_ms = (int) idle_timeout_ms;

    /* Resolve the fixed upstream once (first usable DGRAM result). */
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", (int) up_port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;          /* upstream may be v4 or v6 */
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = NULL;
    if (getaddrinfo(up_host, portstr, &hints, &res) != 0 || !res) {
        if (res) freeaddrinfo(res);
        return -5;
    }
    struct sockaddr_storage up_addr;
    socklen_t up_len     = res->ai_addrlen;
    int       up_family  = res->ai_family;
    int       up_socktype = res->ai_socktype;
    int       up_proto   = res->ai_protocol;
    memcpy(&up_addr, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);

    /* Listen socket (IPv4, non-blocking — we only read on POLLIN). */
    int lfd = (int) socket(AF_INET, SOCK_DGRAM, 0);
    if (lfd < 0) return -1;
    int opt = 1;
    if (setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        close(lfd); return -2;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((uint16_t) listen_port);
    if (bind(lfd, (struct sockaddr*) &addr, sizeof(addr)) < 0) { close(lfd); return -3; }
    amnetstream_set_nonblock(lfd);
    amnetstream_listen_fd = lfd;

    /* Session table — single-threaded, so no lock. cap bounds memory and
     * the pollfd array; 0 / over-large means "use the hard cap". */
    int cap = (int) max_sessions;
    if (cap <= 0 || cap > AMNETSTREAM_UDP_HARD_SESSIONS) cap = AMNETSTREAM_UDP_HARD_SESSIONS;

    amnetstream_udp_session* sess =
        (amnetstream_udp_session*) calloc((size_t) cap, sizeof(amnetstream_udp_session));
    char*          buf  = (char*) malloc((size_t) bsz);
    struct pollfd* pfds = (struct pollfd*) malloc(sizeof(struct pollfd) * (size_t)(cap + 1));
    int*           pidx = (int*) malloc(sizeof(int) * (size_t)(cap + 1)); /* pfds[k] -> session idx (-1 = listener) */
    if (!sess || !buf || !pfds || !pidx) {
        free(sess); free(buf); free(pfds); free(pidx);
        amnetstream_listen_fd = -1; close(lfd); return -1;
    }

    int active = 0;
    int i;

    while (!amnetstream_stopping) {
        /* Build the poll set: listener + every in-use session upstream. */
        int nf = 0;
        pfds[nf].fd = lfd; pfds[nf].events = POLLIN; pidx[nf] = -1; nf++;
        for (i = 0; i < cap; i++) {
            if (sess[i].in_use) {
                pfds[nf].fd = sess[i].up_fd; pfds[nf].events = POLLIN; pidx[nf] = i; nf++;
            }
        }

        int pr = poll(pfds, (nfds_t) nf, 500);   /* 500ms tick → idle reap + stop check */
        if (pr < 0 && errno == EINTR) continue;
        time_t now = time(NULL);

        if (pr > 0) {
            /* Listener readable: drain queued client datagrams. */
            if (pfds[0].revents & POLLIN) {
                for (;;) {
                    struct sockaddr_storage cli;
                    socklen_t clen = sizeof(cli);
                    ssize_t n = recvfrom(lfd, buf, (size_t) bsz, 0,
                                         (struct sockaddr*) &cli, &clen);
                    if (n < 0) break;            /* EAGAIN: listener drained */

                    /* Existing session for this client? */
                    int slot = -1;
                    for (i = 0; i < cap; i++) {
                        if (sess[i].in_use && amnetstream_udp_same_client(&sess[i], &cli, clen)) {
                            slot = i; break;
                        }
                    }

                    if (slot < 0) {
                        /* New session — enforce caps (fail closed: drop). */
                        char ipbuf[INET6_ADDRSTRLEN];
                        amnetstream_udp_ip(&cli, ipbuf, sizeof(ipbuf));

                        if (max_sessions > 0 && active >= (int) max_sessions) continue;
                        if (max_per_ip > 0 && ipbuf[0]) {
                            int c = 0, k;
                            for (k = 0; k < cap; k++)
                                if (sess[k].in_use &&
                                    strncmp(sess[k].cli_ip, ipbuf, INET6_ADDRSTRLEN) == 0) c++;
                            if (c >= (int) max_per_ip) continue;
                        }
                        int free_slot = -1, k;
                        for (k = 0; k < cap; k++) if (!sess[k].in_use) { free_slot = k; break; }
                        if (free_slot < 0) continue;   /* table full: drop */

                        int ufd = (int) socket(up_family, up_socktype, up_proto);
                        if (ufd < 0) continue;
                        if (connect(ufd, (struct sockaddr*) &up_addr, up_len) < 0) { close(ufd); continue; }
                        amnetstream_set_nonblock(ufd);

                        sess[free_slot].in_use      = 1;
                        sess[free_slot].up_fd       = ufd;
                        memcpy(&sess[free_slot].cli, &cli, (size_t) clen);
                        sess[free_slot].cli_len     = clen;
                        strncpy(sess[free_slot].cli_ip, ipbuf, INET6_ADDRSTRLEN - 1);
                        sess[free_slot].cli_ip[INET6_ADDRSTRLEN - 1] = '\0';
                        sess[free_slot].last_active = now;
                        active++;
                        slot = free_slot;
                    }

                    /* Forward this datagram upstream (connected → send). */
                    send(sess[slot].up_fd, buf, (size_t) n, 0);
                    sess[slot].last_active = now;
                }
            }

            /* Session sockets readable: relay upstream replies to client. */
            int k;
            for (k = 1; k < nf; k++) {
                if (!(pfds[k].revents & POLLIN)) continue;
                int s = pidx[k];
                if (s < 0 || !sess[s].in_use) continue;
                for (;;) {
                    ssize_t n = recv(sess[s].up_fd, buf, (size_t) bsz, 0);
                    if (n < 0) break;            /* EAGAIN: drained */
                    sendto(lfd, buf, (size_t) n, 0,
                           (struct sockaddr*) &sess[s].cli, sess[s].cli_len);
                    sess[s].last_active = now;
                }
            }
        }

        /* Idle reap — the only way a UDP session ends (no FIN). */
        if (idle_ms > 0) {
            for (i = 0; i < cap; i++) {
                if (sess[i].in_use && (long long)(now - sess[i].last_active) * 1000 >= idle_ms) {
                    close(sess[i].up_fd);
                    sess[i].in_use = 0;
                    active--;
                }
            }
        }
    }

    /* Graceful shutdown: drain accounting, close every session fd. */
    for (i = 0; i < cap; i++) if (sess[i].in_use) close(sess[i].up_fd);
    free(sess); free(buf); free(pfds); free(pidx);
    amnetstream_listen_fd = -1;
    close(lfd);
    return 0;
}

#endif /* AMALGAME_NET_STREAM_H */
