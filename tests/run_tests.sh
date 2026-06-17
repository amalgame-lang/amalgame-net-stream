#!/bin/bash
# ─────────────────────────────────────────────────────────────────────
#  amalgame-net-stream — test runner
#  Usage: ./tests/run_tests.sh [path-to-amc]
#
#  Runs:
#    1. Unit tests        (tests/stream_test.am) — validation / defaults
#    2. Binary-safety     — a payload with embedded NUL bytes + every
#                           byte value round-trips byte-for-byte through
#                           the proxy (the reason the C splice exists)
#    3. Per-source-IP cap — over-cap connections are dropped immediately
#    4. Graceful shutdown — SIGTERM makes the proxy exit cleanly
# ─────────────────────────────────────────────────────────────────────
set -u

PKG_DIR="$(cd "$(dirname "$0")/.." && pwd)"

AMC=""
if   [ -n "${1:-}" ];                 then AMC="$1"
elif [ -x "./amc" ];                  then AMC="$(pwd)/amc"
elif command -v amc >/dev/null 2>&1;  then AMC="$(command -v amc)"
elif [ -x "$PKG_DIR/../Amalgame/amc" ]; then AMC="$PKG_DIR/../Amalgame/amc"
elif [ -x "$HOME/.local/bin/amc" ];   then AMC="$HOME/.local/bin/amc"
fi
[ -x "$AMC" ] || { echo "error: amc binary not found"; exit 2; }

RUNTIME_DIR=""
if   [ -n "${AMC_RUNTIME:-}" ] && [ -d "$AMC_RUNTIME" ];    then RUNTIME_DIR="$AMC_RUNTIME"
elif [ -d "$PKG_DIR/../Amalgame/runtime" ];                then RUNTIME_DIR="$PKG_DIR/../Amalgame/runtime"
elif [ -d "$HOME/.amalgame/runtime" ];                     then RUNTIME_DIR="$HOME/.amalgame/runtime"
fi

HDR="$PKG_DIR/runtime/Amalgame_Net_Stream.h"
BUILD_DIR=$(mktemp -d -t amalgame-net-stream-XXXXXX)
trap 'rm -rf "$BUILD_DIR"; [ -n "${PROXY:-}" ] && kill "$PROXY" 2>/dev/null; [ -n "${BACK:-}" ] && kill "$BACK" 2>/dev/null; [ -n "${UPROXY:-}" ] && kill "$UPROXY" 2>/dev/null; [ -n "${UPROXY2:-}" ] && kill "$UPROXY2" 2>/dev/null; [ -n "${UBACK:-}" ] && kill "$UBACK" 2>/dev/null; for V in TLBPROXY TBA TBB ULBPROXY UBA UBB; do eval "P=\${$V:-}"; [ -n "$P" ] && kill "$P" 2>/dev/null; done' EXIT

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
echo "Using amc: $AMC"
cd "$PKG_DIR"
FAILED=0

# ── Build the facade once ────────────────────────────────────────────
"$AMC" --lib -o "$BUILD_DIR/facade" facade.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -include "$HDR" -c "$BUILD_DIR/facade.c" -o "$BUILD_DIR/facade.o" 2>"$BUILD_DIR/gcc.log" \
    || { echo -e "${RED}facade build failed${NC}"; cat "$BUILD_DIR/gcc.log"; exit 1; }

# ── 1. Unit tests ────────────────────────────────────────────────────
echo -e "\n── unit tests ──"
"$AMC" -o "$BUILD_DIR/unit" tests/stream_test.am --external facade.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -include "$HDR" "$BUILD_DIR/unit.c" "$BUILD_DIR/facade.o" \
    -lgc -lm -lpthread -o "$BUILD_DIR/unit" 2>"$BUILD_DIR/gcc.log" \
    || { echo -e "${RED}unit build failed${NC}"; cat "$BUILD_DIR/gcc.log"; exit 1; }
UNIT_OUT="$("$BUILD_DIR/unit")"
echo "$UNIT_OUT"
echo "$UNIT_OUT" | grep -q "\[FAIL\]" && FAILED=1

# ── Build the example proxy for integration probes ───────────────────
"$AMC" -o "$BUILD_DIR/proxy" examples/tcp_forward.am --external facade.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -include "$HDR" "$BUILD_DIR/proxy.c" "$BUILD_DIR/facade.o" \
    -lgc -lm -lpthread -o "$BUILD_DIR/proxy" 2>"$BUILD_DIR/gcc.log" \
    || { echo -e "${RED}example build failed${NC}"; cat "$BUILD_DIR/gcc.log"; exit 1; }

command -v python3 >/dev/null 2>&1 || { echo -e "${RED}python3 needed for integration tests${NC}"; exit 2; }

# Threaded echo backend on 19001
cat > "$BUILD_DIR/echo.py" <<'PY'
import socket, threading
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", 19001)); srv.listen(16)
def h(c):
    try:
        while True:
            d = c.recv(65536)
            if not d: break
            c.sendall(d)
    except Exception: pass
    finally: c.close()
while True:
    try: c,_ = srv.accept()
    except Exception: break
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 "$BUILD_DIR/echo.py" & BACK=$!
sleep 0.3
NS_LISTEN=19000 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19001 "$BUILD_DIR/proxy" >/dev/null 2>&1 & PROXY=$!
sleep 0.4

# ── 2. Binary-safety round-trip ──────────────────────────────────────
echo -e "\n── binary-safety (NUL bytes + all 256 values round-trip) ──"
if python3 - <<'PY'
import socket, sys
payload = bytes(range(256)) * 8 + b"\x00\x00\x00\x08PGwire\x00\x00binary-after-nul\xff\xfe\x00"
s = socket.create_connection(("127.0.0.1", 19000), timeout=3); s.sendall(payload)
got = b""
while len(got) < len(payload):
    c = s.recv(65536)
    if not c: break
    got += c
s.close()
sys.exit(0 if got == payload else 1)
PY
then echo -e "${GREEN}[PASS]${NC} byte-exact incl. NUL bytes (2079 B)"; else echo -e "${RED}[FAIL]${NC} payload corrupted through proxy"; FAILED=1; fi

# ── 3. Per-source-IP cap enforcement (security abuse test) ───────────
#      Second proxy on :19002 with MaxPerIp=2: open 2 slots, then a 3rd
#      connection from the same IP must be dropped immediately, while an
#      admitted connection still round-trips.
NS_LISTEN=19002 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19001 \
    NS_MAX_PER_IP=2 NS_IDLE_MS=5000 "$BUILD_DIR/proxy" >/dev/null 2>&1 & PROXY2=$!
sleep 0.4
echo -e "\n── per-source-IP cap: 3rd conn dropped, admitted conn works ──"
if python3 - <<'PY'
import socket, sys
held = []
try:
    # take both slots (held open — counted from admit)
    for _ in range(2):
        c = socket.create_connection(("127.0.0.1", 19002), timeout=3)
        held.append(c)
    # an admitted slot must round-trip (conn #1)
    held[0].sendall(b"ok\x00ok")
    held[0].settimeout(2)
    a = held[0].recv(16)
    if a != b"ok\x00ok":
        print("admitted conn did not echo:", a); sys.exit(1)
    # 3rd conn from same IP: over cap → proxy accepts then closes it.
    # The client sees either a clean EOF (b"") or a RST (ConnectionReset);
    # both mean "dropped, never spliced to upstream".
    dropped = False
    try:
        over = socket.create_connection(("127.0.0.1", 19002), timeout=3)
        over.settimeout(2)
        over.sendall(b"should-be-dropped")
        dropped = (over.recv(64) == b"")
        over.close()
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError):
        dropped = True
    sys.exit(0 if dropped else 1)
finally:
    for c in held:
        try: c.close()
        except Exception: pass
PY
then echo -e "${GREEN}[PASS]${NC} over-cap connection dropped; admitted connection served"; else echo -e "${RED}[FAIL]${NC} per-IP cap not enforced"; FAILED=1; fi
kill "$PROXY2" 2>/dev/null

# ── 4. Graceful shutdown ─────────────────────────────────────────────
echo -e "\n── graceful shutdown (SIGTERM) ──"
kill -TERM "$PROXY" 2>/dev/null
for _ in $(seq 1 20); do kill -0 "$PROXY" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$PROXY" 2>/dev/null; then echo -e "${RED}[FAIL]${NC} proxy did not exit on SIGTERM"; kill -9 "$PROXY" 2>/dev/null; FAILED=1
else echo -e "${GREEN}[PASS]${NC} exited cleanly on SIGTERM"; fi
PROXY=""

# ── 5. UDP forwarding (datagram round-trip incl. NUL bytes) ──────────
#      Build the UDP example, front a UDP echo backend, and prove a
#      datagram with embedded NULs comes back byte-for-byte through the
#      per-client session table — then SIGTERM exits cleanly.
echo -e "\n── udp build ──"
"$AMC" -o "$BUILD_DIR/udp" examples/udp_forward.am --external facade.am >/dev/null 2>&1
gcc -O2 -Iruntime -I"$RUNTIME_DIR" -include "$HDR" "$BUILD_DIR/udp.c" "$BUILD_DIR/facade.o" \
    -lgc -lm -lpthread -o "$BUILD_DIR/udp" 2>"$BUILD_DIR/gcc.log" \
    || { echo -e "${RED}udp example build failed${NC}"; cat "$BUILD_DIR/gcc.log"; exit 1; }

# UDP echo backend on 19011
cat > "$BUILD_DIR/udpecho.py" <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 19011))
while True:
    try:
        data, addr = s.recvfrom(65536)
    except Exception:
        break
    s.sendto(data, addr)
PY
python3 "$BUILD_DIR/udpecho.py" & UBACK=$!
sleep 0.3
NS_LISTEN=19010 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19011 \
    NS_IDLE_MS=5000 "$BUILD_DIR/udp" >/dev/null 2>&1 & UPROXY=$!
sleep 0.4

echo -e "\n── udp datagram round-trip (NUL bytes + all 256 values) ──"
if python3 - <<'PY'
import socket, sys
payload = bytes(range(256)) + b"\x00\x00DNS\x00query\xff\x00after-nul"
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(payload, ("127.0.0.1", 19010))
got, _ = s.recvfrom(65536)
s.close()
sys.exit(0 if got == payload else 1)
PY
then echo -e "${GREEN}[PASS]${NC} udp datagram byte-exact incl. NUL bytes"; else echo -e "${RED}[FAIL]${NC} udp datagram corrupted/lost through proxy"; FAILED=1; fi

# ── UDP per-source-IP cap: 3rd session from same IP dropped ──────────
#      Proxy on :19012 with MaxPerIp=2. Three client sockets (same IP,
#      distinct source ports = 3 sessions): the first two echo, the
#      third is over the per-IP cap → its datagram is dropped (no reply).
NS_LISTEN=19012 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19011 \
    NS_MAX_PER_IP=2 NS_IDLE_MS=5000 "$BUILD_DIR/udp" >/dev/null 2>&1 & UPROXY2=$!
sleep 0.4
echo -e "\n── udp per-source-IP cap: 3rd session dropped, first two work ──"
if python3 - <<'PY'
import socket, sys
def mk():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1.5); return s
socks = [mk() for _ in range(3)]
try:
    def echoes(s, tag):
        s.sendto(tag, ("127.0.0.1", 19012))
        try:    return s.recvfrom(64)[0] == tag
        except socket.timeout: return False
    a = echoes(socks[0], b"one")
    b = echoes(socks[1], b"two")
    c = echoes(socks[2], b"three")     # over per-IP cap → dropped
    sys.exit(0 if (a and b and not c) else 1)
finally:
    for s in socks:
        try: s.close()
        except Exception: pass
PY
then echo -e "${GREEN}[PASS]${NC} over-cap udp session dropped; first two served"; else echo -e "${RED}[FAIL]${NC} udp per-IP cap not enforced"; FAILED=1; fi
kill "$UPROXY2" 2>/dev/null; UPROXY2=""

# ── 6. Multi-upstream load balancing (round-robin distribution) ──────
#      Two identity backends; a round-robin proxy in front. Several
#      connections / sessions must reach BOTH backends.
echo -e "\n── TCP round-robin: connections reach both upstreams ──"
# Identity TCP backends: announce a 1-byte id on connect, then echo.
cat > "$BUILD_DIR/idtcp.py" <<'PY'
import socket, threading, sys
port = int(sys.argv[1]); ident = sys.argv[2].encode()
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port)); srv.listen(16)
def h(c):
    try:
        c.sendall(ident)
        while True:
            d = c.recv(4096)
            if not d: break
            c.sendall(d)
    except Exception: pass
    finally: c.close()
while True:
    try: c, _ = srv.accept()
    except Exception: break
    threading.Thread(target=h, args=(c,), daemon=True).start()
PY
python3 "$BUILD_DIR/idtcp.py" 19031 A & TBA=$!
python3 "$BUILD_DIR/idtcp.py" 19032 B & TBB=$!
sleep 0.3
NS_LISTEN=19030 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19031 \
    NS_UPSTREAM2_HOST=127.0.0.1 NS_UPSTREAM2_PORT=19032 NS_STRATEGY=round_robin \
    "$BUILD_DIR/proxy" >/dev/null 2>&1 & TLBPROXY=$!
sleep 0.4
if python3 - <<'PY'
import socket, sys
seen = set()
for _ in range(6):
    s = socket.create_connection(("127.0.0.1", 19030), timeout=3)
    seen.add(s.recv(1)); s.close()
sys.exit(0 if seen == {b"A", b"B"} else 1)
PY
then echo -e "${GREEN}[PASS]${NC} round-robin hit both TCP upstreams"; else echo -e "${RED}[FAIL]${NC} round-robin did not balance TCP"; FAILED=1; fi
kill "$TLBPROXY" "$TBA" "$TBB" 2>/dev/null; TLBPROXY=""; TBA=""; TBB=""

echo -e "\n── UDP round-robin: sessions reach both upstreams ──"
# Identity UDP backends: reply with id-prefixed datagram.
cat > "$BUILD_DIR/idudp.py" <<'PY'
import socket, sys
port = int(sys.argv[1]); ident = sys.argv[2].encode()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", port))
while True:
    try: data, addr = s.recvfrom(65536)
    except Exception: break
    s.sendto(ident + data, addr)
PY
python3 "$BUILD_DIR/idudp.py" 19041 A & UBA=$!
python3 "$BUILD_DIR/idudp.py" 19042 B & UBB=$!
sleep 0.3
NS_LISTEN=19040 NS_UPSTREAM_HOST=127.0.0.1 NS_UPSTREAM_PORT=19041 \
    NS_UPSTREAM2_HOST=127.0.0.1 NS_UPSTREAM2_PORT=19042 NS_STRATEGY=round_robin \
    NS_IDLE_MS=5000 "$BUILD_DIR/udp" >/dev/null 2>&1 & ULBPROXY=$!
sleep 0.4
if python3 - <<'PY'
import socket, sys
seen = set()
for _ in range(6):                       # distinct source ports → distinct sessions
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(2)
    s.sendto(b"q", ("127.0.0.1", 19040))
    seen.add(s.recvfrom(8)[0][:1]); s.close()
sys.exit(0 if seen == {b"A", b"B"} else 1)
PY
then echo -e "${GREEN}[PASS]${NC} round-robin hit both UDP upstreams"; else echo -e "${RED}[FAIL]${NC} round-robin did not balance UDP"; FAILED=1; fi
kill "$ULBPROXY" "$UBA" "$UBB" 2>/dev/null; ULBPROXY=""; UBA=""; UBB=""

echo -e "\n── udp graceful shutdown (SIGTERM) ──"
kill -TERM "$UPROXY" 2>/dev/null
for _ in $(seq 1 20); do kill -0 "$UPROXY" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$UPROXY" 2>/dev/null; then echo -e "${RED}[FAIL]${NC} udp proxy did not exit on SIGTERM"; kill -9 "$UPROXY" 2>/dev/null; FAILED=1
else echo -e "${GREEN}[PASS]${NC} udp proxy exited cleanly on SIGTERM"; fi
UPROXY=""
kill "$UBACK" 2>/dev/null; UBACK=""

echo ""
if [ "$FAILED" -eq 0 ]; then echo -e "${GREEN}All tests passed${NC}"; else echo -e "${RED}Some tests FAILED${NC}"; exit 1; fi
