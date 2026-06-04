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
trap 'rm -rf "$BUILD_DIR"; [ -n "${PROXY:-}" ] && kill "$PROXY" 2>/dev/null; [ -n "${BACK:-}" ] && kill "$BACK" 2>/dev/null' EXIT

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

echo ""
if [ "$FAILED" -eq 0 ]; then echo -e "${GREEN}All tests passed${NC}"; else echo -e "${RED}Some tests FAILED${NC}"; exit 1; fi
