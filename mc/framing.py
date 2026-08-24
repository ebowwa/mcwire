"""TCP message framing — the wire format under every MC TCP exchange.

Header (16B, big-endian):  op(2B) | flags(2B) | bodylen(4B) | CRC32(4B) | seq(4B)  + body

The CRC is zlib.crc32 of the whole message with bytes 8..11 (the CRC field
itself) zeroed — verified against every observed message type, multi-run.

Messages are simply concatenated on the stream (no top-level length prefix);
each message's own bodylen field frames it.

Known ops (see docs/mc-protocol.md):
  0x07d0  hello / echo    flags 0000 = identity hello, 0001 = echo/receipt
  0x0834  data / ack      flags 0000 = payload (binary plist), 0001 = receipt
  0x0898  capabilities    16B, one per side
"""
import socket
import struct
import zlib

OP_HELLO = 0x07D0
OP_DATA = 0x0834
OP_CAPS = 0x0898


def mc_crc(msg):
    m = bytearray(msg)
    m[8:12] = b"\x00" * 4
    return zlib.crc32(bytes(m)) & 0xFFFFFFFF


def wrap(op, flags, seq, body=b""):
    """Build one framed message: header + body, CRC patched into bytes 8..11."""
    msg = struct.pack(">HHI", op, flags, len(body)) + b"\x00" * 4 + struct.pack(">I", seq) + body
    crc = mc_crc(msg)
    return msg[:8] + struct.pack(">I", crc) + msg[12:]


def echo16():
    """16B echo/receipt hello (flags 0001) — receipts THEIR greeting (their #0)."""
    return wrap(OP_HELLO, 0x0001, 0)


def hello_msg(idstr, display):
    """Identity hello: `idstr+display` NUL-terminated, the 00000006 + len form."""
    name = (idstr + "+" + display).encode()
    body = struct.pack(">I", 6) + struct.pack(">H", len(name) + 1) + name + b"\x00"
    return wrap(OP_HELLO, 0x0000, 0, body)


def caps_msg():
    return wrap(OP_CAPS, 0x0000, 1, b"")


def ack(seq):
    """Receipt for stream message #seq (op 0834, flags 0001)."""
    return wrap(OP_DATA, 0x0001, seq, b"")


class Framer:
    """Exact MC framing: op(2B) flags(2B) bodylen(4B) crc(4B) seq(4B) body.
    Returns a frame the moment it is complete — no boundary wait. On timeout
    or EOF with a partial frame buffered, flushes and returns the partial
    bytes (callers use that to inspect half-formed peer output)."""

    def __init__(self, s):
        self.s = s
        self.buf = bytearray()

    def next(self, timeout=10):
        self.s.settimeout(timeout)
        while True:
            if len(self.buf) >= 16:
                blen = int.from_bytes(self.buf[4:8], "big")
                if len(self.buf) >= 16 + blen:
                    m = bytes(self.buf[:16 + blen])
                    del self.buf[:16 + blen]
                    return m
            try:
                d = self.s.recv(4096)
            except socket.timeout:
                if self.buf:
                    m = bytes(self.buf)
                    self.buf.clear()
                    return m
                return None
            if not d:
                if self.buf:
                    m = bytes(self.buf)
                    self.buf.clear()
                    return m
                return None
            self.buf += d
