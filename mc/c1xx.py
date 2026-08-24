"""The c1xx identity exchange — the FIRST plaintext spoken inside the
encrypted d017 tunnel (and directly on the wire in .none sessions).

Live-observed exchange (caps/plain-none, verified again over DTLS in R40:
the app's first decrypted d017 payload IS its c101):

    them -> c101   hello (their tok8, const tokB)
    us   -> c101   hello (our tok8, same const)          [mirror]
    them -> c102   identity confirm (TLV list, ascii hex)
    us   -> c102   identity confirm (our TLVs)
    us   -> c104   done (18B)

Packet layout (c101 34B shown; c102/c103 share the 8B header):
    [0:2]  c1 0x0N      type
    [2:4]  len BE       TOTAL packet length
    [4:6]  0003/0000    per-type (c101=0003, others 0000)
    [6:8]  CRC16/ARC    over the whole packet with these bytes zeroed
    [8:16] tokA         sender's 8B identity token
    c101 tail (24:34):  0546f801 00100b02 00008000 00000000 0002
                        (tokB slot = the constant 0546f80100100b02 + tail)
    c102 body (16+):    0001 <sender-first4 bin> 0001 08 <sender-first4
                        ASCII-upper-hex> 0001 <peer-first4 bin> 000000 <B>
    c104:               header + tokA + 0000 (18B total)

CRC-16/ARC: poly 0x8005 reflected (0xA001), init 0, no xorout — verified
against every sample in three captures (evilsocket's claim, confirmed).
"""
import struct


def crc16_arc(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc & 0xFFFF


def _finish(p: bytearray) -> bytes:
    """Patch length + CRC into a c1xx packet."""
    p[2:4] = struct.pack(">H", len(p))
    p[6:8] = b"\x00\x00"
    p[6:8] = struct.pack(">H", crc16_arc(bytes(p)))
    return bytes(p)


def hello(our_tok8: bytes) -> bytes:
    """c101 — our identity hello (mirrors theirs)."""
    p = bytearray()
    p += b"\xc1\x01" + b"\x00\x00" + b"\x00\x03" + b"\x00\x00"
    p += our_tok8
    p += bytes.fromhex("0546f80100100b02")       # the constant tokB
    p += bytes.fromhex("00008000000000000002")   # tail
    return _finish(p)


def identity(our_tok8: bytes, peer_tok8: bytes, tail_byte: int = 0x38) -> bytes:
    """c102 — identity confirm (TLV list, both tokens)."""
    p = bytearray()
    p += b"\xc1\x02" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    p += our_tok8
    p += b"\x00\x01" + our_tok8[:4]
    p += b"\x00\x01\x08" + our_tok8[:4].hex().upper().encode()
    p += b"\x00\x01" + peer_tok8[:4]
    p += b"\x00\x00\x00" + bytes([tail_byte])
    return _finish(p)


def done(our_tok8: bytes) -> bytes:
    """c104 — exchange done."""
    p = bytearray()
    p += b"\xc1\x04" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    p += our_tok8
    p += b"\x00\x00"
    return _finish(p)


def mirror(d: bytes, our_pid4: bytes, peer_pid4: bytes) -> bytes:
    """Mirror a c1xx packet: swap every occurrence of peer-pid4 <-> our-pid4
    (both binary and ASCII-hex forms), zero+recompute the CRC. Counter fields
    ride along unchanged — the app accepted mirrored counters live."""
    out = bytearray(d)
    a = peer_pid4.hex().upper().encode()      # "3171FA35"
    b = our_pid4.hex().upper().encode()        # "FFFFFFFE"
    blob = bytes(out)
    # binary swaps (avoid overlapping by doing a single pass with a map)
    res = bytearray()
    i = 0
    while i < len(blob):
        if blob[i:i+4] == peer_pid4:
            res += our_pid4; i += 4
        elif blob[i:i+4] == our_pid4:
            res += peer_pid4; i += 4
        elif blob[i:i+8] == a:
            res += b; i += 8
        elif blob[i:i+8] == b:
            res += a; i += 8
        else:
            res.append(blob[i]); i += 1
    res[6:8] = b"\x00\x00"
    res[6:8] = struct.pack(">H", crc16_arc(bytes(res)))
    return bytes(res)


class Responder:
    """Drives the exchange from our side given live tokens.

    Usage: feed every decrypted app-data record (and, in .none sessions,
    every bare c1xx datagram) to .on_packet; send back what it returns."""

    def __init__(self, our_tok8, peer_tok8):
        self.our = our_tok8
        self.peer = peer_tok8
        self.our_pid4 = our_tok8[:4]     # composite tokens: [my-pid4][peer-pid4]
        self.peer_pid4 = peer_tok8[:4]
        self.sent_hello = False
        self.sent_identity = False
        self.sent_c103 = False
        self.done_sent = False
        self.complete = False        # saw their c104 (or sent ours after c102)

    def on_packet(self, d: bytes):
        """Returns a list of c1xx packets to transmit (possibly empty)."""
        if not d or d[0] != 0xC1:
            return []
        sub = d[1]
        out = []
        if sub == 0x01 and not self.sent_hello:
            # their hello: mirror ours back
            out.append(hello(self.our))
            self.sent_hello = True
        elif sub == 0x02 and not self.sent_identity:
            # their identity confirm: reply ours (c104 comes ONLY after
            # their c103 — sending it early leaves their c103 unanswered and
            # the MC session times out at ~12s, MC8)
            out.append(identity(self.our, self.peer))
            self.sent_identity = True
        elif sub == 0x03:
            # their c103 = full two-peer identity packet; answer EVERY
            # retransmit with a fresh mirror (their retransmit means the
            # previous reply wasn't consumed), c104 once.
            out.append(mirror(d, self.our_pid4, self.peer_pid4))
            if not self.done_sent:
                out.append(done(self.our))
                self.done_sent = True
                self.complete = True
        elif sub == 0x08:
            # c108 keepalive/query (20B): mirror it back
            out.append(mirror(d, self.our_pid4, self.peer_pid4))
        elif sub == 0x04:
            self.complete = True
        return out
