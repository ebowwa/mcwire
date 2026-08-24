"""App data over the session — c105 reliable frames carrying JSON envelopes.

Frame (live-verified against the app's decrypted stream):

DATA (69B+):
    c105 <len:2> <seq:2> <crc:2>        crc16/ARC at [6:8], field zeroed
    <tokA:8>                            sender composite ([my-pid4][peer])
    0500 <field:2>                      data marker + 2B nonce
    <tokB:8>                            rev4-each-half of SENDER's composite
    <acked:4>                           last-received counter (from peer)
    <counter:4>                         our counter (increments 4/8/12..)
    0001 <payload>                      embedded frame header + payload

ACK (44B): same header, `070b <field+0x6A75>` (constant delta, verified on
two real pairs), rev4each of the ack sender's composite, the DATA's acked
field + counter with byte0 += 4 (02000004 -> 06000004), then 8 zero bytes.

JSON envelopes (the app's channel protocol, same as its mc-cli sibling):
    {"v":1,"id":"<uuid>","kind":"hello","payload":"<b64 device JSON>"}
    {"v":1,"id":"<uuid>","kind":"ping"}  /  {"kind":"pong"}
    device JSON: {"model":"...","mac":"xx:xx:..","name":"..."}
"""
import base64
from typing import Optional
import json
import os
import struct
import uuid

from .c1xx import crc16_arc

ACK_DELTA = 0x6A75


def _finish(p: bytearray) -> bytes:
    p[2:4] = struct.pack(">H", len(p))
    p[6:8] = b"\x00\x00"
    p[6:8] = struct.pack(">H", crc16_arc(bytes(p)))
    return bytes(p)


def _rev(b: bytes) -> bytes:
    return b[::-1]


def data(our_c8: bytes, peer_c8: bytes, payload: bytes, counter: int,
         acked: int = 0, nonce: Optional[int] = None) -> bytes:
    """One c105 data frame. `nonce` = the ROUND nonce: both peers' DATA in a
    lockstep round carry the IDENTICAL nonce (real pair: 5456/5456, 4f51/
    4f51) — replies echo the received DATA's nonce verbatim."""
    p = bytearray()
    p += b"\xc1\x05" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    p += our_c8
    p += b"\x05\x00" + (struct.pack(">H", nonce) if nonce is not None
                         else os.urandom(2))
    p += our_c8[0:4][::-1] + our_c8[4:8][::-1]   # rev4each of OUR composite
    p += struct.pack(">I", acked)
    p += struct.pack(">I", counter)
    p += payload               # no frame marker — payload starts at [36:]
    return _finish(p)


def ack(our_c8: bytes, d: bytes) -> bytes:
    """ACK a received data frame `d` (all fields derived per the real pairs:
    tokB = full-8B reverse of the RECEIVER's composite = the data sender's;
    the acked-counter = data's counter with byte0 += 4, e.g. 02000004 →
    06000004 — NOT numeric +4)."""
    nonce = int.from_bytes(d[18:20], "big")
    p = bytearray()
    p += b"\xc1\x05" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00"
    p += our_c8
    p += b"\x07\x0b" + struct.pack(">H", (nonce + ACK_DELTA) & 0xFFFF)
    p += our_c8[0:4][::-1] + our_c8[4:8][::-1]   # rev4each of OUR composite
    _ = d  # (d supplies the acked fields below)
    p += d[28:32]                    # their acked field, echoed
    ctr = bytearray(d[32:36]); ctr[0] = (ctr[0] + 4) & 0xFF
    p += bytes(ctr)                  # counter, byte0 +4
    p += b"\x00" * 8
    return _finish(p)


def parse(d: bytes):
    """-> (counter:int, payload:bytes) or None."""
    if d[:2] != b"\xc1\x05" or d[16:18] != b"\x05\x00":
        return None
    counter = int.from_bytes(d[32:36], "big")
    payload = d[36:]     # the CLI pair's leading "0001" was its TEST payload
    return counter, payload


class Envelopes:
    """The app's JSON channel: answers hello, ping/pong."""

    def __init__(self, name="PYSRV", model="mcwire", mac=None):
        self.name = name
        self.model = model
        self.mac = mac or "02:%s" % ":".join(
            f"{b:02x}" for b in os.urandom(5))
        self.sent_hello = False

    def on_json(self, obj) -> Optional[dict]:
        """Handle one decoded envelope; return a reply envelope or None.

        Replies are regenerated on EVERY retransmission (no once-guard): the
        real pair advances in LOCKSTEP rounds where both sides emit DATA each
        round — the app's reliable layer retries its DATA until it sees OUR
        matching round's DATA, not merely an ACK."""
        kind = obj.get("kind")
        if kind == "hello":
            self.sent_hello = True
            return self.hello()
        if kind == "ping":
            return {"v": 1, "id": str(uuid.uuid4()).upper(), "kind": "pong"}
        return None

    def frame(self, jpeg: bytes) -> dict:
        """A video frame envelope (the app's P2PVideoReceiver decodes
        kind:"frame" payload as JPEG bytes — shipped iOS builds send their
        camera frames exactly this way, no native MC streams involved)."""
        b64 = base64.b64encode(jpeg).decode()
        return {"v": 1, "id": str(uuid.uuid4()).upper(), "kind": "frame",
                "payload": b64}

    def hello(self) -> dict:
        dev = {"model": self.model, "mac": self.mac, "name": self.name}
        b64 = base64.urlsafe_b64encode(json.dumps(dev).encode()).decode().rstrip("=")
        return {"v": 1, "id": str(uuid.uuid4()).upper(), "kind": "hello",
                "payload": b64}


class Channel:
    """Glue: c105 frames in/out over the DTLS engine, JSON payloads up."""

    def __init__(self, our_c8, peer_c8, envelopes=None):
        self.our = our_c8
        self.peer = peer_c8
        self.env = envelopes or Envelopes()
        self.counter = 4           # app's first data used 02000004; ours from 4
        self.acked = 0
        self.last_json = None

    def on_data(self, d: bytes):
        """A decrypted c105 data frame -> (acks_and_replies as c105 bytes).

        The acked/counter fields advance in LOCKSTEP rounds (both sides send
        identical values per round — observed in the real pair): round 2 =
        acked byte0+1 (00000000 -> 01000000), counter byte0+4 byte1+1 byte3+4
        (02000004 -> 06010008). We advance to the next round when replying."""
        out = []
        parsed = parse(d)
        if not parsed:
            return out
        counter, payload = parsed
        self.acked = int.from_bytes(d[28:32], "big")
        self.counter = counter
        out.append(ack(self.our, d))
        try:
            obj = json.loads(payload.decode("utf-8", "replace"))
            self.last_json = obj
            reply = self.env.on_json(obj)
            if reply:
                # LOCKSTEP (real pair, verified): the reply DATA in round N
                # carries THE SAME acked/ctr as the received DATA (both sides
                # emit 02000004 in round 1) — only the ACK advances (+4).
                # Rounds advance when both peers have NEW data to send.
                out.append(self.send_json(
                    reply, acked=int.from_bytes(d[28:32], "big"),
                    counter=int.from_bytes(d[32:36], "big"),
                    nonce=int.from_bytes(d[18:20], "big")))   # round nonce
        except (ValueError, AttributeError):
            pass                    # binary payload (video etc.) — ack only
        return out

    def send_json(self, obj, acked=None, counter=None, nonce: Optional[int] = None) -> bytes:
        payload = json.dumps(obj, separators=(",", ":")).encode()
        return data(self.our, self.peer, payload,
                    counter if counter is not None else self.counter + 4,
                    acked if acked is not None else self.acked, nonce=nonce)
