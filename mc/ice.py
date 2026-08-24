"""The GCK layer under MC — and it is ICE/STUN.

Under MultipeerConnectivity sits Apple's private GCK session layer, which is
plain ICE: binding checks with custom attributes (8001/8003/8004/8005), role
attrs 8029 (controlling) / 802a (controlled), nomination via USE-CANDIDATE
(0025 + 8028 priority) answered with an 87B candidate blob (8009) — whose
final wire bug was one attribute-padding byte.

Layout rules learned the hard way (R28-32):
  - The GCK ICE port allocator is SHARED and dynamic: it hands out port pairs
    from 16397-16402 per session. Advertising a port in that range causes the
    peer's GCK to bind it as a local candidate — its own checks then
    self-deliver. We use 16629 (outside the allocator) for the blob-advertised
    port and bind 16401 + 16629.
  - HOLDING the whole 16380-16409 range starves the peer's allocator — it gets
    forced onto ephemeral ports and ICE validation never fires. Bind only the
    ports you advertise.
  - Spray at most ~1 binding request/second. Flooding (580/s) drowns the
    peer's check validation — real pairs exchange ~2 checks total.
"""
import os
import select
import socket
import struct
import threading
import time

from . import dtls, env, plists

STUN_MAGIC = 0x2112A442


def candidate_from_blob(blob, our_tok4):
    """Build the 87B 8009 candidate from our 89B ConnectionData blob
    (structure reverse-engineered from the real nomination response):

      0001 + 12 + ipv4rev + [v6 SECOND][v6 FIRST] (swapped) +
      61 uuid our_tok 5a 000100 801140 +
      6a uuid fresh 0a 000200 901140 +
      61 uuid fresh 0a 000300 911140
    """
    content = blob[4:]                    # strip 8000 0059 outer TLV
    head = content[:5]                    # 12 + reversed ipv4
    v6a = content[5:21]
    v6b = content[21:37]
    uuid4 = os.urandom(4)   # ONE uuid shared by all three groups (as observed
                            # in the real nomination response — keep it shared)
    g1 = bytes([0x61]) + uuid4 + our_tok4 + bytes([0x5A]) + bytes.fromhex("000100") + bytes.fromhex("801140")
    g2 = bytes([0x6A]) + uuid4 + os.urandom(4) + bytes([0x0A]) + bytes.fromhex("000200") + bytes.fromhex("901140")
    g3 = bytes([0x61]) + uuid4 + os.urandom(4) + bytes([0x0A]) + bytes.fromhex("000300") + bytes.fromhex("911140")
    return bytes.fromhex("0001") + head + v6b + v6a + g1 + g2 + g3


def _stun_reply(d, who, sock, st):
    """INSTANT STUN reply — pre-built template, only txid/8004/mapped patched.
    Must complete within the app's ~650ms ICE timeout."""
    txid = d[8:20]  # 12B
    # find 8004 in request (fixed offset 60 for standard 80B requests)
    req84 = d[64:68] if len(d) >= 68 else b"\x14\x3a\xaf\x78"
    ip, port = who[0], who[1]
    ip_int = (int(ip.split(".")[0]) << 24 | int(ip.split(".")[1]) << 16 |
              int(ip.split(".")[2]) << 8 | int(ip.split(".")[3]))
    # USERNAME = [sender]:[receiver] on EVERY message (pcap ground truth):
    # the app's request carries [app_tok]:[our_tok]; our response must SWAP
    # to [our_tok]:[app_tok] — echoing verbatim = invalid username = silent drop
    iu = d.find(b"\x00\x06\x00\x14")
    if iu >= 0:
        ru = d[iu + 4:iu + 24]             # 20B: [tok4][sep6][tok4][sep6]
        uname = (b"\x00\x06\x00\x14" + ru[10:20] + ru[0:10])  # swap halves
    else:
        their_tok = st.their_tok or b"\x00" * 4
        our_tok4 = st.our_tok4 or b"\x00" * 4
        uname = (b"\x00\x06\x00\x14" + our_tok4 + b"\x00" * 6 + b"\x00\x01" +
                 b"\x00" * 2 + their_tok + b"\x00" * 6 + b"\x00\x01" + b"\x00" * 2)
    # check for nomination (0025 USE-CANDIDATE)
    has_nom = b"\x00\x25\x00\x00" in d and b"\x80\x08" in d

    # build reply (single allocation)
    resp = bytearray(88)  # 20B header + 68B attrs
    resp[0:2] = b"\x01\x01"            # type = Binding Success
    resp[2:4] = b"\x00\x44"            # len = 68
    resp[4:8] = b"\x21\x12\xa4\x42"    # magic cookie
    resp[8:20] = txid                   # echo
    resp[20:44] = uname                 # USERNAME (halves swapped)
    # MAPPED-ADDRESS
    resp[44:46] = b"\x00\x01"
    resp[46:48] = b"\x00\x08"
    resp[48:50] = b"\x00\x01"           # family = IPv4
    resp[50:52] = struct.pack(">H", port)
    resp[52:56] = struct.pack(">I", ip_int)
    # 8001
    resp[56:58] = b"\x80\x01"; resp[58:60] = b"\x00\x04"; resp[60:64] = b"\x00\x00\x00\x06"
    # 8003
    resp[64:66] = b"\x80\x03"; resp[66:68] = b"\x00\x04"; resp[68:72] = b"\x00\x00\x03\xf2"
    # 8004 (echo request's)
    resp[72:74] = b"\x80\x04"; resp[74:76] = b"\x00\x04"; resp[76:80] = req84
    # 8005
    resp[80:82] = b"\x80\x05"; resp[82:84] = b"\x00\x04"; resp[84:88] = b"\x00\x00\x00\x06"  # real pairs use 6

    sock.sendto(bytes(resp), who)
    if has_nom:
        # the APP (controlling role) nominates (0025+8008); answer with 0101
        # + 8009 = our 87B candidate blob — that completes the pair
        cb = st.cand_blob
        if cb:
            our_tok4 = st.our_tok4 or os.urandom(4)
            cand = candidate_from_blob(cb, our_tok4)
            pad = (4 - len(cand) % 4) % 4
            nom_resp = bytearray(resp) + struct.pack(">HH", 0x8009, len(cand)) + cand + bytes([0xAA]) * pad
            nom_resp[2:4] = struct.pack(">H", len(nom_resp) - 20)
            sock.sendto(bytes(nom_resp), who)
            print("[ice] -> nomination answer + 8009")


class IceService(threading.Thread):
    """Global ICE+DTLS service — serves whichever session forms.

    Binds 16401 (where the app's GCK actually sends its checks) and 16629
    (our blob-advertised port, outside Apple's shared allocator range). Both
    are valid check endpoints. Sprays binding requests at the peer's standard
    listener 16402 once per second once both session tokens are known.
    """

    def __init__(self, session):
        super().__init__(daemon=True, name="ice-service")
        self.session = session
        self.stop_flag = threading.Event()
        self.last_check = None           # (addr, port) of the newest inbound check

    def _bind(self, port):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # jumbo datagrams: macOS's default UDP sndbuf (9216B) rejects our
        # ~11KB+ video frames with EMSGSIZE — raise it well past the TLS
        # 16KB record ceiling
        try:
            u.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 262144)
        except OSError:
            pass
        try:
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
        u.bind(("0.0.0.0", port))
        u.settimeout(0.3)
        return u

    def _spray_target(self):
        # THE APP's standard listener = 16402 (regression lesson: reading our
        # own blob advertised OUR port — we sprayed ourselves). The ADDRESS is
        # learned live from the TCP session (or MC_PEER_IP override).
        addr = self.session.peer_addr or (env.peer_addrs()[0] if env.peer_addrs() else None)
        return (addr, 16402) if addr else None

    def run(self):
        s = self.session
        socks = {p: self._bind(p) for p in (plists.OUR_ICE_PORT, plists.OUR_ALT_PORT)}
        print(f"[ice] bound ports: {sorted(socks.keys())}")
        # 8004: per-sender evolving counter (capture shows it advancing per
        # emitted packet; responses echo the request's value verbatim)
        ctr = [int.from_bytes(os.urandom(4), "big") & 0xFFFFFF00 | 0x0A]
        txids = set()

        def next_ctr():
            ctr[0] += 1
            return struct.pack(">I", ctr[0])

        while not self.stop_flag.is_set():
            if s.our_tok4 and s.their_tok and (time.time() - s.last_spray) > 1.0:
                dst = self._spray_target()
                if self.last_check:
                    # The peer's ICE lives where its CHECKS come from — not
                    # necessarily its advertised address (mini: advertises
                    # link-local 169.254.x, checks from LAN 192.0.2.10).
                    dst = self.last_check
                if dst:
                    # DTLS role: if we lost the ID tie-break (lower last4 =
                    # client), proactively send OUR ClientHello — the app (as
                    # server) just waits for it otherwise (deadlock).
                    # c1xx SESSION tokens are pid4 COMPOSITES (live-verified:
                    # in the real pair B's c101 tokA = [B-pid4][A-pid4], A's
                    # = [A-pid4][B-pid4] — perfect mirrors). pids = the last-4
                    # of each identity token (the same 4B the GCK/STUN layer
                    # uses). Sending the raw 8B identity token = the peer
                    # retransmits its c101 forever (MC7).
                    # c1xx composites use MASKED pid4s (run 31: the fresh
                    # app's c101 tokA = 22330043… — masked, though its raw
                    # token byte is a2; every earlier app had pid4 < 0x80 so
                    # masked == raw and the bug was invisible)
                    mp = lambda t: bytes([t[4] & 0x7F]) + t[5:8]
                    s.dtls["_our8"] = mp(s.our_token8) + mp(s.peer_token8)
                    s.dtls["_peer8"] = mp(s.peer_token8) + mp(s.our_token8)
                    dtls.kick_if_client(socks[plists.OUR_ICE_PORT], dst,
                                        s.dtls, s.our_token8, s.peer_token8)
                    s.last_spray = time.time()
                    # USERNAME = [their_tok]:[our_tok] (requester's view:
                    # remote:local) and role 8029 — browser/initiator is
                    # CONTROLLING (ground truth: the browser side sent 8029)
                    r = bytearray(bytes.fromhex(
                        "0001003c2112a442" "0001cf0bb53bad2d72dde30f"
                        "00060014" + s.their_tok.hex() + "000000000001" + s.our_tok4.hex() + "000000000001" +
                        "8001000400000006" "80030004000003f2" "80040004" + next_ctr().hex() +
                        "80290008" + os.urandom(4).hex() + "00000000"))
                    r[8:20] = bytes.fromhex("0001") + os.urandom(10)  # fresh txid every resend
                    txids.add(bytes(r[8:20]))
                    try:
                        socks[plists.OUR_ICE_PORT].sendto(bytes(r), dst)
                    except OSError:
                        pass
                    # ALSO spray the port that SENT us a check: the peer's GCK
                    # picks per-channel source ports (fail signature: its
                    # checks came from :16400 while we sprayed only :16402 —
                    # that pair never formed, MCT-20)
                    try:
                        extra = (self._spray_target() or (dst[0], 16402))
                        if extra != dst:
                            socks[plists.OUR_ICE_PORT].sendto(bytes(r), extra)
                    except OSError:
                        pass
            rl, _, _ = select.select(list(socks.values()), [], [], 0.3)
            if not rl:
                if int(time.time()) % 10 == 0:
                    print(f"[ice] alive; spraying={bool(s.our_tok4)}")
                continue
            sk = rl[0]
            try:
                d, who = sk.recvfrom(65536)
            except OSError:
                continue
            if d[:2] == b"\x00\x01":
                if d[8:20] in txids:
                    continue  # our own spray echoed back
                local_port = sk.getsockname()[1]
                if local_port not in (plists.OUR_ICE_PORT, plists.OUR_ALT_PORT):
                    continue  # only the advertised port forms the real pair
                print(f"[ice] <- STUN req from {who} txid={d[8:14].hex()}")
                self.last_check = who
                _stun_reply(d, who, sk, s)
            elif d[:1] == b"\xd0":
                print(f"[ice] <- d0xx d0{d[1]:02x} {len(d)}B")
                dtls.handle(d, who, sk, s.dtls)
                if s.dtls.get("handshake_done"):
                    # the SSLContext bridge owns the transcript (it records
                    # rx/tx itself); just flush the dump as it grows
                    dtls.dump_session(s.dtls)
            elif d[:2] == b"\x01\x01":
                i89 = d.find(struct.pack(">HH", 0x8009, 0x57))
                print(f"[ice] <- STUN success from {who}" + (f" +8009 CANDIDATE!" if i89 >= 0 else ""))
            else:
                print(f"[ice] <- other {d[:4].hex()} {len(d)}B from {who}")
        for u in socks.values():
            u.close()
