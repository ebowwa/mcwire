"""Apple's d0xx DTLS plane, spoken by OpenSSL (in-process, no subprocess).

THE ENVELOPE (decoded live, R39/MC5): every d0xx datagram is EXACTLY

    0xd0 + <a standard DTLS 1.0 record>     (type ver epoch seq6 len payload)

i.e. the DTLS record with a one-byte marker prefix. Strip/prefix and the
records are plain DTLS.

THE SUITE: the Apple peer offers c019 c018 006d 003a 006c 0034 — where
c019/c018 are the old IETF-draft ECDH_anon codes (C015..C01A) that OpenSSL
still ships as `AECDH-AES256-SHA` / `AECDH-AES128-SHA`. That matches the
app's DTLS settings (authentication [0] = anonymous, no certs anywhere).
Apple's own modern SSLContext dropped these codes (it silently re-negotiated
006d=RSA and then aborted key-exchange with no certificate, -9806) — so the
engine is OpenSSL, giving us the anonymous handshake AND the keys.

THE ROLE (decoded from isServer[0/1] across sessions): the participant whose
identity-token last-4-bytes compare LOWER is the DTLS client (must send the
first ClientHello). Both IDs are random per session, so it flips — the ICE
service kicks the client role proactively when we lose the tie-break.
"""
import struct

from OpenSSL import SSL

from . import appdata, c1xx


# The app's stack fragments big records itself; OpenSSL does not — so we
# claim a jumbo link MTU and send whole records (IP fragments them; the
# peer's UDP reassembles — verified against the real app).
_LINK_MTU = 65000


def _make_ctx():
    # DTLS_METHOD (generic — roles switch via set_*_state) + @SECLEVEL=0 so
    # the anonymous (aNULL) suites are selectable at all.
    ctx = SSL.Context(SSL.DTLS_METHOD)
    ctx.set_cipher_list(
        "AECDH-AES256-SHA:AECDH-AES128-SHA:AES256-SHA:AES128-SHA:@SECLEVEL=0")
    return ctx


class Engine:
    """One DTLS endpoint over memory BIOs (datagrams in/out, d0-stripped)."""

    def __init__(self, role="server"):
        self.conn = SSL.Connection(_make_ctx())
        if role == "client":
            self.conn.set_connect_state()
        else:
            self.conn.set_accept_state()
        self.role = role
        self.handshake_done = False
        self._jumbo = False

    def feed(self, dtls_record):
        """Feed ONE DTLS record (d0 already stripped). Returns records to send."""
        out = []
        if dtls_record:
            try:
                self.conn.bio_write(dtls_record)
            except SSL.Error:
                return out
        # drive: handshake if incomplete, else decrypt-read (app data)
        while True:
            try:
                if not self.handshake_done:
                    self.conn.do_handshake()
                    self.handshake_done = True
                    # Jumbo link MTU for whole video records. ORDER MATTERS:
                    # SSL_OP_NO_QUERY_MTU on the CONNECTION (setting it on the
                    # context at build time zeroes the MTU and NO records are
                    # ever emitted), then DTLS_set_link_mtu — both strictly
                    # post-handshake.
                    try:
                        self.conn.set_options(SSL._lib.SSL_OP_NO_QUERY_MTU)
                        self.conn.set_ciphertext_mtu(_LINK_MTU)
                        self._jumbo = True
                    except Exception as ex:
                        print(f"[dtls] jumbo MTU failed: {ex}")
                else:
                    data = self.conn.recv(65536)
                    if data:
                        self.last_plain = data
            except SSL.WantReadError:
                break
            except SSL.WantWriteError:
                break
            except SSL.SysCallError:
                break
            except SSL.Error as e:
                self.last_error = str(e)
                break
            # collect whatever OpenSSL wants to send
            try:
                while True:
                    out.append(self.conn.bio_read(65536))
            except SSL.WantReadError:
                pass
            if not self.handshake_done:
                continue
            break
        # always drain pending output
        try:
            while True:
                out.append(self.conn.bio_read(65536))
        except SSL.WantReadError:
            pass
        return out

    def send_plain(self, data):
        """Encrypt app data. Returns records to transmit."""
        self.conn.sendall(data)
        out = []
        try:
            while True:
                out.append(self.conn.bio_read(65536))
        except SSL.WantReadError:
            pass
        return out


def new_state():
    return {"engine": None, "peer": None, "handshake_done": False,
            "client_kicked": False, "last_plain": b"", "last_error": ""}


def _masked(pid4):
    """The participant-id mask applies EVERYWHERE (R41): first byte & 0x7f.
    Raw comparison breaks when the peer's raw byte0 exceeds 0x7f — its
    masked id sorts lower and the roles disagree (both peers pick client;
    run 27: app a2330043 masks to 22330043 < our 7f59bc2a)."""
    return bytes([pid4[0] & 0x7F]) + pid4[1:4]


def decide_role(our_token8, peer_token8):
    """LOWER MASKED pid4 = DTLS client (verified vs isServer logs; MC9).
    Our pid4 is pinned 0x7f...... = the highest MASKED value, so we ALWAYS
    win the compare → always the server — the proven path."""
    if not our_token8 or not peer_token8:
        return "server"
    return "client" if _masked(our_token8[4:8]) < _masked(peer_token8[4:8]) else "server"


def kick_if_client(sock, dst, st, our_token8, peer_token8):
    """If we are the DTLS client, proactively emit our ClientHello to `dst`."""
    if st.get("client_kicked") or st.get("engine"):
        return
    if decide_role(our_token8, peer_token8) != "client":
        return
    st["client_kicked"] = True
    st["our_token8"] = our_token8
    st["peer_token8"] = peer_token8
    st["engine"] = Engine(role="client")
    st["peer"] = dst
    print("[dtls] WE are the DTLS client (lost the ID tie-break) — sending ClientHello")
    _pump(sock, dst, st, st["engine"].feed(b""))


def _pump(sock, dst, st, records):
    for rec in records:
        try:
            env = b"\xd0" + rec
            sock.sendto(env, dst)
            print(f"[dtls] -> d0{rec[0]:02x} {len(env)}B (OpenSSL)")
        except OSError:
            pass


def handle(d, who, sock, st):
    """One inbound d0xx datagram through the OpenSSL engine."""
    if d[:1] != b"\xd0" or len(d) < 14:
        return
    # d016 = handshake, d014 = CCS, d017 = app data. Only a HANDSHAKE record
    # may start the engine — stale d017 heartbeats from a previous session
    # (our process restarted; the app keeps sending to the port) must be
    # dropped, or the engine tries to handshake on app-data and every later
    # record fails (MCE regression).
    if d[1] not in (0x16, 0x14) and st.get("engine") is None:
        return
    if st.get("engine") is None and d[1] == 0x16:
        st["engine"] = Engine(role="server")
        st.setdefault("our_token8", st.get("_our8"))
        st.setdefault("peer_token8", st.get("_peer8"))
        print("[dtls] OpenSSL DTLS engine up (AECDH-anon)")
    st["peer"] = who
    eng = st["engine"]
    for rec in eng.feed(d[1:]):
        try:
            env = b"\xd0" + rec
            sock.sendto(env, who)
            print(f"[dtls] -> d0{rec[0]:02x} {len(env)}B (OpenSSL)")
        except OSError:
            pass
    st["handshake_done"] = eng.handshake_done
    if eng.handshake_done and not st.get("announced"):
        st["announced"] = True
        print("[dtls] HANDSHAKE COMPLETE (OpenSSL, anonymous)")
    plain = getattr(eng, "last_plain", b"")
    if plain:
        print(f"[dtls] plain ({len(plain)}B): {plain.hex()}")
        eng.last_plain = b""
        _answer_c1xx(sock, who, st, eng, plain)
    if getattr(eng, "last_error", "") and not st.get("err_shown"):
        st["err_shown"] = True
        print(f"[dtls] engine error: {eng.last_error[:160]}")


def _start_video(sock, dst, st, eng, ch):
    """Sustained video proof: stream JPEG frames as kind:"frame" envelopes —
    the exact path the shipped iOS builds use for their camera feed
    (P2PVideoReceiver decodes kind:"frame" payload as JPEG). Frames come
    from MC_VIDEO_FRAMES (colon-separated files, cycled) or a generated
    test pattern; ~MC_VIDEO_FPS (default 5)."""
    import base64
    import glob as _glob
    import threading as _th
    import time as _t

    fps = float(__import__("os").environ.get("MC_VIDEO_FPS", "5"))

    # frame sources in priority order: explicit env list, then any real JPEGs
    # (only files inside the app's receive budget — bigger records are
    # silently dropped by the peer's receive layer; R47)
    budget = 2700
    paths = []
    env_list = __import__("os").environ.get("MC_VIDEO_FRAMES", "")
    if env_list:
        paths = [p for p in env_list.split(":") if __import__("os").path.isfile(p)]
    if not paths:
        import os as _os
        for pat in ("~/Downloads/*.jpg", "~/Desktop/*.jpg",
                    "~/Pictures/*.jpg"):
            for p in _glob.glob(__import__("os").path.expanduser(pat)):
                try:
                    if _os.path.getsize(p) <= budget:
                        paths.append(p)
                except OSError:
                    pass
    paths = paths[:12]
    if not paths:
        # Self-contained fallback: generate 5 tiny distinct JPEGs (the R47
        # proven working set: small frames at 5fps) so the video proof runs
        # with zero external files. Pure-Python encoder, no deps.
        print("[video] no frame sources found — generating 5 test JPEGs")
        gen = _gen_test_jpegs()
        if not gen:
            print("[video] fallback generation failed")
            return
        paths = gen

    def read_jpeg(p):
        if isinstance(p, bytes):
            return p                      # generated frame (raw bytes)
        try:
            with open(p, "rb") as f:
                return f.read()
        except OSError:
            return None


    state = {"i": 0}

    send_lock = _th.Lock()      # serialize ALL engine use (OpenSSL conn is
                                # not thread-safe; the hello-responder and the
                                # streamer raced it — first video run's crash)

    def loop():
        print(f"[video] streaming {len(paths)} source(s) @ {fps}fps as kind:frame")
        sent = 0
        while sent < 200:                     # ~40s at 5fps
            jpeg = read_jpeg(paths[state["i"] % len(paths)])
            state["i"] += 1
            if jpeg and len(jpeg) > 3000:
                print(f"[video] skipping {len(jpeg)}B source (over the ~2.7KB receive budget)")
                jpeg = None
            if jpeg:
                payload = base64.b64encode(jpeg).decode()
                frame = {"v": 1, "id": f"frame-{sent:04d}", "kind": "frame",
                         "payload": payload}
                with send_lock:
                    try:
                        payload = ch.send_json(frame, counter=_ctr(), acked=0)
                        recs = eng.send_plain(payload)
                    except Exception as ex:
                        print(f"[video] engine error: {ex}")
                        return
                for rec in recs:
                    try:
                        n = sock.sendto(b"\xd0" + rec, dst)
                        print(f"[video] frame {sent}: payload {len(payload)}B -> record {len(rec)+1}B sent={n} to {dst}")
                    except OSError as ex:
                        print(f"[video] sendto failed: {ex}")
                        return
                sent += 1
            _t.sleep(1.0 / fps)
        print(f"[video] done: {sent} frames")

    # simple counter progression: the channel's last known counter +4 per frame
    base = {"c": 0x02000000}
    def _ctr():
        base["c"] += 4
        return base["c"]

    _th.Thread(target=loop, daemon=True).start()


def _gen_test_jpegs(n=5, w=128, h=96):
    """n small distinct solid-color JPEGs, ~1KB each — inside the peer's
    receive budget and distinct by color so receipts are distinguishable.
    Built with macOS `sips` (stdlib BMP -> JPEG); no pip deps."""
    import colorsys
    import struct
    import subprocess
    import tempfile

    out = []
    for i in range(n):
        r, g, b = [int(c * 255) for c in colorsys.hsv_to_rgb(i / n, 0.8, 1.0)]
        d = tempfile.mkdtemp(prefix="mcframe")
        bmp = f"{d}/f.bmp"
        jpg = f"{d}/f.jpg"
        row = bytes((b, g, r)) * w                  # BGR rows, bottom-up
        with open(bmp, "wb") as f:
            f.write(b"BM" + struct.pack("<IHHI", 54 + len(row) * h, 0, 0, 54))
            f.write(struct.pack("<IiiHHIIiiII", 40, w, h, 1, 24, 0,
                                len(row) * h, 0, 0, 0, 0))
            for _ in range(h):
                f.write(row)
        try:
            rc = subprocess.run(["sips", "-s", "format", "jpeg",
                                 "-s", "formatOptions", "50", bmp,
                                 "--out", jpg],
                                capture_output=True).returncode
            if rc == 0:
                out.append(open(jpg, "rb").read())
        except OSError:
            pass
    return out


def _answer_c1xx(sock, dst, st, eng, plain):
    """Decrypted app data: c1xx identity protocol or c105 JSON data ->
    answer in kind, encrypted through the same tunnel."""
    if not plain or plain[0] != 0xC1:
        return
    our8 = st.get("our_token8")
    peer8 = st.get("peer_token8")
    if not our8 or not peer8:
        print("[c1xx] identity tokens unknown — cannot answer")
        return
    if plain[1] == 0x05:
        # ---- c105 data frame: ACK + JSON reply ----
        if st.get("chan") is None:
            st["chan"] = appdata.Channel(our8, peer8)
            print("[app] JSON channel up")
        ch = st["chan"]
        for out in ch.on_data(plain):
            kind = "ack" if out[16] == 0x07 else "data"
            print(f"[app] -> c105 {kind} hex: {out.hex()}")
            for rec in eng.send_plain(out):
                try:
                    sock.sendto(b"\xd0" + rec, dst)
                    print(f"[app] -> c105 {kind} {len(out)}B (encrypted)")
                except OSError:
                    pass
        if ch.last_json:
            print(f"[app] <- JSON: {ch.last_json}")
            if ch.last_json.get("kind") == "hello" and not st.get("_frame_sent"):
                st["_frame_sent"] = True
                _start_video(sock, dst, st, eng, ch)
        return
    if st.get("c1xx") is None:
        st["c1xx"] = c1xx.Responder(our8, peer8)
    replies = st["c1xx"].on_packet(plain)
    for rep in replies:
        for rec in eng.send_plain(rep):
            try:
                sock.sendto(b"\xd0" + rec, dst)
                print(f"[c1xx] -> c1{rep[1]:02x} {len(rep)}B (encrypted)")
            except OSError:
                pass
        if st["c1xx"].complete:
            print("[c1xx] identity exchange COMPLETE")


def dump_session(st):
    """Transcript capture is handled live; kept for API compatibility."""
    return
