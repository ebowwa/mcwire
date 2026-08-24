"""The proven TCP invite flows — the exact byte sequences a real, unmodified
Apple stack ACCEPTS from a foreign peer.

Two roles, both validated live (the app logging "Invitation accepted" /
"Connected to participant"):

  browser_flow    we dial the app's advertiser: hello -> their greeting ->
                  invite -> caps -> their connect plist -> our connect ->
                  receipt. Stream order is load-bearing: hello#0, invite#1,
                  caps#2, connect#3 — and receipts are zero-indexed and
                  per-message (echo16 = receipt #0 for their hello,
                  73e2f9bb#1 for their invite, eaeba801#2 for their connect
                  plist). A mismatched receipt number is fatal ("Unexpected
                  sequence number").

  AdvertResponder the app browses US and dials our advert: greet in kind,
                  then dispatch by message type (the app-as-browser sends
                  echo/greeting/caps/invite in varying order; answer in kind).

The TCP connection must STAY OPEN after the exchange — the GCK/ICE phase
needs it alive.
"""
import plistlib
import random
import struct
import threading
import time

from . import env, framing, identity, plists


def browser_flow(s, session, token8, display):
    """Act as the browser/inviter toward the app's advertiser.

    Requires the peer's live identity: the app verifies greeting.idString
    encodes the SAME token as our invite sender peerID, and our connect
    plist's recipient must be the app's CURRENT identity — so their greeting
    must parse. No constants fallback: the self-referential identity rule
    makes a hardcoded peer identity useless across app restarts anyway.
    Returns True if the exchange completed."""
    idstr = identity.tok36(token8)
    fr = framing.Framer(s)

    # 1. send browser hello1 (54B shape: our identity)
    s.sendall(framing.hello_msg(idstr, display))
    print(f"[mc] -> hello1 ({idstr}+{display})")

    # 2. recv their greeting: may arrive as [echo16][hello54] in ONE frame
    #    or TWO separate frames — read both cases.
    g = fr.next(timeout=6)
    if not g:
        print("[mc] no greeting")
        return False
    hello = g
    if g[:2] == b"\x07\xd0" and int.from_bytes(g[4:8], "big") == 0 and len(g) == 16:
        # bare echo16 — the hello54 follows in the next frame
        g2 = fr.next(timeout=4)
        if g2:
            hello = g2
    elif len(g) >= 32 and g[:2] == b"\x07\xd0" and int.from_bytes(g[4:8], "big") == 0:
        hello = g[16:]   # concatenated [echo16][hello]
    parsed = identity.parse_greeting(hello) if hello[:2] == b"\x07\xd0" else None
    if parsed and parsed["token8"]:
        session.peer_token8 = parsed["token8"]
        session.peer_name = parsed["name"]
        print(f"[mc] <- their greeting: {parsed['idstr']}+{parsed['name']} "
              f"(token {parsed['token8'].hex()})")
    else:
        # without their live identity we cannot forge a coherent invite
        print(f"[mc] their greeting unparsed — aborting (identity rule)")
        if len(hello) < 40:
            print(f"[mc] RAW greeting bytes: {hello.hex()}")
        return False
    # 2b. receipt THEIR greeting (their #0) with our echo16 — browser duty too
    s.sendall(framing.echo16())
    print("[mc] -> echo16 (receipt #0 for their greeting)")

    # 3. (caps moves AFTER the invite — stream order: hello#0 invite#1 caps#2 connect#3)

    # 4. send OUR INVITE IMMEDIATELY — do NOT wait for their caps. When the
    #    app is tearing down a previous session its caps is delayed; waiting
    #    (the old 8s loop) stalled the invite ~9s, by which time the app's
    #    stale peer entry had timed out (the 1-in-3 failure mode, MCT-6).
    #    Caps is informational; the invite is the flow's next real message.

    # 5. send OUR INVITE immediately (their connect plist comes AFTER)
    our_pid = identity.peerid(token8, display)
    app_pid = identity.peerid(session.peer_token8, session.peer_name)
    inv = {
        "MCNearbyServiceInviteIDKey": random.randint(1, 255),
        "MCNearbyServiceRecipientPeerIDKey": app_pid,
        "MCNearbyServiceMessageIDKey": 1,
        "MCNearbyServiceSenderPeerIDKey": our_pid,
    }
    s.sendall(framing.wrap(framing.OP_DATA, 0x0000, 1,
                           plistlib.dumps(inv, fmt=plistlib.FMT_BINARY)))
    print(f"[mc] -> INVITE #1 (sender={token8.hex()})")
    # caps = stream message #2 (after the invite, mirroring the real browser)
    s.sendall(framing.caps_msg())
    print("[mc] -> caps #2")

    # 6. recv their ACCEPT + connect plist (WITH their blob)
    their_tok = None
    their_pid8 = None
    t0 = time.time()
    while time.time() - t0 < 10 and not their_tok:
        m = fr.next(timeout=3)
        if not m:
            continue
        if m[:2] == b"\x08\x34" and b"bplist00" in m:
            pi = m.find(b"bplist00")
            obj = plistlib.loads(m[pi:])
            blob = bytes(obj.get("MCNearbyServiceConnectionDataKey", b""))
            if blob:
                their_tok = identity.blob_token(blob)
                snd = obj.get("MCNearbyServiceSenderPeerIDKey", b"")
                if snd:
                    their_pid8 = bytes(snd)[:8]
                print(f"[mc] <- their connect plist (blob {len(blob)}B "
                      f"tok={their_tok.hex() if their_tok else '?'})")
        elif len(m) == 16 and m[:2] == b"\x08\x34":
            print(f"[mc] <- receipt {m[8:12].hex()} seq={int.from_bytes(m[12:16], 'big')}")
    if not their_tok or not their_pid8:
        print("[mc] no their token")
        return False

    # 6b. send OUR connect plist (our blob: their live participant ID + our token)
    our_tok4 = struct.pack(">I", random.getrandbits(32))
    blb = plists.browser_blob(our_tok4, identity.participant_id_le(their_pid8))
    conn = {
        "MCNearbyServiceConnectionDataKey": blb,
        "MCNearbyServiceInviteIDKey": inv["MCNearbyServiceInviteIDKey"],
        "MCNearbyServiceRecipientPeerIDKey": app_pid,
        "MCNearbyServiceMessageIDKey": 3,   # real browser: invite=1, caps=2, connect=3
        "MCNearbyServiceSenderPeerIDKey": our_pid,
    }   # NOTE: no AcceptInviteKey — that is the ADVERTISER's key
    s.sendall(framing.wrap(framing.OP_DATA, 0x0000, 2,
                           plistlib.dumps(conn, fmt=plistlib.FMT_BINARY)))
    print(f"[mc] -> our connect (tok {our_tok4.hex()}, blob port 16402=peer)")

    # 7. THEIR stream: #0=greeting (echo16-receipted), #1=connect plist
    #    -> receipt 73e2f9bb seq=1 (NOT eaeba801#2 — that mismatched fatally)
    s.sendall(framing.ack(1))
    print("[mc] -> receipt #1 (their plist)")

    try:
        session.peer_addr = s.getpeername()[0]
    except OSError:
        pass
    first = session.publish_exchange(our_tok4, their_tok, blb)
    print("[mc] tokens published to global ICE service" if first
          else "[mc] tokens NOT published (advert session owns ICE)")
    return True


class AdvertResponder(threading.Thread):
    """Accept the app's browser-side dials to OUR advert and run the proven
    responder exchange (echo16+hello, caps, connect-from-invite, receipts)."""

    def __init__(self, srv, session, inst, token8):
        super().__init__(daemon=True, name="advert-responder")
        self.srv = srv
        self.session = session
        self.inst = inst
        self.token8 = token8

    def run(self):
        while True:
            try:
                conn, who = self.srv.accept()
            except OSError:
                return
            print(f"[{time.time() % 1000:.3f}] ACCEPT from {who}")
            try:
                self.session.peer_addr = who[0]
            except Exception:
                pass
            threading.Thread(target=self._flow, args=(conn,), daemon=True).start()

    def _flow(self, conn):
        """State machine: greet, then dispatch by message type (the app-as-
        browser sends echo/greeting/caps/invite in varying order; answer in
        kind)."""
        s = self.session
        sent_connect = False
        try:
            fr = framing.Framer(conn)
            h1 = fr.next(timeout=8)
            if not h1:
                print("[mc] advert: NO DATA received (timeout)")
                return
            if h1[:2] != b"\x07\xd0":
                print(f"[mc] advert: non-hello first frame: {h1[:16].hex()}")
                return
            # the browser sends [echo16][hello54] — read BOTH before greeting
            if len(h1) == 16 and int.from_bytes(h1[4:8], "big") == 0:
                h2 = fr.next(timeout=4)   # their actual hello54
                if not h2:
                    print("[mc] advert: echo16 only, no hello")
                    return
            idstr = identity.tok36(self.token8)
            # greeting: echo16 + our hello
            conn.sendall(framing.echo16())
            print(f"[{time.time() % 1000:.3f}] advert greeting sent")
            conn.sendall(framing.hello_msg(idstr, env.DISPLAY_NAME))
            time.sleep(0.02)
            conn.sendall(framing.caps_msg())   # caps
            t0 = time.time()
            while time.time() - t0 < 75:   # TCP must stay alive through GCK+ICE
                m = fr.next(timeout=2)
                if not m:
                    continue
                if m[:2] == b"\x08\x98":
                    continue  # caps
                if len(m) == 16 and m[:2] == b"\x08\x34":
                    continue  # receipt
                if m[:2] == b"\x08\x34" and b"bplist00" in m:
                    pi = m.find(b"bplist00")
                    obj = plistlib.loads(m[pi:])
                    blob = bytes(obj.get("MCNearbyServiceConnectionDataKey", b""))
                    if blob and not sent_connect:
                        # THEIR connect plist arrived FIRST (before our connect):
                        # publish their token, still send ours
                        tok = identity.blob_token(blob)
                        if tok:
                            s.their_tok = s.their_tok or tok
                            print(f"[mc] advert-side their_tok={tok.hex()}")
                    if "MCNearbyServiceInviteIDKey" in obj and not blob:
                        # their INVITE -> reply with our connect immediately
                        bpid = obj.get("MCNearbyServiceSenderPeerIDKey", b"")
                        mypid = obj.get("MCNearbyServiceRecipientPeerIDKey", b"")
                        invid = obj.get("MCNearbyServiceInviteIDKey", 1)
                        our_tok4 = struct.pack(">I", random.getrandbits(32))
                        their_pid_live = bytes(bpid)[:8] if bpid else None
                        blb = plists.advertiser_blob(
                            our_tok4,
                            identity.participant_id_le(their_pid_live)
                            if their_pid_live else bytes.fromhex("9f140823"))
                        cp = {
                            "MCNearbyServiceConnectionDataKey": blb,
                            "MCNearbyServiceInviteIDKey": invid,
                            "MCNearbyServiceAcceptInviteKey": True,
                            "MCNearbyServiceRecipientPeerIDKey": bpid,
                            "MCNearbyServiceMessageIDKey": 2,
                            "MCNearbyServiceSenderPeerIDKey": mypid,
                        }
                        # connect ALONE (proven responder flow — no receipt before)
                        conn.sendall(framing.wrap(
                            framing.OP_DATA, 0x0000, 2,
                            plistlib.dumps(cp, fmt=plistlib.FMT_BINARY)))
                        sent_connect = True
                        s.publish_exchange(our_tok4, s.their_tok or b"\x00" * 4, blb)
                        print(f"[{time.time() % 1000:.3f}] invite answered + connect sent")
                    elif blob and sent_connect:
                        # their connect after ours -> extract their token, receipt, done
                        tok = identity.blob_token(blob)
                        if tok:
                            s.their_tok = s.their_tok or tok
                            print(f"[mc] advert-side their_tok={tok.hex()}")
                        conn.sendall(framing.ack(2))  # eaeba801#2
                        print("[mc] advert-side exchange complete (tokens live)")
            print(f"[mc] advert-side window done (sent_connect={sent_connect})")
        except Exception as ex:
            print(f"[mc] advert flow err: {ex}")
        # NOTE: do NOT close — the GCK/ICE phase needs this TCP alive
