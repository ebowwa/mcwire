"""Handshake plists + ConnectionData blobs.

The handshake payloads are plain binary property lists (plistlib round-trips
them byte-exact). The ConnectionData blob inside the connect plist is an 89B
TLV structure carrying addresses, tokens and the advertised UDP port — it is
NOT forgeable from scratch yet, so both roles start from a captured template
(bundled in mc/templates/tcp-clipair/, extracted from a real connecting pair)
and patch in: our session token, THEIR live participant ID, the blob type
byte, and our advertised UDP port.

Template patch anchors are stable constants of the captures (token values the
real pair happened to use); they are search-and-replace anchors, not secrets.
"""
import os
import plistlib
import socket as _s

from . import env

_TPL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "tcp-clipair")

# UDP listener ports (see docs/mc-protocol.md): the GCK/ICE plane.
OUR_ICE_PORT = 16401   # 0x4011 little-endian = 11 40 in the blob
OUR_ALT_PORT = 16629   # outside Apple's shared 16397-16402 GCK port allocator


def _load_blob(fname):
    raw = open(os.path.join(_TPL_DIR, fname), "rb").read()
    i = raw.find(b"bplist00")
    obj = plistlib.loads(raw[i:])
    return bytearray(bytes(obj["MCNearbyServiceConnectionDataKey"]))


def invite_plist(recipient_nsdata, sender_nsdata, invid=1, msgid=1):
    return plistlib.dumps({
        "MCNearbyServiceInviteIDKey": invid,
        "MCNearbyServiceRecipientPeerIDKey": recipient_nsdata,
        "MCNearbyServiceMessageIDKey": msgid,
        "MCNearbyServiceSenderPeerIDKey": sender_nsdata,
    }, fmt=plistlib.FMT_BINARY)


def connect_plist(blob, recipient_nsdata, sender_nsdata, invid=1, msgid=2, accept=True):
    d = {
        "MCNearbyServiceConnectionDataKey": blob,
        "MCNearbyServiceInviteIDKey": invid,
        "MCNearbyServiceRecipientPeerIDKey": recipient_nsdata,
        "MCNearbyServiceMessageIDKey": msgid,
        "MCNearbyServiceSenderPeerIDKey": sender_nsdata,
    }
    # AcceptInviteKey is the ADVERTISER's key — the browser never sends it.
    if accept:
        d["MCNearbyServiceAcceptInviteKey"] = True
    return plistlib.dumps(d, fmt=plistlib.FMT_BINARY)


def browser_blob(our_tok4, participant_le):
    """Connect blob for the BROWSER role (we dialed their advertiser).

    Source: B_406.bin (the real browser's 406B connect plist from a captured
    connecting pair). Patched:
      - the 61-group token (53ace299) -> OUR session token
      - the uuid field (2ae7330c)     -> THEIR live participant ID (LE-read;
        equals the app's CURRENT id, changes on every app restart — must be
        extracted from their connect plist's SenderPeerIDKey)
      - advertised port 1240 (16402 LE) -> 1140 (16401 LE): where the
        RECEIVER sends us = OUR listener.

    BLOB TYPE IS ROLE-DEPENDENT: browser-role keeps the template's 8000 type
    byte (8002 broke the app's plist parse — "Got invite connect" never fired).
    """
    blb = _load_blob("B_406.bin")
    i61 = blb.find(bytes.fromhex("53ace299"))
    if i61 >= 0:
        blb[i61:i61 + 4] = our_tok4
    blb = bytearray(bytes(blb).replace(bytes.fromhex("2ae7330c"), participant_le))
    # LIVE-PATCH the address field (bytes [5:9], reversed ipv4) with OUR
    # CURRENT IP: the template carries the capture-time LAN address and the
    # peer sends its ICE checks wherever this says — a stale address sends
    # them to a network we left (the intermittent failure after any network
    # change, MCT-12).
    try:
        ip = _s.inet_aton(env.MY_IP)
    except OSError:
        ip = _s.inet_aton("192.0.2.1")           # doc-range fallback (RFC 5737)
    blb[5:9] = ip[::-1]                          # wire form is reversed
    # ALSO live-patch both v6 slots (bytes [9:41]): the template carries the
    # capture machine's old link-locals, and the peer's GCK sprays every
    # address in the blob — stale v6s burn its candidate rounds while the
    # working IPv4 path goes unvalidated (MCT-15: checks to the office v6
    # forever, one IPv4 exchange, no Connected).
    our_v6 = None
    try:
        import subprocess as _sp
        out = _sp.run(["ifconfig", "en0"], capture_output=True, text=True,
                      timeout=2).stdout
        for line in out.splitlines():
            ls = line.split()
            if len(ls) >= 2 and ls[0] == "inet6" and ls[1].lower().startswith("fe80"):
                our_v6 = _s.inet_pton(_s.AF_INET6, ls[1].split("%")[0])
                break
    except Exception:
        pass
    if our_v6:
        blb[9:25] = our_v6
        blb[25:41] = our_v6
    return bytes(blb).replace(bytes([0x12, 0x40]), bytes([0x11, 0x40]))


def advertiser_blob(our_tok4, participant_le):
    """Connect blob for the ADVERTISER role (they browsed and invited us).

    Source: A_conn446.bin (the real advertiser's 446B connect plist; identical
    to flow_53238_plist.bin). Patched:
      - the 61-group token (39b97b2c) -> OUR session token
        (the template also has a 6a-group field 2eb860d2 — the app's
        extraction path is unknown; patching only the 61-group is the proven
        configuration)
      - the A-template's uuid slot (612cf34c — NOTE: the B-template's was
        2ae7330c!) -> THEIR live participant ID
      - type byte 8000 -> 8002: real app sessions use 8002; THIS byte is what
        makes the app call GCKSessionEstablishConnection (which arms ICE)
      - advertised port 1240 (16402 LE) -> 1140 (16401 LE) = OUR listener.
        The app's checks go TO this port and our replies come FROM it —
        matching the advertised candidate. (The 8002 type byte is what
        triggers EstablishConnection, NOT the port value.)
    """
    blb = _load_blob("A_conn446.bin")
    i61 = blb.find(bytes.fromhex("39b97b2c"))
    if i61 >= 0:
        blb[i61:i61 + 4] = our_tok4
    blb = bytes(blb).replace(bytes.fromhex("612cf34c"), participant_le)
    if blb[1] == 0x00:
        blb = bytearray(blb)
        blb[1] = 0x02
        blb = bytes(blb)
    return blb.replace(bytes([0x12, 0x40]), bytes([0x11, 0x40]))
