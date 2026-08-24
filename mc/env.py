"""Runtime configuration — everything overridable via environment or mc.env.

Design goal: MultipeerConnectivity is a DYNAMIC mesh — peers come and go over
mDNS and the UDP session channel is per-peer on shared fixed ports (16401/
16402). The client follows that; fixed addresses are the exception, not the
rule:

1. DYNAMIC DEFAULT — the client learns peer addresses from the live protocol:
   browser role: the advertiser's address returned by mDNS discovery;
   advertiser role: the IP of the TCP peer that connected.
2. ENV OVERRIDE — only for cases discovery can't see (fixed addresses, tests
   against non-mDNS listeners). MC_PEER_IP accepts one or several addresses
   (space and/or comma separated) and REPLACES the dynamic default:

       export MC_PEER_IP=192.0.2.50,192.0.2.60     # two fixed peers

   MC_MY_IP is what we publish in mDNS / bind UDP for peers to reach us; the
   default is auto-detected from the default route (the UDP-connect trick
   sends no packets).

No machine-specific IP, hostname, or token is hardcoded anywhere in this
package (that is a deliberate, tested property — see git history for the
experimental clients that violated it and only worked on one LAN).
"""
import os
import re
import socket
import uuid


def _load_env_files(*paths):
    """Optionally load a repo-local config (root mc.env, or mc/.env) into the
    environment. Real shell-exported variables always win (setdefault); lines
    are KEY=VALUE, optionally `export`-prefixed."""
    for p in paths:
        try:
            with open(p, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    k = k.strip()
                    if k.startswith("export"):
                        k = k[len("export"):].strip()
                    v = v.strip().strip('"').strip("'")
                    if k:
                        os.environ.setdefault(k, v)
        except OSError:
            continue


_HERE = os.path.dirname(os.path.abspath(__file__))
_load_env_files(os.path.join(_HERE, "..", "mc.env"),
                os.path.join(_HERE, ".env"))


def _auto_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # No packets are sent; this only selects the default-route
            # interface and returns its local address.
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def _env_list(name):
    raw = os.environ.get(name, "").strip()
    return [a.strip() for a in re.split(r"[\s,]+", raw) if a.strip()] if raw else []


def peer_addrs(discovered=None, fallback="127.0.0.1"):
    """Peer IPs to dial: the MC_PEER_IP override list if set, otherwise the
    dynamically discovered address(es), otherwise the loopback fallback.

    `discovered` may be a string, or any iterable of strings (e.g. a live
    set of peer IPs maintained by the responder)."""
    addrs = _env_list("MC_PEER_IP")
    if not addrs and discovered:
        addrs = [discovered] if isinstance(discovered, str) else list(discovered)
    return addrs or [fallback]


def peer_targets(ports=(16402,), discovered=None, fallback="127.0.0.1"):
    """(ip, port) tuples to dial a peer, expanded over `ports`."""
    return [(a, p) for a in peer_addrs(discovered, fallback) for p in ports]


def _host_name():
    # macOS hostnames often already end in ".local"; strip it so identity
    # strings stay clean ("host" rather than "host.local").
    try:
        h = socket.gethostname()
        if h.endswith(".local"):
            h = h[: -len(".local")]
        return h
    except Exception:
        return "localhost"


MY_IP = os.environ.get("MC_MY_IP", "").strip() or _auto_ip()

# mDNS host identity. Real MC publishes a per-machine host (hostname.server
# and a per-machine UUID hostname). Both stay OUT of source; override via env
# when a fixed value is needed:
#   MC_SERVER_NAME -> MY_SERVER      (default: this host's name + .local.)
#   MC_HOST_UUID   -> MY_UUID_SERVER (default: random UUID + .local.)
MY_SERVER = os.environ.get("MC_SERVER_NAME", "").strip() or (_host_name() + ".local.")
MY_UUID_SERVER = (os.environ.get("MC_HOST_UUID", "").strip() or str(uuid.uuid4())) + ".local."

# The Bonjour service type of the target app's MC channel (without domain).
# The validated default is the probed app's channel; any app's type works.
SERVICE_TYPE = os.environ.get("MC_SERVICE_TYPE", "").strip() or "secondsee-mpc"

# Our display name, published in the TXT `_d` record and inside handshakes.
DISPLAY_NAME = os.environ.get("MC_DISPLAY_NAME", "").strip() or "PYSRV"

# TCP listener port for our own advert (0 = ephemeral, like real MC).
ADVERT_PORT = int(os.environ.get("MC_ADVERT_PORT", "0") or 0)

# Where the DTLS session dump is written as the session progresses: the
# live transcript (envelope records both directions, via the SSLContext
# bridge) plus any decrypted app data. Set empty to disable.
DTLS_DUMP = (os.environ["MC_DTLS_DUMP"].strip()
             if "MC_DTLS_DUMP" in os.environ else "/tmp/dtls_session.json")
