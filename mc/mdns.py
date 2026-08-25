"""Bonjour discovery — advertise ourselves, and browse for the target app.

This is the non-Apple discovery stack (Python zeroconf, modeling what an
Android NsdManager or any foreign implementation would do): a real
MCNearbyServiceBrowser finds and parses our adverts, and our browser finds
theirs.

Discovery record format (derived; see README):
    service  = _<type>._tcp.local.
    instance = base36 of the peer's 8-byte token      (NOT random hex)
    TXT _d   = display name
    SRV      = ephemeral TCP port, host = per-machine UUID hostname

Environmental gotchas (learned the hard way):
  - Python zeroconf custom `.local` hostnames do not resolve from remote
    NSNetService — the A record is served by the Python process but the
    peer's mDNSResponder doesn't reliably query it. Use the system hostname
    (env.MY_SERVER) or register the A record with the OS.
  - Stale mDNS registrations from prior runs confuse the peer's browser;
    use token-derived instance names and unregister cleanly.
"""
import socket
import time

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

from . import env, identity


def service_domain(service_type=None):
    return "_" + (service_type or env.SERVICE_TYPE) + "._tcp.local."


def advertise(zc, inst, port, display=None, service_type=None, ip=None, server=None):
    """Register our advert. instance = base36(token8) — the peer's browser
    derives our identity from it and checks it against our greeting (any
    mismatch = close)."""
    info = ServiceInfo(
        service_domain(service_type),
        f"{inst}.{service_domain(service_type)}",
        addresses=[socket.inet_aton(ip or env.MY_IP)],
        port=port,
        server=server or env.MY_SERVER,
        properties={"_d": display or env.DISPLAY_NAME},
    )
    zc.register_service(info)
    return info


class _Collector:
    def __init__(self):
        self.found = {}

    def add_service(self, zc, t, name):
        info = zc.get_service_info(t, name, timeout=2000)
        if info:
            self.found[name] = info

    def update_service(self, zc, t, name):
        info = zc.get_service_info(t, name, timeout=1000)
        if info:
            self.found[name] = info

    def remove_service(self, zc, t, name):
        pass


def browse_target(exclude_inst, exclude_display, timeout=15, service_type=None):
    """Find a foreign advert (not ours) and connect to its TCP listener.

    Returns (socket, service_name, props, zc) or (None, None, None, zc).
    Skips our own advert by instance name and display name."""
    zc = Zeroconf()
    found = _Collector()
    ServiceBrowser(zc, service_domain(service_type), found)
    t0 = time.time()
    target = None
    while time.time() - t0 < timeout and not target:
        time.sleep(0.5)
        for name, info in list(found.found.items()):
            if exclude_inst and exclude_inst in (name or ""):
                continue  # our own advert
            if not info.addresses:
                continue
            props = info.properties or {}
            disp = props.get(b"_d", b"")
            if isinstance(disp, bytes):
                disp = disp.decode(errors="replace")
            if exclude_display and disp == exclude_display:
                continue  # a stale advert from a previous foreign-client run
            target = info
            break
    if not target:
        return None, None, None, zc
    addr = _best_addr(target.addresses)
    s = socket.create_connection((addr, target.port), timeout=8)
    print(f"[mc] connected to advertiser {addr}:{target.port} ({target.name})")
    return s, target.name, target.properties, zc


def _best_addr(addrs):
    """Pick the most reachable IPv4 from a multi-address mDNS registration.

    mDNSResponder registers the advertiser's host with an A record per
    interface, and their order is arbitrary: on multi-interface hosts
    (loopback, disconnected NICs with self-assigned 169.254.x, VPNs, plus the
    real LAN) the first record is routinely loopback or link-local, and
    dialing it strands the session (the peer's GCK then never validates ICE —
    the R48/R49 office-environment failure). Prefer an address on our own
    LAN subnet, then any private routable one, and only fall back to
    loopback/link-local when nothing else exists."""
    import ipaddress

    def score(b):
        try:
            ip = ipaddress.ip_address(socket.inet_ntoa(b))
        except OSError:
            return -1
        if ip.is_loopback:
            return 0
        if ip.is_link_local:
            return 1
        try:  # same subnet as our own address = best
            mine = ipaddress.ip_address(env.MY_IP)
            if ip != mine and int(ip) >> 24 == int(mine) >> 24:
                return 4
        except OSError:
            pass
        return 2 if ip.is_private else 3

    return socket.inet_ntoa(max(addrs, key=score))


def inst_from_token(token8):
    """Instance name MUST be base36(token) — one identity per process, so the
    peer derives the SAME pid from mDNS as from greeting/invite (verified:
    instance 0b0octt9ljaj -> pid 305261EB exactly as the peer logged)."""
    return identity.tok36(token8)
