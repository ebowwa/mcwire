#!/usr/bin/python3
"""probe_mdns.py — advertise a plain mDNS service modeling an Android peer
(NsdManager publish). The service type matches what the macOS MC app browses.

Usage: probe_mdns.py <type> [name] [--txt k=v ...]

Run alongside `mcpeer browse` to test whether a real MCNearbyServiceBrowser
discovers a NON-Apple advertiser. If it does, Android discovery is stock
NsdManager; if not, MC filters on TXT contents we must reverse.
"""
import sys
import time
from zeroconf import ServiceInfo, Zeroconf

def main():
    args = sys.argv[1:]
    if not args:
        print("usage: probe_mdns.py <type> [--name NAME] [--txt k=v ...]")
        return 1
    srv_type = args[0]
    if not srv_type.startswith("_"):
        srv_type = "_" + srv_type
    if not srv_type.endswith(".local."):
        if srv_type.endswith("._tcp."):
            srv_type = srv_type + "local."
        else:
            srv_type = srv_type + "._tcp.local."
    name = "android-probe"
    txt = {}
    i = 1
    while i < len(args):
        if args[i] == "--name":
            i += 1; name = args[i]
        elif args[i] == "--txt":
            i += 1
            for pair in args[i].split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    txt[k] = v.encode()
        i += 1

    full_name = f"{name}.{srv_type}"
    info = ServiceInfo(
        srv_type,
        full_name,
        addresses=["127.0.0.1"],  # registered on all local addrs by zeroconf
        port=9000,
        properties=txt,
    )
    zc = Zeroconf()
    try:
        zc.register_service(info)
        print(f"advertising {full_name} port=9000 txt={txt}")
        print("Ctrl-C to stop")
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        zc.unregister_service(info)
        zc.close()
    return 0

sys.exit(main())