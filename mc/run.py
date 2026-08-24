"""CLI entry point — run the foreign peer against a real app stack.

    python -m mc.run                        # dual role (default, like real MC)
    python -m mc.run --role browser         # only dial their advertiser
    python -m mc.run --role advert          # only answer dials to our advert
    python -m mc.run --service my-app-mpc   # target a different app's channel

Role notes (validated configurations):
  both (default)   one process, one identity: our advert lets the app browse
                   us while we also dial it — the app-as-browser path is the
                   one whose GCK reliably starts.
  browser          pure browser: no advert listener, no mDNS registration.
                   Use when the app-as-browser's dial of our advert CONFLICTS
                   with our dial of its advertiser (it resets the session
                   ~60ms later). Equivalent to the old MC_PURE_BROWSER=1.
  advert           pure advertiser: block answering dials (daemon threads die
                   when main() exits — the blocking loop below is load-
                   bearing, not decoration).

Success is reported BY THE APPLE PEER: its log prints "Invitation accepted",
"Connected to participant", or "DTLSCONNECTED" for our foreign client.
"""
import argparse
import os
import socket
import time

from zeroconf import Zeroconf

from . import env, ice, mdns, session, tcp


def main():
    ap = argparse.ArgumentParser(prog="mc.run", description=__doc__.splitlines()[0])
    ap.add_argument("--role", choices=("both", "browser", "advert"), default="both",
                    help="browser = only dial their advertiser; advert = only answer dials "
                         "(default: both, one identity per process like real MC)")
    ap.add_argument("--service", default=None,
                    help="target app's Bonjour service type (default: MC_SERVICE_TYPE "
                         f"or {env.SERVICE_TYPE})")
    ap.add_argument("--display", default=None,
                    help="our display name (default: MC_DISPLAY_NAME or PYSRV)")
    ap.add_argument("--seconds", type=int, default=60,
                    help="how long to hold the session after a completed browser exchange")
    ap.add_argument("--advert-port", type=int, default=None,
                    help="our advert TCP port (default: MC_ADVERT_PORT or ephemeral)")
    args = ap.parse_args()

    if args.service:
        os.environ["MC_SERVICE_TYPE"] = args.service
        env.SERVICE_TYPE = args.service
    if args.display:
        os.environ["MC_DISPLAY_NAME"] = args.display
        env.DISPLAY_NAME = args.display
    advert_port = args.advert_port if args.advert_port is not None else env.ADVERT_PORT

    # ONE identity per process: instance name = base36(token8) so the app
    # derives the SAME pid from mDNS as from our greeting/invite (verified:
    # instance 0b0octt9ljaj -> pid 305261EB exactly as the app logged).
    # Identity: random, but with the pid4 (bytes 4..8) pinned HIGH so we
    # reliably WIN the DTLS role tie-break (lower last-4 = DTLS client). The
    # app-as-DTLS-client path is the proven one (MC8: full handshake, c1xx
    # exchange, DTLSCONNECTED); when we lose the tie-break the app's server
    # path stalls (MC9).
    # 0x7f + 3 random bytes — NOT a fixed 7f..fe: the participant ID is the
    # pid4 MASKED (token[4] & 0x7f), so byte0 = 0x7f is the highest masked
    # value (always wins the DTLS tie-break vs the app's 0x1e..-era ids)
    # while the random tail makes each PROCESS's id unique. A fixed
    # 7f ff ff fe collided with the app's STALE session entry from the
    # previous (killed) client — its teardown raced our fresh session's
    # establishment and disconnected us (the 1-in-3 failure, MCT-8/10).
    proc_token8 = os.urandom(4) + b"\x7f" + os.urandom(3)
    inst = mdns.inst_from_token(proc_token8)

    sess = session.Session()
    sess.our_token8 = proc_token8   # for the DTLS role decision (lower last4 = client)

    # our advert listener (dual-role / advert role)
    srv = None
    if args.role in ("both", "advert"):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("", advert_port))
        srv.listen(8)
        print(f"[mc] own advert {inst} :{srv.getsockname()[1]} ({env.SERVICE_TYPE})")

    # global ICE/DTLS service — serves whichever session forms
    ice.IceService(sess).start()
    time.sleep(0.5)

    zc = None
    info = None
    if srv is not None:
        zc = Zeroconf()
        info = mdns.advertise(zc, inst, srv.getsockname()[1])
        tcp.AdvertResponder(srv, sess, inst, proc_token8).start()

    ok = False
    if args.role in ("both", "browser"):
        # BROWSER: dial the app's advertiser (cross-host mDNS via Python can
        # be unreliable; the TCP dial itself bypasses that)
        for attempt in range(3):
            s2, name, props, zc2 = mdns.browse_target(
                exclude_inst=inst, exclude_display=env.DISPLAY_NAME)
            try:
                if s2:
                    print(f"[mc] browser flow target: {s2.getpeername()}")
                    if tcp.browser_flow(s2, sess, proc_token8, env.DISPLAY_NAME):
                        ok = True
                        break
                    try:
                        s2.close()
                    except Exception:
                        pass
                    print(f"[mc] browser retry {attempt + 1}/3")
            finally:
                try:
                    zc2.close()
                except Exception:
                    pass
        if ok:
            time.sleep(args.seconds)

    # hold: daemon threads (TCP listener + ICE service) die when main()
    # exits — the blocking loop is required in every role.
    print("[mc] running (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        if zc is not None and info is not None:
            try:
                zc.unregister_service(info)
            except Exception:
                pass
            try:
                zc.close()
            except Exception:
                pass


if __name__ == "__main__":
    main()
