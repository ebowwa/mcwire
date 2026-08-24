"""Shared live session state.

One process runs ONE foreign peer identity (one 8-byte token → one mDNS
instance). The TCP flows (browser and/or advertiser role) publish what they
learn into this shared object; the global ICE/DTLS service consumes it. This
replaces the module-level globals of the experimental clients.
"""
import threading

from . import dtls


class Session:
    def __init__(self):
        self.lock = threading.Lock()
        # OUR identity token for this process (set by run; needed for the
        # DTLS role decision — the LOWER token-last4 becomes DTLS client):
        self.our_token8 = None
        # identity learned from the peer (live — never hardcoded):
        self.peer_addr = None      # IP of the peer's TCP endpoint
        self.peer_token8 = None    # 8B identity token from their greeting
        self.peer_name = None
        self.their_tok = None      # 4B GCK session token from their connect blob
        # ours, once a role exchange completes:
        self.our_tok4 = None       # 4B GCK session token we advertise
        self.cand_blob = None      # our patched ConnectionData blob (for 8009)
        self.dtls = dtls.new_state()
        self.last_spray = 0.0

    def publish_exchange(self, our_tok4, their_tok, cand_blob):
        """Publish a completed TCP exchange for the ICE service. First writer
        wins: the app-as-browser path is the one whose GCK reliably starts, so
        a later browser-flow result must NOT clobber it."""
        with self.lock:
            first = self.their_tok is None
            if first:
                self.our_tok4 = our_tok4
                self.their_tok = their_tok
                self.cand_blob = cand_blob
            return first
