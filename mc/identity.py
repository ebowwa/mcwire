"""Identity — one 8-byte token, everywhere, all derived from it.

THE self-referential identity rule (decoded from disassembly; explains every
earlier synthetic-invite rejection): the framework requires greeting, invite,
and Bonjour record to describe the SAME peer —

  - greeting idString      = base36 of the token (natural length)
  - peerID NSData          = [8B token][1B namelen][display name]
  - mDNS instance name     = base36 of the token AGAIN

Any mismatch between the three = the peer closes the connection.
"""
import struct


def tok36(token8):
    """peer token8 -> base36 idString (natural length, like MC does)."""
    v = int.from_bytes(token8, "big")
    dg = "0123456789abcdefghijklmnopqrstuvwxyz"
    bs = ""
    while v:
        bs = dg[v % 36] + bs
        v //= 36
    return bs or "0"


def token_from36(idstr):
    """base36 idString -> 8-byte token (big-endian; ValueError if not base36)."""
    return int(idstr, 36).to_bytes(8, "big")


def peerid(token8, name):
    """Sender/RecipientPeerIDKey NSData: [8B token][1B namelen][name]."""
    return token8 + bytes([len(name)]) + name.encode()


def parse_greeting(hello):
    """Parse a 0x07d0 identity hello body -> {idstr, name, token8} or None.

    The name field is `idString+displayName\\0`; the search for '+' starts at
    offset 22 because the random field before it can itself contain '+' bytes
    (learned from real greetings)."""
    if hello[:2] != b"\x07\xd0":
        return None
    nb = hello.find(b"+", 22)  # skip rand field (contains '+' bytes!)
    if nb <= 0:
        return None
    idstr = hello[22:nb].decode(errors="replace")
    name = hello[nb + 1:].split(b"\x00")[0].decode(errors="replace")
    try:
        return {"idstr": idstr, "name": name, "token8": token_from36(idstr)}
    except ValueError:
        return {"idstr": idstr, "name": name, "token8": None}


def participant_id_le(token8):
    """Their 8B peer token -> the 4B participant ID a ConnectionData blob must
    carry for THEM, little-endian-read by the app:

        blob bytes = reverse( (token[4] & 0x7f) + token[5:8] )

    Verified against a known-good pair. The participant ID CHANGES on every
    app restart, so it must be extracted live from their connect plist's
    SenderPeerIDKey — never hardcoded."""
    return (bytes([token8[4] & 0x7F]) + token8[5:8])[::-1]


def blob_token(blob):
    """Extract a peer's 4B session token from a ConnectionData blob: the
    anchor is the `5a 000000` group header; the token is the 4 bytes before
    it (returns None if the anchor is absent)."""
    i5a = blob.find(bytes.fromhex("5a000000"))
    if i5a >= 4:
        return blob[i5a - 4:i5a]
    return None
