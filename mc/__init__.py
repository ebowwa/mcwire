"""mcwire client — a foreign (non-Apple) peer speaking the reverse-engineered
MultipeerConnectivity wire protocol against real, unmodified macOS/iOS apps.

Consolidated from the pyprobe experiment lineage (browser10 / responder9 were
the last proven clients). The RE knowledge lives in the comments and in
docs/ — this package is just that knowledge, executable.

Modules:
  framing   TCP message framing (op|flags|len|CRC32|seq) + stream reassembly
  identity  the 8-byte token identity system (base36 idString, peerID NSData)
  plists    handshake plist forging + ConnectionData blob patching
  mdns      Bonjour advertise/browse (models a non-Apple discovery stack)
  tcp       the proven TCP invite flows (browser role and advertiser role)
  ice       the GCK layer under MC: ICE/STUN checks + nomination
  dtls      the d0xx DTLS plane, driven by Apple's own SSLContext via the
            gckdtls bridge subprocess (tools/gckdtls.swift)
  env       runtime configuration (environment + mc.env, no hardcoded hosts)
  run       CLI entry point: `python -m mc.run`
"""
__version__ = "0.1.0"
