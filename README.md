### basket2 - A transport for the paranoid.
#### Yawning Angel (yawning at schwanenlied dot me)

basket2 is the next transport in the obfs series.  It derives inspiration
primarily from obfs4 and predecessors, and incorporates ideas initially
prototyped in the experimental basket transport.

Features:

 * Authentication, data integrity, and confidentiality.
 * Active probing resistance.
 * Passive fingerprinting resistance, significantly improved over obfs4.
 * Client driven dynamic negotiation of runtime padding to better suit various
   adversary models.
 * Better separation between the handshake obfuscation and the authenticated
   key exchange mechanisms.
 * Significantly improved link layer framing.
 * Optional user authentication.
 * Post-quantum forward secrecy.
 * License switch from 3BSD to AGPL for more Freedom.

Dependencies:

 * Go 1.6.x or later - (May work with older versions, don't care if they don't)
 * golang.org/x/crypto - SHA3, Curve25519, Poly1305
 * github.com/agl/ed25519 - Ed25519, Edwards curve field arithmatic
 * github.com/dchest/siphash - SipHash-2-4
 * git.schwanenlied.me/yawning/chacha20.git - (X)ChaCha20
 * git.schwanenlied.me/yawning/x448.git - X448
 * git.schwanenlied.me/yawning/newhope.git - newhope

Notes:

 * I am waiving the remote network interaction requirements specified in
   Section 13 ("Remote Network Interaction; Use with the GNU General Public
   License") of the AGPL, per the terms of Section 7 ("Additional Terms"),
   for users that:

    * Are using the software to operate a publically accessible Bridge to
      provide access to the public Tor network as a Tor Pluggable Transport
      server.  This means:

        The Bridge publishes a descriptor to the Bridge Authority, and is
        available via BridgeDB OR is a default Bridge pre-configured and
        distributed with Tor Browser.

   All other users MUST comply with the AGPL in it's entirety as a general
   rule, though other licensing arrangements may be possible on request.
   I will likely be fairly liberal here, so please contact me if the
   current licensing is unsuitable for your use case.

 * The post-quantum cryptography does not apply to active attackers in
   posession of a quantum computer, and only will protect pre-existing data
   from later decryption.

   Using a PQ signature algorithm such as SPHINCS256 would solve this
   problem, however the key and signature sizes are still larger than what
   I feel comfortable with being able to obfsucate.

 * Yeah, this uses SHA3 instead of whatever trendy BLAKE variant kids like
   these days.

 * If your system has busted PMTUD, this probably won't work at all.  Not my
   problem.  Complain to your OS vendor.

TODO:

 * Write a formal specification.

 * Someone that's not me should write assembly optimized ChaCha20 for ARM and
   i386.  I may do both if I feel bored enough, but no promises.

 * Write optimized assembler versions of things for gccgo (or C if that's
   easier).  Low priority.

 * Define more padding primitives.

