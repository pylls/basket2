### basket2 - Obfsy McObfsface
#### Yawning Angel (yawning at schwanenlied dot me)

basket2 is the next transport in the obfs series.  It derives inspiration
primarily from obfs4 and predecessors, and incorporates ideas initially
prototyped in the experimental basket transport.

Features:

 * Authentication, data integrity, and confidentiality.
 * Active probing resistance.
 * Passive fingerprinting resistance, improved over obfs4.
 * Client driven dynamic negotiation of runtime padding to better suit various
   adversary models.
 * Better separation between the handshake obfuscation and the authenticated
   key exchange mechanisms.
 * Significantly improved link layer framing.
 * Optional user authentication.
 * Post-quantum forward secrecy.
 * License switch from 3BSD to AGPL for more Freedom.

Dependencies:

The more obsucre dependencies are included using the Go 1.6 `vendor` scheme,
and are managed via `git-subtree`.  Certain larger dependencies likely to be
already packaged are not included (as opposed to `vendor`-ing everything).

 * Go 1.6.x or later - (May work with older versions, don't care if they don't)
 * golang.org/x/crypto - SHA3, Curve25519, Poly1305
 * golang.org/x/net - Only for `basket2proxy`.
 * git.torproject.org/pluggable-transports/goptlib.git - Only for `basket2proxy`.

Notes:

 * I am waiving the remote network interaction requirements specified in
   Section 13 ("Remote Network Interaction; Use with the GNU General Public
   License") of the AGPL, per the terms of Section 7 ("Additional Terms"),
   for users that:

    * Are using the software exclusively to operate a publically accessible
      Bridge to provide access to the public Tor network as a Tor Pluggable
      Transport server.  This means:

        The Bridge publishes a descriptor to the Bridge Authority, and is
        available via BridgeDB OR is a default Bridge pre-configured and
        distributed with Tor Browser, and uses basket2 as a server side
        Pluggable Transport for said Bridge.

 * All other users MUST comply with the AGPL in it's entirety as a general
   rule, though other licensing arrangements may be possible on request.
   I will likely be fairly liberal here, so please contact me if the
   current licensing is unsuitable for your use case.

 * All bundled external dependencies have different (more permissive)
   licenses that should be followed as appropriate.

 * The post-quantum cryptography does not apply to active attackers in
   posession of a quantum computer, and only will protect pre-existing data
   from later decryption.

 * If your system has busted PMTUD, this probably won't work at all.  Not my
   problem.  Complain to your OS vendor.

 * This could have been based on Trevor Perin's noise protocol framework, with
   a decent amount of work and extensions, but certain properties and behavior
   I need aren't formally specified yet.  This is something I will strongly
   consider if/when I design basket3.
