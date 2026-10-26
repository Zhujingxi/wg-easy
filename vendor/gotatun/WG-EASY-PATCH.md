# Local memory-lifecycle patch

Source: gotatun 0.9.2 from crates.io, Mullvad VPN, MPL-2.0. Original crate SHA-256:
`4578da6dc5281756ef0277a8ab92fd390b472b87b939c89252130be9ca28812b`.
Original source notices are retained; the complete MPL-2.0 text is included.
Ship these modified source files, or their corresponding source URL, with binary
releases as required by MPL-2.0. The surrounding wg-easy crates remain MIT.

The original public `Peer` retains a raw optional preshared key and derives
`Debug`. `NoiseParams` also retains that key and prints it in `Debug`. Neither
clears the key on drop. This copy applies a narrow lifetime and formatting fix:

- Zero the owned `Peer` and `NoiseParams` PSKs on replacement and drop. Redact
  those debug fields and handshake chaining-key debug output.
- Keep peer-update PSKs in `Zeroizing` buffers, including aborted updates, and
  clear parameter copies forwarded between setters and constructors.
- Borrow the stored PSK during handshake processing instead of making an
  unguarded array copy. The WireGuard algorithm and wire format are unchanged.
- Zero temporary session-constructor key arrays after handing them to AWS-LC.
- Zero parsed key buffers and the UAPI key wrapper when they leave scope.

`Peer::with_preshared_key` is no longer a const function because zeroization is a
runtime operation. Moving non-Copy fields out of a Peer is replaced with taking
or borrowing them so the owning Peer can run its destructor. The selected
X25519 implementation already enables its zeroize feature; AWS-LC owns and
cleans up the session cipher contexts. This patch makes no cryptographic changes.

Validation: 78 unit tests pass, including upstream PSK update and mismatch tests
and two local redaction/zeroization checks. Seven upstream privileged tests stay
ignored; wg-easy's own isolated Linux namespace test verifies real encrypted
IPv4/IPv6 traffic with a PSK, handshakes, counters and cleanup. No general claim
about erasing compiler-generated register/spill copies is made.

Remove this vendor copy when a reviewed upstream release supplies the same
lifetime guarantees. The explicit dependency on zeroize reuses wg-easy's existing
version; no alternative crypto backend is introduced.

The local device API also exposes `failure()`, a formatted copy of its existing
fatal I/O error, so the application can report why a tunnel stopped rather than
discarding the cause when it polls status. No peer or key state is formatted.

Windows UDP sockets disable `SIO_UDP_CONNRESET` reporting, so an offline peer's
ICMP port-unreachable cannot end the receive task and stop the tunnel. Other
socket setup and I/O errors still propagate. The workspace UDP regression checks
IPv4, IPv6 and dual-stack sockets can receive after probing a closed local port.
