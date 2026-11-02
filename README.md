# udp-lite

Userspace [UDP-Lite](https://www.rfc-editor.org/rfc/rfc3828) (RFC 3828) datagram construction and verification.

The crate builds and checks UDP-Lite datagrams. It does not open a socket and does not require `IPPROTO_UDPLITE`. Callers pass the IPv4 or IPv6 addresses used in the checksum pseudo-header. The datagram is the IP payload. Jumbograms are not supported; a packet is at most 65,535 octets.

There are no dependencies. The crate is `#![forbid(unsafe_code)]`.

## Toolchain

`std::simd` is used for the checksum, through the nightly `portable_simd` feature. Build with a nightly toolchain:

```sh
rustup override set nightly
cargo test
```

`Cargo.toml` records `rust-version = "1.70"`. That field does not describe the feature gate: stable 1.70 cannot compile this crate.

## API

```rust
use std::net::{IpAddr, Ipv4Addr};
use udp_lite::{build, verify, PROTOCOL};

fn main() {
    assert_eq!(PROTOCOL, 136);

    let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let packet = build(src, dst, 1234, 5678, b"hi", None).unwrap();
    let got = verify(src, dst, packet.as_bytes(), None).unwrap();
    assert_eq!(got.payload, b"hi");
}
```

| Item | Role |
| --- | --- |
| `PROTOCOL` | IP protocol number 136 |
| `build` | Assemble a datagram and write its checksum |
| `verify` | Check coverage and checksum, then return the payload |
| `Packet` | Owned datagram: ports, coverage, checksum, payload, bytes |
| `Verified` | Borrowed view of a datagram that passed `verify` |
| `Error` | Build or verify failure |
| `checksum_uses_simd` | Whether that datagram's checksum takes the SIMD path |

Source and destination must be the same IP version. An IPv4 pseudo-header is 12 octets and an IPv6 pseudo-header is 40. The length in the pseudo-header is the full UDP-Lite packet length, not the coverage.

### Coverage on send

`build(..., coverage)`:

- `None` checksums the whole datagram and writes the packet length in the coverage field (RFC 3828 §3.3, the UDP-equivalent default).
- `Some(0)` checksums the whole datagram and writes coverage 0, the sentinel for the entire packet.
- `Some(1..=7)` is sent as coverage 8. Those values are never written.
- `Some(n)` with `n` greater than the datagram checksums the whole datagram and writes the packet length.
- Any other `Some(n)` checksums the first `n` octets and writes `n`.

### Coverage on receive

`verify(..., min_coverage)` drops a datagram when the checksum field is 0, the coverage is 1–7, or the coverage is greater than the datagram.

- `None` and `Some(0)` require a checksum over the entire datagram.
- `Some(n)` for `n > 0` drops a datagram whose covered length is below `n`. Coverage 0 counts as the full length.

An odd covered length is padded with one zero octet for the sum only. Octets past the covered prefix do not affect the check.

### Checksum

The sum is the Internet checksum (RFC 1071) of the pseudo-header plus the covered prefix. A computed checksum of 0 is stored as `0xFFFF`. The checksum field itself is treated as zero while the sum is formed.

Covered payloads whose even length is at least 64 octets are accumulated with `std::simd`. Shorter inputs use a scalar 16-bit one's-complement sum. `checksum_uses_simd` reports which path `build` and `verify` take after the structural checks.

## Examples

```sh
cargo test
cargo run --example roundtrip
cargo run --release --example bench
```

`examples/roundtrip.rs` builds one IPv4 datagram (198.51.100.10 → 203.0.113.20, ports 4000/5000, coverage 16) and prints a single `ok` line.

`examples/bench.rs` is a release-only comparison. It verifies one datagram of at least 8 KiB and times that against a scalar checksum of the same bytes. Each trial runs for at least 30 ms. Debug timings are not meaningful.

## License

MIT OR Apache-2.0.
