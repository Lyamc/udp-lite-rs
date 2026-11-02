//! Calls the shipped build and verify paths.
//!
//! Expected datagrams are fixed from RFC 3828 and RFC 1071:
//! protocol 136, pseudo-header length equal to the whole datagram,
//! coverage 0 meaning the whole datagram, an odd covered length padded
//! with one zero octet, and a computed checksum of 0 stored as 0xFFFF.
//! They are not produced by calling the library.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use udp_lite::{build, checksum_uses_simd, verify, Error};

const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
const SRC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
const DST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 2));

const PORTS: (u16, u16) = (1234, 5678);

/// IPv4, ports 1234/5678, payload "hi", coverage field 10, checksum 0xF7F5.
/// Pseudo-header length is 10 and the protocol is 136.
const IPV4_FULL_HI: &[u8] = &[0x04, 0xD2, 0x16, 0x2E, 0x00, 0x0A, 0xF7, 0xF5, b'h', b'i'];

/// Same packet with the coverage-0 sentinel. Checksum 0xF7FF.
const IPV4_COVERAGE_ZERO_HI: &[u8] = &[0x04, 0xD2, 0x16, 0x2E, 0x00, 0x00, 0xF7, 0xFF, b'h', b'i'];

/// Payload 0x60 0x5F makes the one's-complement sum 0xFFFF, so the stored
/// checksum is 0xFFFF rather than 0x0000. Coverage field is the length, 10.
const IPV4_CHECKSUM_FFFF: &[u8] = &[0x04, 0xD2, 0x16, 0x2E, 0x00, 0x0A, 0xFF, 0xFF, 0x60, 0x5F];

/// Coverage 9 (odd) over a 12-octet datagram. Pseudo-header length is 12,
/// not 9. The first payload octet is in the sum as 0x0100.
const IPV4_COVERAGE_9: &[u8] = &[
    0x04, 0xD2, 0x16, 0x2E, 0x00, 0x09, 0x5F, 0x5E, 0x01, 0x02, 0x03, 0x04,
];

/// Coverage 8 over the same 12-octet datagram. Checksum 0x605F.
const IPV4_COVERAGE_8: &[u8] = &[
    0x04, 0xD2, 0x16, 0x2E, 0x00, 0x08, 0x60, 0x5F, 0x01, 0x02, 0x03, 0x04,
];

/// IPv6, same ports and "hi" payload, coverage field 10, checksum 0x2085.
const IPV6_FULL_HI: &[u8] = &[0x04, 0xD2, 0x16, 0x2E, 0x00, 0x0A, 0x20, 0x85, b'h', b'i'];

/// IPv6 coverage-0 sentinel for the same payload. Checksum 0x208F.
const IPV6_COVERAGE_ZERO_HI: &[u8] = &[0x04, 0xD2, 0x16, 0x2E, 0x00, 0x00, 0x20, 0x8F, b'h', b'i'];

/// IPv6 coverage 9 over a 12-octet datagram. Pseudo-header length is 12.
const IPV6_COVERAGE_9: &[u8] = &[
    0x04, 0xD2, 0x16, 0x2E, 0x00, 0x09, 0x87, 0xED, 0x01, 0x02, 0x03, 0x04,
];

/// IPv6 coverage 8 over the same payload. Checksum 0x88EE.
const IPV6_COVERAGE_8: &[u8] = &[
    0x04, 0xD2, 0x16, 0x2E, 0x00, 0x08, 0x88, 0xEE, 0x01, 0x02, 0x03, 0x04,
];

#[test]
fn ipv4_full_coverage() {
    let packet = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, b"hi", None).unwrap();
    assert_eq!(packet.as_bytes(), IPV4_FULL_HI);
    assert_eq!(packet.coverage(), 10);
    assert_ne!(packet.checksum(), 0);
    let got = verify(SRC_V4, DST_V4, packet.as_bytes(), None).unwrap();
    assert_eq!(got.payload, b"hi");
    assert_eq!(got.coverage, 10);
    assert_eq!(got.covered_octets, 10);
    assert_eq!(got.source_port, PORTS.0);
    assert_eq!(got.destination_port, PORTS.1);
}

#[test]
fn ipv6_full_coverage() {
    let packet = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, b"hi", None).unwrap();
    assert_eq!(packet.as_bytes(), IPV6_FULL_HI);
    assert_eq!(packet.coverage(), 10);
    assert_ne!(packet.checksum(), 0);
    let got = verify(SRC_V6, DST_V6, packet.as_bytes(), None).unwrap();
    assert_eq!(got.payload, b"hi");
    assert_eq!(got.coverage, 10);
    assert_eq!(got.covered_octets, 10);
}

#[test]
fn partial_coverage_odd_length() {
    let payload = [0x01, 0x02, 0x03, 0x04];
    let v4 = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, Some(9)).unwrap();
    assert_eq!(v4.as_bytes(), IPV4_COVERAGE_9);
    let v6 = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, &payload, Some(9)).unwrap();
    assert_eq!(v6.as_bytes(), IPV6_COVERAGE_9);

    // The uncovered tail is outside the sum, so it does not change the checksum.
    let shifted = build(
        SRC_V4,
        DST_V4,
        PORTS.0,
        PORTS.1,
        &[0x01, 0x02, 0x03, 0xFF],
        Some(9),
    )
    .unwrap();
    assert_eq!(shifted.checksum(), v4.checksum());
    assert_eq!(shifted.coverage(), 9);

    // The first payload octet is inside the odd covered prefix.
    let covered_changed = build(
        SRC_V4,
        DST_V4,
        PORTS.0,
        PORTS.1,
        &[0x11, 0x02, 0x03, 0x04],
        Some(9),
    )
    .unwrap();
    assert_ne!(covered_changed.checksum(), v4.checksum());
}

#[test]
fn checksum_zero_stored_as_ffff() {
    let packet = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &[0x60, 0x5F], None).unwrap();
    assert_eq!(packet.as_bytes(), IPV4_CHECKSUM_FFFF);
    assert_eq!(packet.checksum(), 0xFFFF);
    let got = verify(SRC_V4, DST_V4, packet.as_bytes(), None).unwrap();
    assert_eq!(got.payload, &[0x60, 0x5F]);
    assert_eq!(got.coverage, 10);
}

#[test]
fn bit_flip_outside_coverage_accepted() {
    for (src, dst, bytes) in [
        (SRC_V4, DST_V4, IPV4_COVERAGE_9),
        (SRC_V6, DST_V6, IPV6_COVERAGE_9),
    ] {
        // Covered length 9: octets 9, 10, and 11 are strictly past the prefix.
        for index in 9..bytes.len() {
            for bit in 0..8 {
                let mut damaged = bytes.to_vec();
                damaged[index] ^= 1 << bit;
                let got = verify(src, dst, &damaged, Some(9))
                    .unwrap_or_else(|err| panic!("{src} index {index} bit {bit} rejected: {err}"));
                assert_eq!(got.coverage, 9);
                assert_eq!(got.covered_octets, 9);
                let mut payload = bytes[8..].to_vec();
                payload[index - 8] ^= 1 << bit;
                assert_eq!(got.payload, payload);
            }
        }
    }
}

#[test]
fn bit_flip_inside_coverage_rejected() {
    for (src, dst, bytes, min) in [
        (SRC_V4, DST_V4, IPV4_COVERAGE_9, Some(9)),
        (SRC_V6, DST_V6, IPV6_COVERAGE_9, Some(9)),
        (SRC_V4, DST_V4, IPV4_FULL_HI, None),
        (SRC_V6, DST_V6, IPV6_FULL_HI, None),
    ] {
        let covered = if bytes[4] == 0 && bytes[5] == 0 {
            bytes.len()
        } else {
            u16::from_be_bytes([bytes[4], bytes[5]]) as usize
        };
        for index in 0..covered {
            for bit in 0..8 {
                let mut damaged = bytes.to_vec();
                damaged[index] ^= 1 << bit;
                assert!(
                    verify(src, dst, &damaged, min).is_err(),
                    "{src} accepted a flip at octet {index} bit {bit}"
                );
            }
        }
    }
}

#[test]
fn checksum_field_zero_rejected() {
    // This datagram's covered words already sum to 0xFFFF. Storing 0 in the
    // checksum field is still a one's-complement zero, and must be discarded
    // because UDP-Lite forbids a checksum field of 0.
    let mut zeroed = IPV4_CHECKSUM_FFFF.to_vec();
    zeroed[6] = 0;
    zeroed[7] = 0;
    assert_eq!(
        verify(SRC_V4, DST_V4, &zeroed, None).unwrap_err(),
        Error::ChecksumAbsent
    );

    let mut ordinary = IPV4_FULL_HI.to_vec();
    ordinary[6] = 0;
    ordinary[7] = 0;
    assert_eq!(
        verify(SRC_V4, DST_V4, &ordinary, None).unwrap_err(),
        Error::ChecksumAbsent
    );

    let mut v6 = IPV6_FULL_HI.to_vec();
    v6[6] = 0;
    v6[7] = 0;
    assert_eq!(
        verify(SRC_V6, DST_V6, &v6, None).unwrap_err(),
        Error::ChecksumAbsent
    );
}

#[test]
fn coverage_1_through_7_rejected() {
    for coverage in 1u16..=7 {
        for (src, dst, bytes) in [
            (SRC_V4, DST_V4, IPV4_FULL_HI),
            (SRC_V6, DST_V6, IPV6_FULL_HI),
        ] {
            let mut damaged = bytes.to_vec();
            damaged[4..6].copy_from_slice(&coverage.to_be_bytes());
            assert_eq!(
                verify(src, dst, &damaged, Some(8)).unwrap_err(),
                Error::IllegalCoverage { coverage }
            );
        }
    }
}

#[test]
fn coverage_greater_than_packet_rejected() {
    for (src, dst, bytes) in [
        (SRC_V4, DST_V4, IPV4_FULL_HI),
        (SRC_V6, DST_V6, IPV6_FULL_HI),
        (SRC_V4, DST_V4, IPV4_COVERAGE_9),
    ] {
        for coverage in [bytes.len() as u16 + 1, 65535] {
            let mut damaged = bytes.to_vec();
            damaged[4..6].copy_from_slice(&coverage.to_be_bytes());
            assert_eq!(
                verify(src, dst, &damaged, None).unwrap_err(),
                Error::CoverageExceedsPacket {
                    coverage,
                    length: bytes.len(),
                }
            );
        }
    }
}

#[test]
fn default_full_coverage() {
    let payload = b"hi";
    let v4 = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, payload, None).unwrap();
    let v6 = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, payload, None).unwrap();
    assert_eq!(v4.as_bytes(), IPV4_FULL_HI);
    assert_eq!(v6.as_bytes(), IPV6_FULL_HI);
    assert_eq!(v4.coverage() as usize, v4.len());
    assert_eq!(v6.coverage() as usize, v6.len());

    // No partial-coverage request: every octet is checked.
    for index in 0..v4.len() {
        let mut damaged = v4.as_bytes().to_vec();
        damaged[index] ^= 0x01;
        assert!(verify(SRC_V4, DST_V4, &damaged, None).is_err());
    }
    for index in 0..v6.len() {
        let mut damaged = v6.as_bytes().to_vec();
        damaged[index] ^= 0x80;
        assert!(verify(SRC_V6, DST_V6, &damaged, None).is_err());
    }

    // A partial datagram is below the default full-packet threshold.
    assert!(matches!(
        verify(SRC_V4, DST_V4, IPV4_COVERAGE_9, None).unwrap_err(),
        Error::CoverageBelowMinimum { .. }
    ));
}

#[test]
fn sender_does_not_emit_coverage_1_through_7() {
    let payload = [0x01, 0x02, 0x03, 0x04];
    let v4_eight = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, Some(8)).unwrap();
    let v6_eight = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, &payload, Some(8)).unwrap();
    assert_eq!(v4_eight.as_bytes(), IPV4_COVERAGE_8);
    assert_eq!(v6_eight.as_bytes(), IPV6_COVERAGE_8);
    for request in 1u16..=7 {
        let v4 = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, Some(request)).unwrap();
        let v6 = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, &payload, Some(request)).unwrap();
        assert_eq!(v4.as_bytes(), IPV4_COVERAGE_8, "ipv4 request {request}");
        assert_eq!(v6.as_bytes(), IPV6_COVERAGE_8, "ipv6 request {request}");
        assert_eq!(v4.coverage(), 8);
        assert_eq!(v6.coverage(), 8);
    }
}

#[test]
fn sender_does_not_emit_coverage_past_packet() {
    let payload = b"hi";
    let v4_full = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, payload, None).unwrap();
    let v6_full = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, payload, None).unwrap();
    assert_eq!(v4_full.as_bytes(), IPV4_FULL_HI);
    assert_eq!(v6_full.as_bytes(), IPV6_FULL_HI);

    for request in [10u16, 11, 100, 65535] {
        let v4 = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, payload, Some(request)).unwrap();
        let v6 = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, payload, Some(request)).unwrap();
        assert_eq!(v4.as_bytes(), v4_full.as_bytes(), "ipv4 request {request}");
        assert_eq!(v6.as_bytes(), v6_full.as_bytes(), "ipv6 request {request}");
        assert!(v4.coverage() as usize <= v4.len());
        assert!(v6.coverage() as usize <= v6.len());
        assert!(!(1..8).contains(&v4.coverage()));
        assert!(!(1..8).contains(&v6.coverage()));
    }

    // The clamped datagram protects every octet.
    let mut flipped = v4_full.as_bytes().to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    assert!(verify(SRC_V4, DST_V4, &flipped, None).is_err());
}

#[test]
fn explicit_coverage_zero_protects_entire_packet() {
    let v4 = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, b"hi", Some(0)).unwrap();
    let v6 = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, b"hi", Some(0)).unwrap();
    assert_eq!(v4.as_bytes(), IPV4_COVERAGE_ZERO_HI);
    assert_eq!(v6.as_bytes(), IPV6_COVERAGE_ZERO_HI);
    let got = verify(SRC_V4, DST_V4, v4.as_bytes(), None).unwrap();
    assert_eq!(got.payload, b"hi");
    assert_eq!(got.coverage, 0);
    assert_eq!(got.covered_octets, v4.len());
    for index in 0..v4.len() {
        let mut damaged = v4.as_bytes().to_vec();
        damaged[index] ^= 0x01;
        assert!(verify(SRC_V4, DST_V4, &damaged, None).is_err());
    }
}

#[test]
fn receiver_minimum_coverage_drops_below_threshold() {
    let payload = [0x01, 0x02, 0x03, 0x04];
    let partial = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, Some(9)).unwrap();
    assert_eq!(partial.as_bytes(), IPV4_COVERAGE_9);

    assert!(matches!(
        verify(SRC_V4, DST_V4, partial.as_bytes(), Some(10)).unwrap_err(),
        Error::CoverageBelowMinimum {
            coverage: 9,
            covered_octets: 9,
            minimum: 10,
        }
    ));
    // Some(0) is the entire-packet threshold, same as the default.
    assert!(matches!(
        verify(SRC_V4, DST_V4, partial.as_bytes(), Some(0)).unwrap_err(),
        Error::CoverageBelowMinimum {
            coverage: 9,
            covered_octets: 9,
            minimum: 12,
        }
    ));
    let accepted = verify(SRC_V4, DST_V4, partial.as_bytes(), Some(9)).unwrap();
    assert_eq!(accepted.payload, &payload);
    assert_eq!(accepted.coverage, 9);

    // A fully covered datagram meets a threshold equal to its length and
    // fails a threshold above it. Coverage 0 counts as the full length.
    let full = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, b"hi", Some(0)).unwrap();
    assert_eq!(full.coverage(), 0);
    assert_eq!(
        verify(SRC_V4, DST_V4, full.as_bytes(), Some(10))
            .unwrap()
            .covered_octets,
        10
    );
    assert!(matches!(
        verify(SRC_V4, DST_V4, full.as_bytes(), Some(11)).unwrap_err(),
        Error::CoverageBelowMinimum {
            coverage: 0,
            covered_octets: 10,
            minimum: 11,
        }
    ));
}

#[test]
fn accepted_coverage_is_observable() {
    let payload = [0x01, 0x02, 0x03, 0x04];
    let packet = build(SRC_V6, DST_V6, PORTS.0, PORTS.1, &payload, Some(9)).unwrap();
    assert_eq!(packet.as_bytes(), IPV6_COVERAGE_9);
    let got = verify(SRC_V6, DST_V6, packet.as_bytes(), Some(8)).unwrap();
    assert_eq!(got.coverage, 9);
    assert_eq!(got.covered_octets, 9);
    assert_eq!(got.payload, &payload);
    assert_eq!(got.source_port, PORTS.0);
    assert_eq!(got.destination_port, PORTS.1);

    let full = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, b"hi", None).unwrap();
    let got = verify(SRC_V4, DST_V4, full.as_bytes(), None).unwrap();
    assert_eq!(got.coverage, full.coverage());
    assert_eq!(got.coverage, 10);
    assert_eq!(got.payload, b"hi");
}

#[test]
fn round_trip_returns_same_payload_and_coverage() {
    let cases: [(IpAddr, IpAddr, &[u8], Option<u16>); 4] = [
        (SRC_V4, DST_V4, b"hi", None),
        (SRC_V6, DST_V6, b"hi", None),
        (SRC_V4, DST_V4, &[1, 2, 3, 4], Some(9)),
        (SRC_V6, DST_V6, &[1, 2, 3, 4], Some(0)),
    ];
    for (src, dst, payload, coverage) in cases {
        let packet = build(src, dst, PORTS.0, PORTS.1, payload, coverage).unwrap();
        let min = match coverage {
            None | Some(0) => None,
            Some(n) => Some(n),
        };
        let got = verify(src, dst, packet.as_bytes(), min).unwrap();
        assert_eq!(got.payload, payload);
        assert_eq!(got.coverage, packet.coverage());
        assert_ne!(packet.checksum(), 0);
    }
}

#[test]
fn rejects_short_long_and_mismatched_addresses() {
    assert_eq!(
        verify(SRC_V4, DST_V4, &[], None).unwrap_err(),
        Error::DatagramTooShort { length: 0 }
    );
    assert_eq!(
        verify(SRC_V4, DST_V4, &[0; 7], None).unwrap_err(),
        Error::DatagramTooShort { length: 7 }
    );
    let too_long = vec![0u8; 65536];
    assert!(matches!(
        verify(SRC_V4, DST_V4, &too_long, None).unwrap_err(),
        Error::PacketTooLong { length: 65536 }
    ));

    let oversized = vec![0u8; 65528];
    assert!(matches!(
        build(SRC_V4, DST_V4, 1, 2, &oversized, None).unwrap_err(),
        Error::PacketTooLong { .. }
    ));

    assert_eq!(
        build(SRC_V4, DST_V6, 1, 2, b"hi", None).unwrap_err(),
        Error::AddressFamilyMismatch
    );
    assert_eq!(
        verify(SRC_V4, DST_V6, IPV4_FULL_HI, None).unwrap_err(),
        Error::AddressFamilyMismatch
    );
    // A different destination changes the pseudo-header, so the checksum fails.
    let other = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3));
    assert_eq!(
        verify(SRC_V4, other, IPV4_FULL_HI, None).unwrap_err(),
        Error::ChecksumMismatch
    );
}

/// 4096 payload bytes. Byte `i` is `(i * 3 + 1)` truncated to 8 bits.
fn patterned(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 3 + 1) as u8).collect()
}

#[test]
fn large_even_coverage_spans_simd_width() {
    // Full coverage of a 4104-octet datagram. The checksum 0x445F is the
    // RFC 1071 sum for protocol 136 and pseudo-header length 4104.
    let payload = patterned(4096);
    let packet = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, None).unwrap();
    assert!(packet.len() > 64);
    assert_eq!(packet.coverage(), 4104);
    assert!(checksum_uses_simd(packet.len(), packet.coverage()));
    assert_eq!(packet.checksum(), 0x445F);
    let got = verify(SRC_V4, DST_V4, packet.as_bytes(), None).unwrap();
    assert_eq!(got.payload, payload.as_slice());
    assert_eq!(got.coverage, 4104);
    assert_eq!(got.covered_octets, 4104);
}

#[test]
fn large_odd_covered_length_spans_simd_width() {
    // Coverage 3001 is odd and longer than two SIMD vectors. The checksum
    // 0x3C2C uses pseudo-header length 4104, not 3001, and pads the final
    // covered octet with a zero byte.
    let payload = patterned(4096);
    let packet = build(SRC_V4, DST_V4, PORTS.0, PORTS.1, &payload, Some(3001)).unwrap();
    assert_eq!(packet.coverage(), 3001);
    assert!(checksum_uses_simd(packet.len(), packet.coverage()));
    assert_eq!(packet.checksum(), 0x3C2C);
    let got = verify(SRC_V4, DST_V4, packet.as_bytes(), Some(3001)).unwrap();
    assert_eq!(got.payload, payload.as_slice());
    assert_eq!(got.coverage, 3001);
    assert_eq!(got.covered_octets, 3001);

    let mut damaged = packet.as_bytes().to_vec();
    let last = damaged.len() - 1;
    damaged[last] ^= 0x01;
    let got = verify(SRC_V4, DST_V4, &damaged, Some(3001)).unwrap();
    assert_eq!(got.coverage, 3001);
    assert_eq!(got.payload[last - 8], payload[last - 8] ^ 0x01);
}
