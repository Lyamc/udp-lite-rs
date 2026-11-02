//! Userspace UDP-Lite (RFC 3828) datagram construction and verification.
//!
//! The crate builds and checks UDP-Lite datagrams. It does not open a kernel
//! socket and does not require `IPPROTO_UDPLITE`. Callers supply the IP
//! addresses that the pseudo-header needs. The datagram length is the IP
//! payload length.
//!
//! With no partial-coverage request, the whole datagram is protected and
//! checked, matching UDP. A coverage request of 1–7 is sent as 8. A request
//! larger than the datagram protects the whole datagram and is not written
//! as a coverage greater than the datagram.

#![feature(portable_simd)]
#![forbid(unsafe_code)]

mod checksum;

use std::fmt;
use std::net::IpAddr;

/// IP protocol number assigned to UDP-Lite.
pub const PROTOCOL: u8 = 136;

/// Whether the checksum of a datagram this long, with this coverage field,
/// is accumulated with `std::simd`.
///
/// Short inputs stay on the scalar sum. The answer matches the path [`build`]
/// and [`verify`] take for a datagram that passes the structural checks.
pub fn checksum_uses_simd(datagram_len: usize, coverage: u16) -> bool {
    if !(HEADER_LEN..=MAX_PACKET_LEN).contains(&datagram_len) {
        return false;
    }
    if (1..8).contains(&coverage) || coverage as usize > datagram_len {
        return false;
    }
    let covered = if coverage == 0 {
        datagram_len
    } else {
        coverage as usize
    };
    checksum::payload_uses_simd(covered - HEADER_LEN)
}

const HEADER_LEN: usize = 8;
const MAX_PACKET_LEN: usize = 65535;

/// A built UDP-Lite datagram.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    bytes: Vec<u8>,
}

impl Packet {
    /// Header and payload, big-endian.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length of the datagram in octets.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// False. A datagram always contains the 8-octet header.
    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn source_port(&self) -> u16 {
        read_u16(&self.bytes, 0)
    }

    pub fn destination_port(&self) -> u16 {
        read_u16(&self.bytes, 2)
    }

    /// Coverage field. Zero means the checksum covers the entire datagram.
    pub fn coverage(&self) -> u16 {
        read_u16(&self.bytes, 4)
    }

    pub fn checksum(&self) -> u16 {
        read_u16(&self.bytes, 6)
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[HEADER_LEN..]
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A datagram that passed verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    /// Coverage field from the header. Zero means the entire datagram.
    pub coverage: u16,
    /// Octets covered by the checksum, counting from the first header octet.
    pub covered_octets: usize,
    pub payload: &'a [u8],
}

/// Why a datagram could not be built or accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Source and destination are not the same IP version.
    AddressFamilyMismatch,
    /// `8 + payload` exceeds 65,535 octets. Jumbograms are not supported.
    PacketTooLong { length: usize },
    /// Fewer than 8 octets.
    DatagramTooShort { length: usize },
    /// The checksum field is 0. UDP-Lite requires a checksum.
    ChecksumAbsent,
    /// Coverage is 1–7. The header is 8 octets and must be covered.
    IllegalCoverage { coverage: u16 },
    /// Coverage is greater than the datagram.
    CoverageExceedsPacket { coverage: u16, length: usize },
    /// The covered prefix does not match the checksum.
    ChecksumMismatch,
    /// Effective coverage is below the receiver minimum.
    CoverageBelowMinimum {
        coverage: u16,
        covered_octets: usize,
        minimum: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AddressFamilyMismatch => {
                write!(f, "source and destination IP versions differ")
            }
            Error::PacketTooLong { length } => {
                write!(f, "UDP-Lite datagram length {length} exceeds 65535")
            }
            Error::DatagramTooShort { length } => {
                write!(f, "UDP-Lite datagram is {length} octets, shorter than 8")
            }
            Error::ChecksumAbsent => write!(f, "UDP-Lite checksum field is zero"),
            Error::IllegalCoverage { coverage } => {
                write!(f, "UDP-Lite coverage {coverage} is between 1 and 7")
            }
            Error::CoverageExceedsPacket { coverage, length } => {
                write!(f, "UDP-Lite coverage {coverage} exceeds datagram length {length}")
            }
            Error::ChecksumMismatch => write!(f, "UDP-Lite checksum does not match"),
            Error::CoverageBelowMinimum {
                coverage,
                covered_octets,
                minimum,
            } => write!(
                f,
                "UDP-Lite coverage {coverage} covers {covered_octets} octets, below minimum {minimum}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Build a UDP-Lite datagram.
///
/// `coverage` selects the checksum coverage:
/// - `None` protects the entire datagram and writes the datagram length into
///   the coverage field (RFC 3828 section 3.3, UDP-equivalent default).
/// - `Some(0)` protects the entire datagram and writes coverage 0, the
///   RFC 3828 sentinel for "entire packet".
/// - `Some(1..=7)` is sent as coverage 8. Values in that range are never emitted.
/// - `Some(n)` with `n` greater than the datagram protects the entire datagram
///   and writes the datagram length, which is not greater than the packet.
/// - Any other `Some(n)` checksums the first `n` octets and writes `n`.
///
/// # Examples
///
/// ```
/// use std::net::{IpAddr, Ipv4Addr};
/// use udp_lite::{build, verify};
///
/// let src = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
/// let dst = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
/// let packet = build(src, dst, 1234, 5678, b"hi", None).unwrap();
/// let got = verify(src, dst, packet.as_bytes(), None).unwrap();
/// assert_eq!(got.payload, b"hi");
/// assert_eq!(got.coverage, packet.len() as u16);
/// assert_ne!(packet.checksum(), 0);
/// ```
pub fn build(
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: &[u8],
    coverage: Option<u16>,
) -> Result<Packet, Error> {
    let packet_len = HEADER_LEN
        .checked_add(payload.len())
        .filter(|len| *len <= MAX_PACKET_LEN)
        .ok_or(Error::PacketTooLong {
            length: payload.len().saturating_add(HEADER_LEN),
        })?;
    let (wire, covered) = resolve_send_coverage(coverage, packet_len);

    let mut bytes = Vec::with_capacity(packet_len);
    bytes.extend_from_slice(&source_port.to_be_bytes());
    bytes.extend_from_slice(&destination_port.to_be_bytes());
    bytes.extend_from_slice(&wire.to_be_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(payload);

    let sum = checksum::cover_checksum(source, destination, &bytes, covered)?;
    bytes[6..8].copy_from_slice(&sum.to_be_bytes());
    Ok(Packet { bytes })
}

/// Verify a UDP-Lite datagram and return its payload.
///
/// The checksum covers the prefix selected by the coverage field. Coverage 0
/// means the entire datagram. An odd covered length is padded with one zero
/// octet for the sum only. Bits strictly past the covered prefix do not affect
/// the decision.
///
/// The datagram is discarded when the checksum field is 0, the coverage is
/// 1–7, the coverage is greater than the datagram, or any covered octet does
/// not match the checksum.
///
/// `min_coverage` is the receiver threshold:
/// - `None` and `Some(0)` require a checksum over the entire datagram. A
///   partial datagram is below that threshold. This is the default, with no
///   partial-coverage request.
/// - `Some(n)` for `n > 0` drops a datagram whose covered length is below `n`.
///   Coverage 0 counts as the full datagram length.
///
/// An accepted datagram's coverage field is [`Verified::coverage`].
pub fn verify<'a>(
    source: IpAddr,
    destination: IpAddr,
    datagram: &'a [u8],
    min_coverage: Option<u16>,
) -> Result<Verified<'a>, Error> {
    if datagram.len() < HEADER_LEN {
        return Err(Error::DatagramTooShort {
            length: datagram.len(),
        });
    }
    if datagram.len() > MAX_PACKET_LEN {
        return Err(Error::PacketTooLong {
            length: datagram.len(),
        });
    }

    let source_port = read_u16(datagram, 0);
    let destination_port = read_u16(datagram, 2);
    let coverage = read_u16(datagram, 4);
    let checksum = read_u16(datagram, 6);

    if checksum == 0 {
        return Err(Error::ChecksumAbsent);
    }
    if (1..8).contains(&coverage) {
        return Err(Error::IllegalCoverage { coverage });
    }
    if coverage as usize > datagram.len() {
        return Err(Error::CoverageExceedsPacket {
            coverage,
            length: datagram.len(),
        });
    }

    let covered = covered_octets(coverage, datagram.len());
    let computed = checksum::cover_checksum(source, destination, datagram, covered)?;
    if computed != checksum {
        return Err(Error::ChecksumMismatch);
    }

    let minimum = receiver_minimum(min_coverage, datagram.len());
    if covered < minimum {
        return Err(Error::CoverageBelowMinimum {
            coverage,
            covered_octets: covered,
            minimum,
        });
    }

    Ok(Verified {
        source_port,
        destination_port,
        coverage,
        covered_octets: covered,
        payload: &datagram[HEADER_LEN..],
    })
}

fn resolve_send_coverage(requested: Option<u16>, packet_len: usize) -> (u16, usize) {
    let packet_len_u16 = packet_len as u16;
    match requested {
        None => (packet_len_u16, packet_len),
        Some(0) => (0, packet_len),
        Some(n) => {
            let n = if n < 8 { 8 } else { n };
            if n as usize >= packet_len {
                (packet_len_u16, packet_len)
            } else {
                (n, n as usize)
            }
        }
    }
}

fn covered_octets(coverage: u16, packet_len: usize) -> usize {
    if coverage == 0 {
        packet_len
    } else {
        coverage as usize
    }
}

fn receiver_minimum(min_coverage: Option<u16>, packet_len: usize) -> usize {
    match min_coverage {
        None | Some(0) => packet_len,
        Some(n) => n as usize,
    }
}

fn read_u16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([bytes[at], bytes[at + 1]])
}
