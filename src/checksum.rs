//! Internet checksum (RFC 1071) of an IPv4 or IPv6 UDP-Lite pseudo-header
//! plus the covered prefix of a datagram.
//!
//! Long even runs of bytes are accumulated with `std::simd`. Each 16-byte
//! group is split into big-endian high and low bytes so a little-endian lane
//! load is not treated as a big-endian word. Carries stay in 32-bit lanes.
//! Short inputs and the odd tail stay on the scalar word loop.

use std::net::IpAddr;
use std::simd::prelude::*;

use crate::{Error, PROTOCOL};

/// Even payload bytes at or above this length take the SIMD path.
/// Shorter coverage stays on the scalar accumulator.
pub(crate) const SIMD_MIN_BYTES: usize = 64;

enum Pseudo {
    V4([u8; 12]),
    V6([u8; 40]),
}

impl Pseudo {
    fn bytes(&self) -> &[u8] {
        match self {
            Pseudo::V4(bytes) => bytes,
            Pseudo::V6(bytes) => bytes,
        }
    }
}

/// Pseudo-header length is the full UDP-Lite packet length, never the coverage.
fn pseudo_header(source: IpAddr, destination: IpAddr, packet_len: u16) -> Result<Pseudo, Error> {
    match (source, destination) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut bytes = [0u8; 12];
            bytes[0..4].copy_from_slice(&src.octets());
            bytes[4..8].copy_from_slice(&dst.octets());
            bytes[9] = PROTOCOL;
            bytes[10..12].copy_from_slice(&packet_len.to_be_bytes());
            Ok(Pseudo::V4(bytes))
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut bytes = [0u8; 40];
            bytes[0..16].copy_from_slice(&src.octets());
            bytes[16..32].copy_from_slice(&dst.octets());
            bytes[32..36].copy_from_slice(&u32::from(packet_len).to_be_bytes());
            bytes[39] = PROTOCOL;
            Ok(Pseudo::V6(bytes))
        }
        _ => Err(Error::AddressFamilyMismatch),
    }
}

/// True when a covered payload of `payload_len` octets is summed with SIMD.
pub(crate) fn payload_uses_simd(payload_len: usize) -> bool {
    (payload_len & !1) >= SIMD_MIN_BYTES
}

/// Checksum of `datagram` using `source` and `destination` in the pseudo-header.
///
/// `covered_len` is the number of datagram octets that enter the sum, counting
/// from the first header octet. The checksum field is treated as zero. The
/// pseudo-header carries `datagram.len()`, not `covered_len`.
pub(crate) fn cover_checksum(
    source: IpAddr,
    destination: IpAddr,
    datagram: &[u8],
    covered_len: usize,
) -> Result<u16, Error> {
    debug_assert!(datagram.len() >= 8);
    debug_assert!((8..=datagram.len()).contains(&covered_len));
    debug_assert!(datagram.len() <= 65535);

    let pseudo = pseudo_header(source, destination, datagram.len() as u16)?;
    let mut sum = sum_scalar(pseudo.bytes());
    sum += sum_scalar(&datagram[..6]);
    // The checksum field is zero while the sum is formed, so those two octets
    // add nothing. The bytes after the header are the covered payload.
    sum += sum_bytes(&datagram[8..covered_len]);
    Ok(finish(sum))
}

fn sum_bytes(data: &[u8]) -> u32 {
    if payload_uses_simd(data.len()) {
        sum_simd(data)
    } else {
        sum_scalar(data)
    }
}

/// Big-endian 16-bit words into a 32-bit sum. A final odd octet is padded
/// with a zero low byte (RFC 1071).
fn sum_scalar(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    sum
}

/// SIMD sum of big-endian words.
///
/// A 16-bit word `0xHHLL` is `HH * 256 + LL`. Summing every high byte and
/// every low byte, then combining with `<< 8`, is the same integer total as
/// adding the words one at a time. High bytes are the even indexes because
/// the covered payload starts on a word boundary.
fn sum_simd(data: &[u8]) -> u32 {
    let even_len = data.len() & !1;
    let mut wide_hi = Simd::<u32, 8>::splat(0);
    let mut wide_lo = Simd::<u32, 8>::splat(0);
    let mut offset = 0;
    // 128 chunks * 255 is 32640, which still fits in a u16 lane.
    const BLOCK: usize = 128 * 16;
    while offset + BLOCK <= even_len {
        let (hi, lo) = sum_block(&data[offset..offset + BLOCK]);
        wide_hi += hi.cast::<u32>();
        wide_lo += lo.cast::<u32>();
        offset += BLOCK;
    }
    let tail = (even_len - offset) & !15;
    if tail > 0 {
        let (hi, lo) = sum_block(&data[offset..offset + tail]);
        wide_hi += hi.cast::<u32>();
        wide_lo += lo.cast::<u32>();
        offset += tail;
    }
    let mut sum = (wide_hi.reduce_sum() << 8) + wide_lo.reduce_sum();
    sum += sum_scalar(&data[offset..]);
    sum
}

fn sum_block(data: &[u8]) -> (Simd<u16, 8>, Simd<u16, 8>) {
    let mut hi = Simd::<u16, 8>::splat(0);
    let mut lo = Simd::<u16, 8>::splat(0);
    let mut offset = 0;
    while offset < data.len() {
        let bytes = Simd::<u8, 16>::from_slice(&data[offset..offset + 16]);
        let even: Simd<u8, 8> = simd_swizzle!(bytes, [0, 2, 4, 6, 8, 10, 12, 14]);
        let odd: Simd<u8, 8> = simd_swizzle!(bytes, [1, 3, 5, 7, 9, 11, 13, 15]);
        hi += even.cast::<u16>();
        lo += odd.cast::<u16>();
        offset += 16;
    }
    (hi, lo)
}

/// One's complement of the folded 16-bit sum.
/// A computed checksum of 0 is returned as `0xFFFF`.
fn finish(mut sum: u32) -> u16 {
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let complemented = !(sum as u16);
    if complemented == 0 {
        0xFFFF
    } else {
        complemented
    }
}
