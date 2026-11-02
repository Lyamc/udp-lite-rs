//! Release timing of shipped `verify` against the pre-change scalar checksum.
//!
//! The datagram is built once. Each recorded trial uses the same iteration
//! count and runs for at least 30 ms.

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use udp_lite::{build, checksum_uses_simd, verify};

const PAYLOAD_LEN: usize = 8192;
const TRIALS: usize = 7;

fn main() {
    let source = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1));
    let destination = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
    let mut payload = vec![0u8; PAYLOAD_LEN];
    for (i, byte) in payload.iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(3).wrapping_add(1);
    }
    let packet = build(source, destination, 1234, 5678, &payload, None).expect("build");
    let datagram = packet.as_bytes().to_vec();
    let uses_simd = checksum_uses_simd(datagram.len(), packet.coverage());

    let pseudo = ipv4_pseudo(source, destination, datagram.len() as u16);
    let head = datagram[..6].to_vec();
    let body = datagram[8..].to_vec();

    let iterations = calibrate(&datagram, &pseudo, &head, &body, source, destination);
    let mut scalar_ns = Vec::with_capacity(TRIALS);
    let mut shipped_ns = Vec::with_capacity(TRIALS);
    for _ in 0..TRIALS {
        scalar_ns.push(time_scalar(iterations, &pseudo, &head, &body));
        shipped_ns.push(time_verify(iterations, source, destination, &datagram));
    }
    scalar_ns.sort_unstable();
    shipped_ns.sort_unstable();
    let scalar_median = scalar_ns[TRIALS / 2];
    let shipped_median = shipped_ns[TRIALS / 2];
    let ratio = shipped_median as f64 / scalar_median as f64;
    let winner = if uses_simd { "simd" } else { "scalar" };

    println!("datagram_len={}", datagram.len());
    println!("coverage={}", packet.coverage());
    println!("iterations={iterations}");
    println!("trials={TRIALS}");
    println!(
        "scalar_trial_ms={}",
        scalar_ns
            .iter()
            .map(|ns| format!("{:.3}", *ns as f64 / 1_000_000.0))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!(
        "shipped_trial_ms={}",
        shipped_ns
            .iter()
            .map(|ns| format!("{:.3}", *ns as f64 / 1_000_000.0))
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("scalar_median_ns={scalar_median}");
    println!("shipped_median_ns={shipped_median}");
    println!("ratio={ratio:.4}");
    println!("shipped_simd={uses_simd}");
    println!("winner={winner}");

    let scalar_trial_ok = scalar_ns.iter().all(|ns| *ns >= 30_000_000);
    let shipped_trial_ok = shipped_ns.iter().all(|ns| *ns >= 30_000_000);
    if !scalar_trial_ok || !shipped_trial_ok {
        eprintln!("a trial finished in under 30 ms");
        std::process::exit(1);
    }
}

fn calibrate(
    datagram: &[u8],
    pseudo: &[u8],
    head: &[u8],
    body: &[u8],
    source: IpAddr,
    destination: IpAddr,
) -> u32 {
    let mut iterations = 64u32;
    loop {
        let scalar = time_scalar(iterations, pseudo, head, body);
        let shipped = time_verify(iterations, source, destination, datagram);
        if scalar >= 30_000_000 && shipped >= 30_000_000 {
            return iterations;
        }
        iterations = iterations.saturating_mul(2);
        if iterations >= 64 * 1024 * 1024 {
            return iterations;
        }
    }
}

fn time_verify(iterations: u32, source: IpAddr, destination: IpAddr, datagram: &[u8]) -> u64 {
    let start = Instant::now();
    for _ in 0..iterations {
        let got = verify(source, destination, black_box(datagram), None).expect("verify");
        black_box(got.payload);
    }
    start.elapsed().as_nanos() as u64
}

fn time_scalar(iterations: u32, pseudo: &[u8], head: &[u8], body: &[u8]) -> u64 {
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(scalar_checksum(
            black_box(pseudo),
            black_box(head),
            black_box(body),
        ));
    }
    start.elapsed().as_nanos() as u64
}

/// Pre-change accumulator: big-endian pairs into a 32-bit sum, fold at the end.
fn scalar_checksum(pseudo: &[u8], head: &[u8], body: &[u8]) -> u16 {
    let mut sum = 0u32;
    sum = add_words(sum, pseudo);
    sum = add_words(sum, head);
    sum = add_words(sum, &[0, 0]);
    sum = add_words(sum, body);
    fold_checksum(sum)
}

fn add_words(mut sum: u32, data: &[u8]) -> u32 {
    let mut chunks = data.chunks_exact(2);
    for chunk in chunks.by_ref() {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum += u32::from(byte) << 8;
    }
    sum
}

fn fold_checksum(mut sum: u32) -> u16 {
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

fn ipv4_pseudo(source: IpAddr, destination: IpAddr, length: u16) -> Vec<u8> {
    let IpAddr::V4(source) = source else {
        unreachable!("bench uses IPv4");
    };
    let IpAddr::V4(destination) = destination else {
        unreachable!("bench uses IPv4");
    };
    let mut bytes = Vec::with_capacity(12);
    bytes.extend_from_slice(&source.octets());
    bytes.extend_from_slice(&destination.octets());
    bytes.push(0);
    bytes.push(udp_lite::PROTOCOL);
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes
}
