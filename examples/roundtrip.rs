//! Fresh consumer of the shipped UDP-Lite API.
//!
//! Builds one datagram, verifies it, and prints a single success line when
//! the payload and coverage match the request and the checksum field is not 0.

use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;

use udp_lite::{build, verify};

fn main() -> ExitCode {
    match run() {
        Ok(line) => {
            println!("{line}");
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<String, String> {
    let source = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    let destination = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20));
    let payload = b"udp-lite representative payload";
    let coverage = 16u16;

    let packet = build(source, destination, 4000, 5000, payload, Some(coverage))
        .map_err(|err| err.to_string())?;
    let got = verify(source, destination, packet.as_bytes(), Some(coverage))
        .map_err(|err| err.to_string())?;

    if got.payload != payload {
        return Err("payload mismatch".to_string());
    }
    if got.coverage != coverage {
        return Err(format!(
            "coverage mismatch: got {} requested {coverage}",
            got.coverage
        ));
    }
    if packet.checksum() == 0 {
        return Err("checksum field is zero".to_string());
    }

    Ok(format!(
        "ok payload={} coverage={} checksum=0x{:04x}",
        hex(got.payload),
        got.coverage,
        packet.checksum()
    ))
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
