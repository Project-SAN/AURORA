use hornet::routing::{elems_from_segment, segment_from_elems, IpAddr, RouteElem};
use std::net::{Ipv4Addr, Ipv6Addr};

fn main() {
    // Build a mixed IPv4/IPv6 path that ends with an exit TCP hop.
    let planned_route = vec![
        RouteElem::NextHop {
            addr: IpAddr::V4([10, 10, 0, 1]),
            port: 7000,
        },
        RouteElem::NextHop {
            addr: IpAddr::V6([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            port: 7100,
        },
        RouteElem::ExitTcp {
            addr: IpAddr::V4([203, 0, 113, 10]),
            port: 443,
            tls: true,
        },
    ];

    println!("Planned route:");
    for (idx, hop) in planned_route.iter().enumerate() {
        println!("  hop {} -> {}", idx + 1, describe_route_elem(hop));
    }

    let segment = segment_from_elems(&planned_route);
    println!(
        "\nRouting segment ({} bytes): {}",
        segment.0.len(),
        hex_bytes(&segment.0)
    );

    let parsed = elems_from_segment(&segment).expect("segment decoding failed");
    println!("\nDecoded hops:");
    for (idx, hop) in parsed.iter().enumerate() {
        println!("  hop {} -> {}", idx + 1, describe_route_elem(hop));
    }

    assert_eq!(parsed, planned_route);
    println!(
        "\nRound-trip OK: planned route matches decoded hops ({} TLVs).",
        parsed.len()
    );
}

fn describe_route_elem(elem: &RouteElem) -> String {
    match elem {
        RouteElem::NextHop { addr, port } => format!("NextHop {}:{}", fmt_ip(addr), port),
        RouteElem::ExitTcp { addr, port, tls } => format!(
            "ExitTcp {}:{} ({})",
            fmt_ip(addr),
            port,
            if *tls { "tls" } else { "plaintext" }
        ),
    }
}

fn fmt_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(bytes) => Ipv4Addr::from(*bytes).to_string(),
        IpAddr::V6(bytes) => Ipv6Addr::from(*bytes).to_string(),
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use core::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}
