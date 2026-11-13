//! Benchmarks for the hot paths: packet building and parsing, port specs,
//! and a full connect scan of closed localhost ports.
//!
//! Run with `cargo bench -p feroprobe-core`.

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use feroprobe_core::{ScanConfig, Target, connect_scan, packet, parse_ports};

fn packets(c: &mut Criterion) {
    let src = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(10, 0, 0, 2);
    let mut g = c.benchmark_group("packet");

    let data = vec![0xa5u8; 1500];
    g.throughput(Throughput::Bytes(data.len() as u64));
    g.bench_function("checksum_1500", |b| {
        b.iter(|| packet::checksum(black_box(&data)))
    });

    g.throughput(Throughput::Elements(1));
    g.bench_function("build_syn", |b| {
        b.iter(|| packet::tcp_syn(src, dst, black_box(40000), black_box(443), 0xdead_beef))
    });

    // A SYN-ACK as the receiver sees it: IPv4 header, then TCP.
    let mut reply = vec![
        0x45,
        0,
        0,
        44,
        0,
        0,
        0x40,
        0,
        64,
        packet::IPPROTO_TCP,
        0,
        0,
        10,
        0,
        0,
        2,
        10,
        0,
        0,
        1,
    ];
    reply.extend_from_slice(&packet::tcp_syn(dst, src, 443, 40000, 1));
    reply[33] = packet::TCP_SYN | packet::TCP_ACK;
    g.bench_function("parse_syn_ack", |b| {
        b.iter(|| {
            let ip = packet::parse_ipv4(black_box(&reply)).unwrap();
            packet::parse_tcp(ip.payload).unwrap()
        })
    });
    g.finish();
}

fn ports(c: &mut Criterion) {
    c.bench_function("parse_ports_all", |b| {
        b.iter(|| parse_ports(black_box("1-65535")).unwrap())
    });
    c.bench_function("parse_ports_list", |b| {
        b.iter(|| parse_ports(black_box("22,80,443,1000-2000,8080,8443")).unwrap())
    });
}

/// Connect scan of 1000 closed ports on 127.0.0.1: measures the scan
/// engine's per-probe overhead, since every port answers immediately.
fn connect_localhost(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let target = [Target::new("127.0.0.1".parse().unwrap())];
    // High ports, very likely closed.
    let ports: Vec<u16> = (61000..62000).collect();
    let cfg = ScanConfig {
        timeout: Duration::from_secs(3),
        concurrency: 200,
        ..Default::default()
    };
    let mut g = c.benchmark_group("scan");
    g.sample_size(10);
    g.throughput(Throughput::Elements(ports.len() as u64));
    g.bench_function("connect_1000_localhost", |b| {
        b.to_async(&rt)
            .iter(|| async { connect_scan(&target, &ports, &cfg).await.unwrap() })
    });
    g.finish();
}

criterion_group!(benches, packets, ports, connect_localhost);
criterion_main!(benches);
