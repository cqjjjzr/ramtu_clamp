use std::fs::File;

use clap::Parser;
use nfqueue::Verdict;
use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use pnet::packet::{MutablePacket, Packet};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::icmpv6::ndp::{MutableRouterAdvertPacket, NdpOption, NdpOptionTypes, RouterAdvertPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv6::{Ipv6Packet, MutableIpv6Packet};

fn handle_ip_packet(ip6_pkt: &mut Ipv6Packet, mtu_value: u32, log: bool) -> Option<Vec<u8>> {
    if ip6_pkt.get_next_header() != IpNextHeaderProtocols::Icmpv6 { return None }
    let ra_pkt = RouterAdvertPacket::new(ip6_pkt.payload())?;
    if ra_pkt.get_icmpv6_type() != Icmpv6Types::RouterAdvert { return None }

    if log {
        println!("Found RA packet: \n    {:?}\n    {:?}", ip6_pkt, ra_pkt);
    }

    let mut existing_mtu = false;
    for opt in ra_pkt.get_options_iter() {
        if opt.get_option_type() == NdpOptionTypes::MTU {
            existing_mtu = true;
            break;
        }
    }

    let mut vec_result = ip6_pkt.packet().to_vec();
    if !existing_mtu {
        vec_result.extend(&[0u8; 8]);
    }
    let mut r_ip6_pkt = MutableIpv6Packet::new(vec_result.as_mut_slice()).unwrap();
    assert_eq!(r_ip6_pkt.get_next_header(), IpNextHeaderProtocols::Icmpv6);
    if !existing_mtu {
        r_ip6_pkt.set_payload_length(r_ip6_pkt.get_payload_length() + 8);
    }

    let mut r_ra_pkt = MutableRouterAdvertPacket::new(r_ip6_pkt.payload_mut()).unwrap();
    assert_eq!(r_ra_pkt.get_icmpv6_type(), Icmpv6Types::RouterAdvert);

    let mut options = r_ra_pkt.get_options();
    for opt in options.iter_mut() {
        if opt.option_type == NdpOptionTypes::MTU {
            if opt.data.len() != 6 {
                println!("Invalid MTU option length: {:}", opt.data.len());
                return None;
            }
            opt.data[2..6].copy_from_slice(&mtu_value.to_be_bytes());
            assert!(existing_mtu);
        }
    }
    if !existing_mtu {
        let mut data: Vec<u8> = vec![0x00u8, 0x00u8];
        data.extend_from_slice(&mtu_value.to_be_bytes());
        options.push(NdpOption {
            option_type: NdpOptionTypes::MTU,
            length: 1,
            data
        });
    }

    r_ra_pkt.set_options(&options[..]);

    let mut r_ip6_pkt_2 = MutableIpv6Packet::new(vec_result.as_mut_slice()).unwrap();
    let r_ip6_src = r_ip6_pkt_2.get_source();
    let r_ip6_dest  = r_ip6_pkt_2.get_destination();
    let mut r_mut_ra_pkt_2 = MutableIcmpv6Packet::new(r_ip6_pkt_2.payload_mut()).unwrap();
    r_mut_ra_pkt_2.set_checksum(0);
    r_mut_ra_pkt_2.set_checksum(pnet_packet::icmpv6::checksum(
        &r_mut_ra_pkt_2.to_immutable(),
        &r_ip6_src,
        &r_ip6_dest
    ));

    if log {
        // Can't use r_ip6_pkt, r_eth_pkt, r_ra_pkt anymore
        let new_ip6 = Ipv6Packet::new(vec_result.as_slice()).unwrap();
        let new_ra = RouterAdvertPacket::new(new_ip6.payload()).unwrap();
        println!("Transformed packet: \n    {:?}\n    {:?}", new_ip6, new_ra);
        //println!("Transformed packet: \n    {:?}\n    {:?}\n    {:?}", eth_pkt, ip6_pkt, ra_pkt);
    }

    Some(vec_result)
}

fn handle_packet(eth_pkt: &mut EthernetPacket, mtu_value: u32, log: bool) -> Option<Vec<u8>> {
    if eth_pkt.get_ethertype() != EtherTypes::Ipv6 { return None }
    let ip6_pkt = Ipv6Packet::new(eth_pkt.payload())?;
    if ip6_pkt.get_next_header() != IpNextHeaderProtocols::Icmpv6 { return None }
    let ra_pkt = RouterAdvertPacket::new(ip6_pkt.payload())?;
    if ra_pkt.get_icmpv6_type() != Icmpv6Types::RouterAdvert { return None }

    if log {
        println!("Found RA packet: \n    {:?}\n    {:?}\n    {:?}", eth_pkt, ip6_pkt, ra_pkt);
    }

    let mut vec_result = eth_pkt.packet().to_vec();
    let ip_vec_result = handle_ip_packet(&mut Ipv6Packet::new(eth_pkt.payload())?, mtu_value, false)?;
    vec_result.resize(ip_vec_result.len() + 18, 0);
    vec_result.as_mut_slice()[18..].copy_from_slice(ip_vec_result.as_slice());

    if log {
        // Can't use r_ip6_pkt, r_eth_pkt, r_ra_pkt anymore
        let new_eth = EthernetPacket::new(vec_result.as_slice()).unwrap();
        let new_ip6 = Ipv6Packet::new(new_eth.payload()).unwrap();
        let new_ra = RouterAdvertPacket::new(new_ip6.payload()).unwrap();
        println!("Transformed packet: \n    {:?}\n    {:?}\n    {:?}", new_eth, new_ip6, new_ra);
        //println!("Transformed packet: \n    {:?}\n    {:?}\n    {:?}", eth_pkt, ip6_pkt, ra_pkt);
    }

    Some(vec_result)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    pcap_file: Option<String>,

    #[arg(short, long, default_value_t = 1280)]
    new_mtu: u16,
    #[arg(short, long, default_value_t = 1)]
    queue: u16,
    #[arg(short, long, default_value_t = false)]
    log: bool
}

struct State {
    log: bool,
    new_mtu: u16
}

fn queue_callback(msg: &nfqueue::Message, state: &mut State) {
    if let Some(transformed)
        = Ipv6Packet::new(msg.get_payload())
        .and_then(|mut eth_pkt| handle_ip_packet(&mut eth_pkt, state.new_mtu as u32, state.log)) {
        msg.set_verdict_full(Verdict::Accept, 0, transformed.as_slice());
    } else {
        if state.log {
            println!("Unknown packet received: {:02X?}", msg.get_payload())
        }
        msg.set_verdict(Verdict::Accept);
    }
}

fn main() {
    let args = Args::parse();

    match args.pcap_file {
        None => {
            let mut q = nfqueue::Queue::new(State {
                log: args.log,
                new_mtu: args.new_mtu,
            });
            q.open();
            q.unbind(libc::AF_INET6);
            let rc = q.bind(libc::AF_INET6);
            assert_eq!(rc, 0);

            q.create_queue(args.queue, queue_callback);
            q.set_mode(nfqueue::CopyMode::CopyPacket, 0xffff);

            println!("RAMTU-Clamp running on queue {:}", args.queue);

            q.run_loop();
        }
        Some(file_name) => {
            let mut reader = LegacyPcapReader::new(65536, File::open(file_name).unwrap()).expect("PcapNGReader");
            loop {
                match reader.next()  {
                    Ok((off, block)) => {
                        match block {
                            PcapBlockOwned::Legacy(payload) => {
                                if let Some(mut eth_pkt) = EthernetPacket::new(payload.data) {
                                    handle_packet(&mut eth_pkt, args.new_mtu as u32, args.log);
                                } else {
                                    println!("Error: Can't parse packet: {:02X?}", payload.data);
                                };
                            }
                            PcapBlockOwned::LegacyHeader(_) => {},
                            PcapBlockOwned::NG(_) => panic!("Unexcepted NG block")
                        }
                        reader.consume(off)
                    },
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete) => reader.refill().unwrap(),
                    Err(e) => {
                        println!("Error while reading: {:?}", e);
                        break;
                    }
                }
            }
        }
    }
}
