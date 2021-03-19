mod ntcp;

const ETH_PACKET_OFFSET: usize = 0;

#[derive(Debug, PartialEq, Eq, Hash)]
struct Connection {
    src: (std::net::Ipv4Addr, u16),
    dest: (std::net::Ipv4Addr, u16),
}

fn main() -> std::io::Result<()> {
    let mut interface = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut connections: std::collections::HashMap<Connection, ntcp::TCB> = Default::default();
    let mut buf = [0u8; 1234];

    loop {
        let n_bytes = interface.recv(&mut buf[..])?;
        // let flags = u16::from_be_bytes([buf[0], buf[1]]);
        // let proto = u16::from_be_bytes([buf[2], buf[3]]);

        // if proto != 0x0800 /* ipv4 protocol */ {
        //     eprintln!("ntcp: not ipv4 protocol");
        //     continue;
        // } 

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[ETH_PACKET_OFFSET..n_bytes]) {
            Ok(ip_hdr) => {
                if ip_hdr.protocol() != 0x06 /* tcp protocol */ {
                    eprintln!("ntcp: not tcp protocol");
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[ETH_PACKET_OFFSET + ip_hdr.slice().len()..]) {
                    Ok(tcp_hdr) => {
                        use std::collections::hash_map::Entry;
                        
                        let data_idx = ETH_PACKET_OFFSET + ip_hdr.slice().len() + tcp_hdr.slice().len();
                        
                        match connections.entry(Connection {
                            src: (ip_hdr.source_addr(), tcp_hdr.source_port()),
                            dest: (ip_hdr.destination_addr(), tcp_hdr.destination_port()),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(&mut interface, ip_hdr, tcp_hdr, &buf[data_idx..n_bytes])?;
                            },
                            Entry::Vacant(mut e) => {
                                if let Some(c) = ntcp::TCB::accept(
                                    &mut interface,
                                    ip_hdr,
                                    tcp_hdr,
                                    &buf[data_idx..n_bytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("ntcp: invalid tcp packet, {:?}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("ntcp: invalid ipv4 packet, {:?}", e);
            }
        }
    }


    Ok(())
}
