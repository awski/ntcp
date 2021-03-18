mod ntcp;

#[derive(Debug, PartialEq, Eq, Hash)]
struct Connection {
    src: (std::net::Ipv4Addr, u16),
    dest: (std::net::Ipv4Addr, u16),
}

fn main() -> std::io::Result<()> {
    let interface = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun)?;
    let mut connections: std::collections::HashMap<Connection, ntcp::TcpState> = Default::default();
    let mut buf = [0u8; 1234];

    loop {
        let n_bytes = interface.recv(&mut buf[..])?;
        let flags = u16::from_be_bytes([buf[0], buf[1]]);
        let proto = u16::from_be_bytes([buf[2], buf[3]]);

        if proto != 0x0800 /* ipv4 protocol */ {
            eprintln!("ntcp: not ipv4 protocol");
            continue;
        } 

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..n_bytes]) {
            Ok(ip_hdr) => {
                if ip_hdr.protocol() != 0x06 /* tcp protocol */ {
                    eprintln!("ntcp: not tcp protocol");
                    continue;
                }

                match etherparse::TcpHeaderSlice::from_slice(&buf[4 + ip_hdr.slice().len()..]) {
                    Ok(tcp_hdr) => {
                        let data_idx = 4 + ip_hdr.slice().len() + tcp_hdr.slice().len();

                        connections.entry(Connection {
                            src: (ip_hdr.source_addr(), tcp_hdr.source_port()),
                            dest: (ip_hdr.destination_addr(), tcp_hdr.destination_port())
                        })
                        .or_default()
                        .on_packet(ip_hdr, tcp_hdr, &buf[data_idx..n_bytes]);
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
