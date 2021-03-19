use std::io::prelude::*;
use std::io;

const MTU_SIZE: usize = 1500;
const IP_HDR_TIMEOUT: u8 = 123;

enum State {
    Closed,
    Listen,
    //SynRecv
    //Estab,
}

struct TCB {
    state: State,
}

struct SendSequence {
    una: usize,
    next: usize,
    window: usize,
    up: usize,
    wl1: usize,
    wl2: usize,
    iss: usize,
}

struct RcvSequence {
    next: usize,
    window: usize,
    up: usize,
    irs: usize,
}

impl Default for State {
    fn default() -> Self {
        State::Listen
    }
}

impl State {
    pub fn on_packet<'a>(
        &mut self,
        iface: &mut tun_tap::Iface,
        ip_hdr: etherparse::Ipv4HeaderSlice<'a>,
        tcp_hdr: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) -> io::Result<usize> {
        let mut buf = [0u8; MTU_SIZE];
        
        match *self {
            State::Closed => {
                return Ok(0);
            }
            State::Listen => {
                if !tcp_hdr.syn() {
                    return Ok(0);
                }
                let mut syn_ack = etherparse::TcpHeader::new(
                    tcp_hdr.destination_port(),
                    tcp_hdr.source_port(),
                    std::unimplemented!(),
                    std::unimplemented!(),
                );

                syn_ack.syn = true;
                syn_ack.ack = true;
                
                let new_ip_hdr = etherparse::Ipv4Header::new(
                    syn_ack.header_len(),
                    IP_HDR_TIMEOUT,
                    etherparse::IpTrafficClass::Tcp,
                    [
                        ip_hdr.destination()[0],
                        ip_hdr.destination()[1],
                        ip_hdr.destination()[2],
                        ip_hdr.destination()[3],
                    ],
                    [
                        ip_hdr.source()[0],
                        ip_hdr.source()[1],
                        ip_hdr.source()[2],
                        ip_hdr.source()[3],
                    ],
                );
                
                let copy_buf = {
                    let mut copy_buf = &mut buf[..];
                    new_ip_hdr.write(&mut copy_buf);
                    syn_ack.write(&mut copy_buf);
                    copy_buf.len()
                };

                iface.send(&buf[..copy_buf])?;
            }
        }

        // eprintln!("ntcp: {src}:{srcp} -> {dest}:{destp}, pay_l:[{payl}], proto:[0x{prt:x}]",
        //     src  = ip_hdr.source_addr(),
        //     srcp = tcp_hdr.source_port(),
        //     dest = ip_hdr.destination_addr(),
        //     destp = tcp_hdr.destination_port(),
        //     payl = tcp_hdr.slice().len(),
        //     prt  = ip_hdr.protocol());
    }
}