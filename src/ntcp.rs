use std::{cmp::Ordering, io::prelude::*, unimplemented};
use std::io;

const MTU_SIZE: usize = 1500;
const IP_HDR_TIMEOUT: u8 = 123;

pub struct TCB {
    state: State,
    send: SendSequence,
    recv: RecvSequence,
}

pub enum State {
    Closed,
    Listen,
    SynRecv
    Estab,
}

struct SendSequence {
    una: u32,
    next: u32,
    window: u16,
    up: bool,
    wl1: usize,
    wl2: usize,
    iss: u32,
}

struct RecvSequence {
    next: u32,
    window: u16,
    up: bool,
    irs: u32,
}

impl TCB {
    pub fn accept<'a>(
        iface: &mut tun_tap::Iface,
        ip_hdr: etherparse::Ipv4HeaderSlice<'a>,
        tcp_hdr: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) -> io::Result<Option<Self>> {

        if !tcp_hdr.syn() {
            return Ok(None);
        }

        let mut buf = [0u8; MTU_SIZE];
        let iss = 0;
        let mut tcb = TCB {
            state: State::SynRecv,
            send: SendSequence {
                iss,
                una: iss,
                next: iss + 1,
                window: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            recv: RecvSequence {
                irs: tcp_hdr.sequence_number(),
                next: tcp_hdr.sequence_number() + 1,
                window: tcp_hdr.window_size(),
                up: false,
            },
        };

        let mut syn_ack = etherparse::TcpHeader::new(
            tcp_hdr.destination_port(),
            tcp_hdr.source_port(),
            tcb.send.iss,
            tcb.send.window,
        );

        syn_ack.acknowledgment_number = tcb.recv.next;
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
        Ok(Some(tcb))
        // eprintln!("ntcp: {src}:{srcp} -> {dest}:{destp}, pay_l:[{payl}], proto:[0x{prt:x}]",
        //     src  = ip_hdr.source_addr(),
        //     srcp = tcp_hdr.source_port(),
        //     dest = ip_hdr.destination_addr(),
        //     destp = tcp_hdr.destination_port(),
        //     payl = tcp_hdr.slice().len(),
        //     prt  = ip_hdr.protocol());
    }

    pub fn on_packet<'a>(
        &mut self,
        iface: &mut tun_tap::Iface,
        ip_hdr: etherparse::Ipv4HeaderSlice<'a>,
        tcp_hdr: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) -> io::Result<()> {

        let ack_num = tcp_hdr.acknowledgment_number();
        if !is_boundary_valid(self.send.una, ack_num, self.send.next.wrapping_add(1)) {
            return Ok(());
        }

        let seq_num = tcp_hdr.sequence_number();
        let mut seq_len = data.len() as u32;

        if tcp_hdr.fin() {
            seq_len += 1;
        }
        if tcp_hdr.syn() {
            seq_len += 1;
        }
        let wend = self.recv.next.wrapping_add(self.recv.window as u32);
        if seq_len == 0 {
            if self.recv.window == 0 {
                if seq_num != self.recv.next {
                    return Ok(())
                }
            } else if !is_boundary_valid(self.recv.next.wrapping_sub(1), seq_num, wend) {
                return Ok(())
            }
        } else {
            if self.recv.window == 0 {
                return Ok(())
            } else if !is_boundary_valid(self.recv.next.wrapping_sub(1), seq_num, wend) &&
                      !is_boundary_valid(self.recv.next.wrapping_sub(1), seq_num + seq_len - 1, wend) {
                return Ok(())
            }
        }


        match self.state {
            State::SynRecv => {
                unimplemented!();
            },
            State::Estab => {
                unimplemented!();
            },
            _ => {
                unimplemented!();
            }
        }
    }
}

fn is_boundary_valid(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            if end >= start && end <= x {
                return false;
            }
        }
        Ordering::Greater => {
            if end < start && end > x {
            } else {
                return false;
            }
        }
    }
    true
}