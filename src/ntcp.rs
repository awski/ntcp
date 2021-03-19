use std::{cmp::Ordering, io::prelude::*, unimplemented};
use std::io;

const MTU_SIZE: usize = 1500;
const IP_HDR_TIMEOUT: u8 = 123;

pub struct TCB {
    state: State,
    send: SendSequence,
    recv: RecvSequence,
    ip: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

pub enum State {
    Closed,
    Listen,
    SynRecv,
    Estab,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRecv => false,
            State::Estab => true,
            _ => unimplemented!(),
        }
    }
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
        let wnd = 1024;
        let mut tcb = TCB {
            state: State::SynRecv,
            send: SendSequence {
                iss,
                una: iss,
                next: iss + 1,
                window: wnd,
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
            tcp: etherparse::TcpHeader::new(tcp_hdr.destination_port(), tcp_hdr.source_port(), iss, wnd),
            ip: etherparse::Ipv4Header::new(
                0,
                64,
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
            ),
        };

        tcb.tcp.syn = true;
        tcb.tcp.ack = true;
        tcb.send(iface, &[])?;
        Ok(Some(tcb))
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
            if !self.state.is_synchronized() {
                self.send_reset(iface);
            }
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
                self.state = State::Estab;
                Ok(())
            },
            State::Estab => {
                unimplemented!();
            },
            _ => {
                unimplemented!();
            }
        }
    }

    fn send(
        &mut self,
        iface: &mut tun_tap::Iface,
        payl: &[u8]) -> io::Result<(usize)>
    {
        let mut buf = [0u8; MTU_SIZE];

        self.tcp.sequence_number = self.send.next;
        self.tcp.acknowledgment_number = self.recv.next;

        let sz = std::cmp::min(
            buf.len(),
            self.tcp.header_len() as usize + self.ip.header_len() as usize + payl.len()
        );
        self.ip.set_payload_len(sz);

        let mut copy_buf = &mut buf[..];
        self.ip.write(&mut copy_buf);
        self.tcp.write(&mut copy_buf);
        let payl_bytes = copy_buf.write(payl)?;
        let copy_buf = copy_buf.len();
        self.send.next.wrapping_add(payl_bytes as u32);

        if self.tcp.syn {
            self.send.next.wrapping_add(1);
            self.tcp.syn = false;
        }
        if self.tcp.fin {
            self.send.next.wrapping_add(1);
            self.tcp.fin = false;
        }

        iface.send(&buf[..buf.len() - copy_buf])?;
        Ok(payl_bytes)
    }

    fn send_reset(
        &mut self,
        iface: &mut tun_tap::Iface) -> io::Result<()>
    {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.send(iface, &[])?;
        Ok(())
    }
}

fn wrapping_lt(lhs: u32, rhs: u32) -> bool {
    lhs.wrapping_sub(rhs) > (1 << 31)
}

fn is_boundary_valid(start: u32, x: u32, end: u32) -> bool {
    wrapping_lt(start, x) && wrapping_lt(x, end)
}