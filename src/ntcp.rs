use etherparse::{self, TcpHeader, TcpHeaderSlice};

pub struct TcpState {

}

impl Default for TcpState {
    fn default() -> Self {
        TcpState {}
    }
}

impl TcpState {
    pub fn on_packet<'a>(
        &mut self,
        ip_hdr: etherparse::Ipv4HeaderSlice<'a>,
        tcp_hdr: etherparse::TcpHeaderSlice<'a>,
        data: &'a[u8]
    ) {
        eprintln!("ntcp: {src}:{srcp} -> {dest}:{destp}, pay_l:[{payl}], proto:[0x{prt:x}]",
            src  = ip_hdr.source_addr(),
            srcp = tcp_hdr.source_port(),
            dest = ip_hdr.destination_addr(),
            destp = tcp_hdr.destination_port(),
            payl = tcp_hdr.slice().len(),
            prt  = ip_hdr.protocol());
    }
}