#![allow(warnings)]

use std::str::FromStr;
use smoltcp::{
    iface::{EthernetInterfaceBuilder, NeighborCache, Routes},
    phy::{wait as phy_wait, TapInterface},
    socket::{RawPacketMetadata, RawSocket, RawSocketBuffer, SocketRef, SocketSet},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpProtocol, IpVersion, Ipv6Address, Ipv6Packet},
};

fn main() {
    let responder = IpAddress::from_str("fdaa:0:0:0:0:0:0:2").expect("invalid address format");
    println!("{:?}", responder);
}