#![allow(warnings)]

mod utils;

use rustdhipv2::crypto::{
    constants::*,
    ecdh::{KeyExchange, ToBytes, ECDHNISTP256},
};
use rustdhipv2::daemon::hipd::HIPDaemon;
use rustdhipv2::storage::HIPState::*;
use rustdhipv2::storage::SecurityAssociations::SARecordStore;
use rustdhipv2::utils::{hi::*, hit::*, misc::*};
use rustdhipv2::wire::constants::field::*;
use rustdhipv2::HIPError;

use log::debug;
use smoltcp::{
    iface::{EthernetInterfaceBuilder, NeighborCache, Routes},
    phy::{wait as phy_wait, TapInterface},
    socket::{RawPacketMetadata, RawSocket, RawSocketBuffer, SocketRef, SocketSet},
    time::Instant,
    wire::{EthernetAddress, IpAddress, IpCidr, IpProtocol, IpVersion, Ipv4Address},
};
use std::os::unix::io::AsRawFd;
use std::str::FromStr;
use std::{collections::BTreeMap, convert::TryInto};

fn main() {
    utils::setup_logging("");

    let device = TapInterface::new("tap0").unwrap();
    let fd = device.as_raw_fd();

    let initiator_addr = IpAddress::from_str("192.168.69.1").expect("invalid address format");
    let responder_addr = IpAddress::from_str("192.168.69.2").expect("invalid address format");

    let neighbor_cache = NeighborCache::new(BTreeMap::new());
    let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]);
    let ip_addrs = [IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24)];

    let default_v4_gw = Ipv4Address::new(192, 168, 69, 100);
    let mut routes_storage = [None; 1];
    let mut routes = Routes::new(&mut routes_storage[..]);
    routes.add_default_ipv4_route(default_v4_gw).unwrap();

    let mut iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .routes(routes)
        .finalize();

    let mut sockets = SocketSet::new(vec![]);

    // Must fit a HIP packet
    let raw_rx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; 2], vec![0; 1024]);
    let raw_tx_buffer = RawSocketBuffer::new(vec![RawPacketMetadata::EMPTY; 2], vec![0; 1024]);
    let raw_socket = RawSocket::new(
        IpVersion::Ipv4,
        IpProtocol::Unknown(HIP_PROTOCOL as u8),
        raw_rx_buffer,
        raw_tx_buffer,
    );
    let raw_handle = sockets.add(raw_socket);

    // HIP Host Identity generation
    let initiator_sk = ECDHNISTP256::generate_private_key([13; 32]);
    let initiator_pk = ECDHNISTP256::generate_public_key(&initiator_sk);
    let serialized_initiator_sk = initiator_sk.to_bytes();
    let serialized_initiator_pk = initiator_pk.to_bytes();
    let pubkey_x: [u8; 32] = initiator_pk.to_bytes().as_slice()[1..NIST_256_PUBKEY_X_LEN + 1]
        .try_into()
        .unwrap();
    let pubkey_y: [u8; 32] = initiator_pk.to_bytes().as_slice()[NIST_256_PUBKEY_X_LEN + 1..]
        .try_into()
        .unwrap();

    let hi = ECDSAHostId::get_host_id::<32>(&pubkey_x, &pubkey_y);
    let hit_bytes = HIT::compute_hit::<82>(hi.as_bytes(), 0x1);
    let hit_hexstring = match Utils::hex_formatted_hit_bytes(Some(&hit_bytes), None) {
        Ok(str) => str,
        Err(_) => panic!("Failed to hex format HIT"),
    };

    // HIP Daemon instantiation
    let state_store = &mut StateStore::new();
    let keymat_store = &mut GenericValueStore::<[u8; 800]>::new();
    let dh_map = &mut GenericValueStore::<DHKeys>::new();
    let cipher_map = &mut GenericValueStore::<Option<u8>>::new();
    let pubkey_map = &mut GenericValueStore::<SharedDHPubKey>::new();
    let state_vars_map = &mut GenericValueStore::<StateVariables>::new();
    let key_info_map = &mut GenericValueStore::<KeyInfo>::new();
    let sa_map = &mut SARecordStore::new();

    let mut hipd = HIPDaemon::new(
        Some(&serialized_initiator_pk.as_slice()[1..]),
        Some(serialized_initiator_sk.as_slice()),
        hi,
        Some(hit_hexstring.as_str()),
        hit_bytes,
        state_store,
        keymat_store,
        dh_map,
        cipher_map,
        pubkey_map,
        state_vars_map,
        key_info_map,
        sa_map,
    );

    {
        // Fixed remote HIT. No DNS resolution.
        let rhit = [
            32, 1, 32, 1, 132, 58, 150, 38, 12, 183, 21, 139, 116, 22, 246, 82,
        ];
        let src_ip = match initiator_addr {
            IpAddress::Ipv4(val) => val.0,
            _ => unimplemented!(),
        };
        let dst_ip = match responder_addr {
            IpAddress::Ipv4(val) => val.0,
            _ => unimplemented!(),
        };
        let mut socket = sockets.get::<RawSocket>(raw_handle);
        let i1_packet = hipd.initiate_hip_connection(rhit, src_ip, dst_ip, socket);
    }

    loop {
        let timestamp = Instant::now();
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        {
            let mut socket = sockets.get::<RawSocket>(raw_handle);
            if socket.can_recv() {
                match hipd.process_hip_packet(socket) {
                    Ok(_) => {}
                    Err(e) => {
                        debug!("HIP error: {}", e);
                    }
                }
            }
        }
        phy_wait(fd, iface.poll_delay(&sockets, timestamp)).expect("wait error");
    }
}
