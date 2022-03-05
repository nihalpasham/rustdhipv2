```sh
root@DESKTOP-M9O6B7J:/mnt/c/Users/Nil/devspace/rust/projects/rusty_hipv2# cargo run --example hip_responder
   Compiling rustdhipv2 v0.1.0 (/mnt/c/Users/Nil/devspace/rust/projects/rusty_hipv2)
    Finished dev [unoptimized + debuginfo] target(s) in 1m 44s
     Running `target/debug/examples/hip_responder`
[1614620466.534s] (socket::set): [0]: adding
[1614620466.626s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620466.626s] (iface::ethernet): packet dump follows:
EthernetII src=ba-03-db-05-17-c1 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::b803:dbff:fe05:17c1 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620466.627s] (hip_responder): poll error: unrecognized packet
[1614620466.627s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620466.627s] (iface::ethernet): packet dump follows:
EthernetII src=ba-03-db-05-17-c1 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::b803:dbff:fe05:17c1 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620466.627s] (hip_responder): poll error: unrecognized packet
[1614620466.661s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620466.661s] (iface::ethernet): packet dump follows:
EthernetII src=ba-03-db-05-17-c1 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::b803:dbff:fe05:17c1 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620466.661s] (hip_responder): poll error: unrecognized packet
[1614620467.251s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620467.251s] (iface::ethernet): packet dump follows:
EthernetII src=ba-03-db-05-17-c1 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::b803:dbff:fe05:17c1 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620467.251s] (hip_responder): poll error: unrecognized packet
[1614620560.41s] (iface::neighbor): filled 192.168.69.1 => 02-00-00-00-00-02 (was empty)
[1614620560.42s] (socket::raw): #0:IPv4:0x8b: receiving 76 octets
[1614620560.42s] (socket::raw): #0:IPv4:0x8b: receive 76 buffered octets
[1614620560.42s] (rustdhipv2::daemon::hipd): #msg::(ihit < rhit)==true
[1614620560.42s] (rustdhipv2::daemon::hipd): #rmsg: *****got I1 Packet*****
[1614620560.51s] (rustdhipv2::storage::HIPState): #log: new entry added to state_vars_map
[1614620560.56s] (rustdhipv2::storage::HIPState): #log: new entry added to dh_map
[1614620560.66s] (rustdhipv2::daemon::hipd): #rmsg: sending [R1] packet
[1614620560.66s] (socket::raw): #0:IPv4:0x8b: buffer to send 404 octets
[1614620560.66s] (socket::raw): #0:IPv4:0x8b: sending 404 octets
[1614620573.888s] (socket::raw): #0:IPv4:0x8b: receiving 460 octets
[1614620573.888s] (socket::raw): #0:IPv4:0x8b: receive 460 buffered octets
[1614620573.888s] (rustdhipv2::daemon::hipd): #msg::(ihit < rhit)==true
[1614620573.888s] (rustdhipv2::daemon::hipd): #rmsg: *****got I2 packet*****
[1614620573.888s] (rustdhipv2::daemon::hipd): [I2] packet contains:
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + ESP Info parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + Solution parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + DH parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + Cipher parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + ESP Transform parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + Host Id parameter contains:
[1614620573.889s] (rustdhipv2::daemon::hipd):         |__ + initiator's OGA id 0x1
[1614620573.889s] (rustdhipv2::daemon::hipd):         |__ + initiator's computed HIT: [32, 1, 32, 1, 87, 49, 50, 242, 174, 14, 178, 139, 44, 8, 246, 35]
[1614620573.889s] (rustdhipv2::daemon::hipd):         |__ + initiator's actual HIT:   [32, 1, 32, 1, 87, 49, 50, 242, 174, 14, 178, 139, 44, 8, 246, 35]
[1614620573.889s] (rustdhipv2::daemon::hipd):         |__ + self HIT:                 [32, 1, 32, 1, 132, 58, 150, 38, 12, 183, 21, 139, 116, 22, 246, 82]
[1614620573.889s] (rustdhipv2::storage::HIPState): #log: new entry added to pubkey_map
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + Transport parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):         |__ + Transport formats: Ok([15, 255])
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + MAC Parameter
[1614620573.889s] (rustdhipv2::daemon::hipd):     |__ + Signature parameter
[1614620573.889s] (rustdhipv2::daemon::hipd): #rmsg: puzzle was verified
[1614620573.893s] (rustdhipv2::daemon::hipd): #rdbg: shared secret_key, 32 bytes
[1614620573.893s] (rustdhipv2::storage::HIPState): #log: new entry added to key_info_map
[1614620573.893s] (rustdhipv2::storage::HIPState): #log: new entry added to cipher_map
[1614620573.895s] (rustdhipv2::storage::HIPState): #log: new entry added to keymat_map
[1614620573.902s] (rustdhipv2::daemon::hipd): #rmsg: signature verified!
[1614620573.902s] (rustdhipv2::daemon::hipd): #rmsg: validated [I2] packet
[1614620573.907s] (rustdhipv2::daemon::hipd): #ista: hip_state::[current state: Unassociated]
[1614620573.907s] (rustdhipv2::daemon::hipd): #ista: hip_state::[UNASSOCIATED]=>[R2-SENT]
[1614620573.907s] (rustdhipv2::daemon::hipd): #rmsg: sending [R2] packet to 192.168.69.1, bytes sent 188
[1614620573.907s] (socket::raw): #0:IPv4:0x8b: buffer to send 188 octets
[1614620573.907s] (rustdhipv2::daemon::hipd): #rmsg: setting SA records...
[1614620573.907s] (rustdhipv2::storage::SecurityAssociations): #log: new entry added to sa_map
[1614620573.908s] (socket::raw): #0:IPv4:0x8b: sending 188 octets
```