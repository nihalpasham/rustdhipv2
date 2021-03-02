```sh
root@DESKTOP-M9O6B7J:/mnt/c/Users/Nil/devspace/rust/projects/rusty_hipv2# cargo run --example hip_initiator
    Blocking waiting for file lock on build directory
   Compiling rustdhipv2 v0.1.0 (/mnt/c/Users/Nil/devspace/rust/projects/rusty_hipv2)
    Finished dev [unoptimized + debuginfo] target(s) in 3m 12s
     Running `target/debug/examples/hip_initiator`
[1614620559.920s] (socket::set): [0]: adding
[1614620560.32s] (rustdhipv2::daemon::hipd): #imsg::(ihit < rhit)==true
[1614620560.32s] (rustdhipv2::daemon::hipd): #ista: hip_state::[None]=>[UNASSOCIATED]
[1614620560.33s] (rustdhipv2::daemon::hipd): #imsg: initiate [HIP_BEX]...
[1614620560.33s] (rustdhipv2::daemon::hipd): #imsg: sending [I1] packet: 56 bytes
[1614620560.33s] (socket::raw): #0:IPv4:0x8b: buffer to send 76 octets
[1614620560.33s] (rustdhipv2::daemon::hipd): #ista: hip_state::[UNASSOCIATED]=>[I1-SENT]
[1614620560.33s] (rustdhipv2::storage::HIPState): #log: new entry added to state_vars_map
[1614620560.33s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620560.33s] (iface::ethernet): packet dump follows:
EthernetII src=fa-e4-2c-1b-22-a3 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::f8e4:2cff:fe1b:22a3 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620560.33s] (hip_initiator): poll error: unrecognized packet
[1614620560.33s] (socket::raw): #0:IPv4:0x8b: sending 76 octets
[1614620560.41s] (iface::ethernet): address 192.168.69.2 not in neighbor cache, sending ARP request
[1614620560.41s] (socket::meta): #0: neighbor 192.168.69.2 missing, silencing until t+3.000s
[1614620560.41s] (iface::neighbor): filled 192.168.69.2 => 02-00-00-00-00-01 (was empty)
[1614620560.42s] (socket::meta): #0: neighbor 192.168.69.2 discovered, unsilencing
[1614620560.42s] (socket::raw): #0:IPv4:0x8b: sending 76 octets
[1614620560.77s] (socket::raw): #0:IPv4:0x8b: receiving 404 octets
[1614620560.78s] (socket::raw): #0:IPv4:0x8b: receive 404 buffered octets
[1614620560.78s] (rustdhipv2::daemon::hipd): #msg::(ihit < rhit)==false
[1614620560.89s] (rustdhipv2::daemon::hipd): #imsg: *****got [R1] packet*****
[1614620560.89s] (rustdhipv2::daemon::hipd): #ista: hip_state::[current state: I1Sent]
[1614620560.90s] (rustdhipv2::daemon::hipd): [R1] packet contains
[1614620560.90s] (rustdhipv2::daemon::hipd):     |__ + Puzzle parameter
[1614620560.90s] (rustdhipv2::daemon::hipd):     |__ + DH parameter
[1614620560.90s] (rustdhipv2::daemon::hipd):     |__ + Cipher Parameter
[1614620560.90s] (rustdhipv2::daemon::hipd):     |__ + ESP Transform Parameter
[1614620560.90s] (rustdhipv2::daemon::hipd):     |__ + Host Id parameter
[1614620560.91s] (rustdhipv2::daemon::hipd):         |__ + responder's OGA id 0x1
[1614620560.91s] (rustdhipv2::daemon::hipd):         |__ + responder's computed HIT: [32, 1, 32, 1, 132, 58, 150, 38, 12, 183, 21, 139, 116, 22, 246, 82]
[1614620560.91s] (rustdhipv2::daemon::hipd):         |__ + responder's actual HIT:   [32, 1, 32, 1, 132, 58, 150, 38, 12, 183, 21, 139, 116, 22, 246, 82]
[1614620560.91s] (rustdhipv2::daemon::hipd):         |__ + self HIT:                 [32, 1, 32, 1, 87, 49, 50, 242, 174, 14, 178, 139, 44, 8, 246, 35]
[1614620560.91s] (rustdhipv2::storage::HIPState): #log: new entry added to pubkey_map
[1614620560.91s] (rustdhipv2::daemon::hipd):     |__ + HIT Suit list parameter
[1614620560.91s] (rustdhipv2::daemon::hipd):     |__ + DH groups parameter
[1614620560.91s] (rustdhipv2::daemon::hipd):     |__ + Transport parameter
[1614620560.91s] (rustdhipv2::daemon::hipd):         |__ + Transport formats: Ok([15, 255])
[1614620560.91s] (rustdhipv2::daemon::hipd):     |__ + Signature parameter
[1614620573.867s] (rustdhipv2::daemon::hipd): #imsg: puzzle was solved
[1614620573.867s] (rustdhipv2::daemon::hipd): #imsg: time_taken: 13.776s < timer_duration: 64.000s
[1614620573.880s] (rustdhipv2::storage::HIPState): #log: new entry added to dh_map
[1614620573.880s] (rustdhipv2::storage::HIPState): #log: new entry added to key_info_map
[1614620573.880s] (rustdhipv2::storage::HIPState): #log: new entry added to cipher_map
[1614620573.882s] (rustdhipv2::storage::HIPState): #log: new entry added to keymat_map
[1614620573.882s] (rustdhipv2::daemon::hipd): #imsg: validated [R1] packet
[1614620573.887s] (rustdhipv2::daemon::hipd): #imsg: sending [I2] packet to 192.168.69.2, bytes sent 460
[1614620573.887s] (socket::raw): #0:IPv4:0x8b: buffer to send 460 octets
[1614620573.887s] (rustdhipv2::daemon::hipd): #ista: hip_state::[I1-SENT]=>[I2-SENT]
[1614620573.887s] (iface::ethernet): cannot process ingress packet: unrecognized packet
[1614620573.887s] (iface::ethernet): packet dump follows:
EthernetII src=fa-e4-2c-1b-22-a3 dst=33-33-00-00-00-16 type=IPv6
\ IPv6 src=fe80::f8e4:2cff:fe1b:22a3 dst=ff02::16 nxt_hdr=Hop-by-Hop hop_limit=1
[1614620573.887s] (hip_initiator): poll error: unrecognized packet
[1614620573.888s] (socket::raw): #0:IPv4:0x8b: sending 460 octets
[1614620573.908s] (socket::raw): #0:IPv4:0x8b: receiving 188 octets
[1614620573.908s] (socket::raw): #0:IPv4:0x8b: receive 188 buffered octets
[1614620573.908s] (rustdhipv2::daemon::hipd): #msg::(ihit < rhit)==false
[1614620573.909s] (rustdhipv2::daemon::hipd): #imsg: *****got [R2] Packet*****
[1614620573.909s] (rustdhipv2::daemon::hipd): [R2] packet contains:
[1614620573.909s] (rustdhipv2::daemon::hipd):     |__ + ESP Info parameter
[1614620573.909s] (rustdhipv2::daemon::hipd):     |__ + Mac2 parameter
[1614620573.909s] (rustdhipv2::daemon::hipd):     |__ + Signature2 parameter
[1614620573.909s] (rustdhipv2::daemon::hipd): #imsg: HMAC is Ok, proceed to compute signature...
[1614620573.917s] (rustdhipv2::daemon::hipd): #imsg: signature is Ok
[1614620573.917s] (rustdhipv2::daemon::hipd): #imsg: validated [R2] packet
[1614620573.917s] (rustdhipv2::daemon::hipd): #imsg: ending HIP BEX...
[1614620573.917s] (rustdhipv2::daemon::hipd): #imsg: setting SA records for...  192.168.69.1 <=> 192.168.69.2
[1614620573.917s] (rustdhipv2::storage::SecurityAssociations): #log: new entry added to sa_map
[1614620573.917s] (rustdhipv2::daemon::hipd): #ista: hip_state::[I2-SENT]=>[ESTABLISHED]
```