
## Host Identity Protocol for bare-metal systems, using Rust [![](https://tokei.rs/b1/github/nihalpasham/rustdhipv2?category=code)](https://github.com/nihalpasham/rustdhipv2)

I've been evaluating `TLS replacements` in constrained environments for a while now. Embedded systems have fewer (yet precise) security requirements, owing to available resources or by design.

Embedded systems, unlike people dont need to talk to every other machine on the planet. They are designed to perform a specific set of functions. Functions that most likely require them to communicate with other machines. 

The key point here is that the vast majority of embedded systems communicate with a `known or predetermined` set of peers. However, problem is that clearly identifying a networked machine (and its peers) is a non trivial undertaking, even today.

This repo implements the `HIPv2` IETF standard which aims to solve this problem. 

## Why not TLS:

TLS is not exactly a good fit for a couple of reasons.

- It comes with a plethora of extensions, ciphersuites and options.
- In addition to the above, TLS presents an additional set of challenges when working with devices that are limited in resources such as `compute, bandwidth or battery`.
- In reality, this combination of `limited resources and way too many options` is in itself a pretty good source of complexity, resulting in buggy or high-mainetnance implementations. 
- Put another way, this is a non-trivial undertaking, where even the most inconspicuous slip-up could prove to be a complete showstopper for everyone involved - the product teams/developers/integrators/maintenance engineers/mgmt.
- Mutual TLS authentication is NOT the default and a serious pain to get right. (especially in a constrained environment)
- Its not exactly lightweight (even with TLS 1.3) when you begin to account for extensions. Ex: client-auth extension.
- Certificate sizes.
- .... and more

**What's needed:** - a simpler, easy-to-use, lightweight secure channel. A secure channel with just 2 pre-requisites. It must provide any 2 communicating parties the ability `to mutually authenticate each other and encrypt all data end-end.`

More importantly, both pre-requisites must be the default and not tacked-on. 

## HIPv2 is an IETF standard *[[rfc7401](https://tools.ietf.org/html/rfc7401)]* that offers

- Mutual authentication by default 
	- HIPv2's central idea is - the creation and usage of unique, permanent, and cryptographically verifiable host/machine identities.
- End-End encryption (although not exactly a part of the HIPv2 standard, it is designed around ESP)
- Mobility and Multi-homing 
	- Example: Seamless switch-over to a backup `update-server` in a failover scenario.

The neat thing about HIPv2 is that it does NOT operate at the application-layer but rather is a part of a host's networking stack.

## Advantages:
- All network traffic flows through the secure channel by default
- We can build or extend it. 
	- Example: its much easier to do secure multiparty computation if you can `guarantee` that all parties possess unique cryptographically verifiable identities.

## A few things to keep in mind if you'd like to contribute:
- It’s a PoC.
- My core goal for this project is 
    - **To evaluate whether the entire HIPv2 protocol can be written in safe-rust, without the need for heap allocation, making it easier to port to any bare metal environment.**
- `Performance` has not been considered for now and but it can be optimized, when we have a working implementation.
- It uses const_generics which requires nightly as of this writing.
- In order to achieve its second goal (i.e. zero dynamic memory allocation), `rustdhipv2` depends on `smoltcp` and borrows many of its ideas (such as simplicity above all else). 

### Note: This is a WIP
I'm a security consultant by profession. This is a first attempt at putting together a full fledged networking-related library. Please be feel free to chime-in if something's amiss.
- I've tried to keep the layout of code similar to that of `smoltcp` but there are a couple of deviations in the `crypto` department. 
- I'll be adding more documentation over the coming weeks and months.

## HIP Overview 

One key component that binds `networking and security` is the concept of an IP address. An IP address provides 

- Location information to `network machines` 
- Identity information to `secure networks`

This duality of the `IP address` is why we can't uniquely identify machines across different networks. 

An IP address 

- can be spoofed, 
- can be dynamic, 
- is not a reliable piece of identification. 

Yet every piece of networking equipment - from firewalls to access controllers to IoT devices, all rely on an `IP` for location and identification. 

I spent some time understanding the concept of a location-identity split. For starters, HIP is an IETF standard that's been in the making for over 15 years, 

- HIP solves the problem of having to rely on overloaded IP addresses by splitting the 2 tasks i.e. 
	- `machine/host identification` and 
	- `machine/host location`
- It proposes the use of 2 different markers to represent location and identification information.

This simple change can help us build drastically different networks where secure internetworking is an inherent property of the system.

## How it works -

HIP assigns a permanent, location-independent name to a host. HIP names are cryptographic identities that can be used to uniquely identify a host called host identity (it's essentially a public key). As public keys are quite long, usually it is more convenient to use a 128-bit fingerprint of the HI, which is called the Host Identity Tag (HIT). The HIT resembles an IPv6 address, and it gives the host a permanent name. 

*The Internet Assigned Numbers Authority (IANA) allocated an IPv6 address prefix for HITs (2001:0010::/28)*

In HIP, when you call the OS's socket API, transport sockets (TCP/UDP) are bound to HITs rather than IP addresses. The networking stack translates the HITs to IP addresses before packet transmission on the wire. The reverse occurs on the host receiving HIP packets. When the host changes the network, the networking stack changes the IP address for the translation. The application doesn't notice the change because it is using the constant HIT. This is how HIP solves the problem of host mobility (which is a bonus if we were just looking for security).

<p align="center">
  <img width="500" height="300" src="https://user-images.githubusercontent.com/20253082/108634128-2dfad480-749e-11eb-83fc-24652311e409.png">
</p>

HIP is a 2 round-trip, end-to-end Diffie-Hellman key-exchange protocol, called base-exchange with mobility updates and some additional messages. The networking stack triggers the base exchange automatically when an application tries to connect to an HIT. 

<p align="center">
  <img width="500" height="400" src="https://user-images.githubusercontent.com/20253082/108632871-18ce7780-7497-11eb-937b-99c545d3c00e.png">
</p>

During a base exchange, a client (initiator) and a server (responder) authenticate each other with their public keys and generate symmetric encryption keys. The data flow between them is encrypted by IPsec Encapsulating Security Payload (ESP) with the symmetric key set up by HIP. HIP introduces mechanisms, such as `computational puzzles`, that protect HIP responders (servers) against DoS attacks. The initiator must solve a computational puzzle. The responder selects the difficulty of the puzzle according to its load. When the responder is busy or under DoS attack, the responder can increase the puzzle difficulty level to delay new connections. Applications simply need to use HITs instead of IP addresses. Application source code does not need to be modified. 
 
We can describe this process as follows: 

| 			 DNS Lookup                     |
|-------------------------------------------|
| I  --> &nbsp; DNS: &nbsp; lookup R  		            |
| I  <-- &nbsp; DNS: &nbsp; return R's address and HI/HIT|

|  Base	 | Exchange	| 										   |
|--------|----------|------------------------------------------|
| I1     | I --> R  | Hi, Here is my I1, let's talk with HIP   |
| R1     | R --> I  | OK, Here is my R1, solve this HIP puzzle |
| I2     | I --> R  | Computing, here is my counter I2		   |
| R2     | R --> I  | OK. Let's finish base exchange with my R2|

| 			 Encrypted data	                |
|-------------------------------------------|
| I --> &nbsp;	R (ESP protected data)      |
| R --> &nbsp;	I (ESP protected data)		|

## What's supported so far:
- [x] HIP Base Exchange
	- support for crafting HIP BEX packet types - I1, R1, I2, R2. 
	- support for the 2 round-trip, end-to-end Diffie-Hellman (ECDH256, ECDH384) key-exchange protocol.
	- support for ECSDA-256 (or 384) signature based authentication. 
	- support for I2 and R2 (HMAC-SHA-256 based) message authentication codes.   
	- support for HMAC-based key derivation function to compute shared `HMAC and AES keys` 
	- support for computational puzzles to protect HIP responders
	- support for the (complete) HIP wire format (including all HIP parameters, packet types)
	- BEX is written in **safe-rust** and does not require dynamic memory allocation except when using
	 	- ECDH384 and ECDSA384 impl(s) which require dynamic memory allocation for now (as they rely on the `num-bigint-dig` crate).

Note: This is a huge monolith for now. I do plan to re-factor this to make it more modular i.e. I'm thinking there should be a separate packet-processing logic block for each of the different packet-types. This should in theory make it easier to use rust's type-system to to enforce state-transition rules aka **make invalid states un-representable**.

## HIP BEX examples:

The examples folder contains 2 examples 
- **hip_initiator:** triggers or initiates the HIP session over `rawsockets` and is assigned
	- IP - `192.168.69.1` 
	- HIT - `2001:2001:5731:32f2:ae0e:b28b:2c08:f623`
- **hip_responder:** responds to and processes valid incoming HIP packets
	- IP - `192.168.69.2`
	- HIT - `2001:2001:843a:9626:0cb7:158b:7416:f652`

You can test these examples via the `cargo run` command. But before you do, you'll need to add a `bridge and 2 tap interfaces`. You can do this via the following commands

```sh 
ip tuntap add name tap0 mode tap user {$USER}
ip tuntap add name tap1 mode tap user {$USER}
brctl addbr br0
brctl addif br0 tap0 tap1 
ip link set tap0 up
ip link set tap1 up
ip link set br0 up
```

check to see if everything's working via an `ifconfig` call. Once done, run the following in separate terminals.

- `cargo run --example hip_responder` (make sure you run the server/responder first)
- `cargo run --example hip_initiator`

This should produce initiator and responder logs. Reference logs are available in the logs folder.

*If you're using VSCode, pull up the task-list and run the `bridge tap interfaces` task. This should run the above commands and set you up.* 

## Conclusion: Identity based networking

We can now design networks where devices talk to each other without having to navigate the complex landscape of network security.

- Note - HIPv2 doesn't mandate use of a specific method/mechanism, when it comes to establishing trust (i.e. certifying public keys). It is expected that each system using HIP may want to address it differently. But if you want to use *X.509 version 3* certificates, [RFC 8002](https://datatracker.ietf.org/doc/html/rfc8002) adds support for HIP certificates via an additional *CERT* parameter. 

### References

- https://tools.ietf.org/html/rfc7401 - *HIPv2 RFC*
- https://code.launchpad.net/~hipl-core/hipl/trunk
- https://github.com/dmitriykuptsov/cutehip
- https://www.tempered.io/resources/#whitepapers 
