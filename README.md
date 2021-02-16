### Context: 
I've been evaluating `TLS replacements` for constrained/embedded systems for a while now. Embedded systems have fewer (yet precise) security requirements, owing to available resources and TLS is not exactly a good fit for a couple of reasons.

### Why not TLS:
- Bloated with a plethora of extensions 
- Mutual TLS authentication is NOT the default and a serious pain to get right. (especially in a constrained environment)
- Its not exactly lightweight (even with TLS 1.3) when you begin to account for extensions. Ex: client-auth extension.
- Certificate sizes.

What's needed is a simpler, easy-to-use, lightweight secure channel. A secure channel with 2 pre-requisites. It must allow any 2 communicating parties the ability `to mutually authenticate each other coupled with end-end data encryption.`

More importantly, both pre-requisites must be the default and not tacked-on. 

### HIPv2 is an IETF standard [[RFC7401](https://tools.ietf.org/html/rfc7401)] that offers

- Mutual authentication by default 
	- HIPv2's central idea is - the creation and usage of unique, permanent, and cryptographically verifiable host/machine identities.
- End-End encryption (although not exactly a part of the HIPv2 standard but is designed around ESP)
- Mobility and Multi-homing 
	- Example: Seamless switch-over to a backup `update-server` in a failover scenario.

The neat thing about HIPv2 is that it operates at the application-layer and is a part of a host's networking stack.

### Advantages:
- All network traffic flows through the secure channel by default
- We can build or extend it. 
	- Example: its much easier to do secure multiparty computation if you can `guarantee` that all parties possess unique verifiable identities.

### A few things to keep in mind if you'd like to contribute:
- It’s a PoC.
- My core goal for this project is 
    - **To evaluate whether the entire HIPv2 protocol can be written in safe-rust, without the need for heap allocation, making it easier to port to any bare metal environment.**
- `Performance` has not been considered for now and but it can be optimized after we have a fully working implementation.
- It uses const_generics which requires nightly as of this writing.
- In order to achieve its second goal (i.e. zero dynamic memory allocation), `rustdhipv2` depends on `smoltcp` and borrows many of its ideas (such as simplicity above all else). 

### Notes: This is a WIP
I'm a security consultant by profession. This is my very first attempt at putting together a full fledged networking-related library. Please be feel free to chime-in if something's amiss.
- I've tried to keep the layout of code similar to that of `smoltcp` but there are a couple of deviations in the `crypto` department. 
- I'll be adding more documentation over the coming weeks and months.

### HIP Overview 

One key component that binds `networking and security` is the concept of an IP address. An IP address provides 

- Location information to `network machines` 
- Identity information to `secure networks`

This duality of the `IP address` is why we can't uniquely identify machines across different networks. 

An IP address 

- can be spoofed, 
- it can be dynamic, 
- it is not a reliable piece of identification. 

Yet every piece of networking equipment - from firewalls to access controllers to IoT devices, all rely on an `IP` for location and identification. 

I spent some time understanding the concept of a location-identity split. For starters, HIP is an IETF standard that's been in the making for over 15 years, 

- HIP solves the problem of having to rely on overloaded IP addresses by splitting the 2 tasks i.e. 
	- `machine/host identification` and 
	- `machine/host location`
- It proposes the use of 2 different markers to represent location and identification information.

This simple change can help us build drastically different networks where secure internetworking is an inherent property of the system.

### How it works -

HIP assigns a permanent, location-independent name to a host. HIP names are cryptographic identities that can be used to uniquely identify a host called host identity (it's essentially a public key). As public keys are quite long, usually it is more convenient to use a 128-bit fingerprint of the HI, which is called the Host Identity Tag (HIT). The HIT resembles an IPv6 address, and it gives the host a permanent name. 

*The Internet Assigned Numbers Authority (IANA) allocated an IPv6 address prefix for HITs (2001:0010::/28)*

In HIP, when you call the OS's socket API, transport sockets (TCP/UDP) are bound to HITs rather than IP addresses. The networking stack translates the HITs to IP addresses before packet transmission on the wire. The reverse occurs on the host receiving HIP packets. When the host changes the network, the networking stack changes the IP address for the translation. The application doesn't notice the change because it is using the constant HIT. This is how HIP solves the problem of host mobility (which is a bonus if we were just looking for security).

![Host Identity Protocol Overview](https://user-images.githubusercontent.com/20253082/107903532-864a4780-6f6f-11eb-8362-b5f816d86fd2.jpg)


HIP is a two round-trip, end-to-end Diffie-Hellman key-exchange protocol, called base-exchange with mobility updates and some additional messages. The networking stack triggers the base exchange automatically when an application tries to connect to an HIT. 

![HIP Base Exchange](https://user-images.githubusercontent.com/20253082/107903606-b42f8c00-6f6f-11eb-99a9-2ee7b70bb2ca.png)

During a base exchange, a client (initiator) and a server (responder) authenticate each other with their public keys and generate symmetric encryption keys. The data flow between them is encrypted by IPsec Encapsulating Security Payload (ESP) with the symmetric key set up by HIP. HIP introduces mechanisms, such as cryptographic puzzles, that protect HIP responders (servers) against DoS attacks. The initiator must solve a computational puzzle. The responder selects the difficulty of the puzzle according to its load. When the responder is busy or under DoS attack, the responder can increase the puzzle difficulty level to delay new connections. Applications simply need to use HITs instead of IP addresses. Application source code does not need to be modified. 
 
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

### Conclusion: Identity based networking

We can now design networks where devices talk to each other without having to navigate the complex landscape of network security.

- For example: A private non-routable IP within network A can talk to another non-routable IP within network B by authenticating each other with non-spoofable cryptographic machine identities (i.e. public keys or HITs).  
- Note - Certifying public keys or otherwise creating trust relationships between hosts has explicitly been left out of the HIP architecture, it is expected that each system using HIP may want to address it differently. 

