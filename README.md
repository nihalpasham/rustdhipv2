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
