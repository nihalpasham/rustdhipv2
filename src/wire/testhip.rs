#![allow(warnings)]
// use std::sync::atomic::AtomicU8;

use byteorder::{ByteOrder, NetworkEndian};
// use core::{cmp, fmt, i32, ops};

// use smoltcp::phy::ChecksumCapabilities;
use crate::{HIPError, Result};
use super::constants::field;

/// A read/write wrapper around a Host Identity Protocol packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with HIP packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::Malformed)` if the header length field has a value smaller
    /// than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::HIP_RECIEVERS_HIT.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let header_len = self.get_header_length() as usize;
            if len < header_len {
                Err(HIPError::Bufferistooshort)
            } else if header_len < field::HIP_RECIEVERS_HIT.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the next header field.
    #[inline]
    pub fn get_next_header(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::NXT_HDR]
    }

    /// Return the header length field.
    #[inline]
    pub fn get_header_length(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::HDR_LEN]
    }

    /// Return the packet type field
    pub fn  get_packet_type(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::PKT_TYPE] & 0x7F
    }

    /// Return the HIP `version` field
    #[inline]
	pub fn  get_version(self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VERSION] >> 0x4) & 0xFF
    }
     
    /// Return the checksum field
    #[inline]
	pub fn  get_checksum(self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::CHECKSUM.start] as u16) << 0x8) | data[field::CHECKSUM.start + 1] as u16
    }

    /// Return the `controls` field value
    #[inline]
	pub fn  get_controls(self) -> u16 { 
        let data = self.buffer.as_ref();
        ((data[field::CONTROLS.start] as u16) << 0x8) | data[field::CONTROLS.start + 1] as u16
    }
    
    /// Return the sender's 128-bit HIT value
    #[inline]
    pub fn  get_senders_hit(self) -> u128 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u128(&data[field::HIP_SENDERS_HIT])
    }
    
    /// Return the receiver's 128-bit HIT value
    #[inline]
	pub fn  get_receivers_hit(self) -> u128 { 
       let data = self.buffer.as_ref();
       NetworkEndian::read_u128(&data[field::HIP_RECIEVERS_HIT])
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a slice of bytes contaning all HIP parameters.
    #[inline]
    pub fn all_parameters(&self) -> &'a [u8] {
        let header_len = self.get_header_length() * 8 + 8;
        let data = self.buffer.as_ref();
        &data[field::HIP_PARAMS(header_len)]
    }

    /// Return a pointer to the payload (i.e. starting index of HIP parameters)
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[field::HIP_RECIEVERS_HIT.end..]
    }

    /// Return list of HIP parameters from a HIPPacket.
    pub fn get_parameters(&self) -> &'a [HIPParameter<&[u8]>] {
        let mut offset = field::HIP_RECIEVERS_HIT.end;
        let mut has_more_params = false;
        let len = self.get_header_length() * 8 + 8;
        if len > field::HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES as u8 { has_more_params = true;};
        if len != self.buffer.as_ref().len() as u8 { return &[];}; 

        let mut idx = 0;
        let param_list = &mut [];
        let data = self.buffer.as_ref();
        while has_more_params {
            let param_type = NetworkEndian::read_u16(&data[offset..offset+2]);
            let param_len = NetworkEndian::read_u16(&data[offset + 2..offset + 4]);
            let mut total_param_len = 11 + param_len - (param_len - 3) % 8;

            let param_data = &data[offset..offset + total_param_len as usize];
            match param_type as usize {
                (field::HIP_R1_COUNTER_TYPE)             => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_PUZZLE_TYPE)                 => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_SOLUTION_TYPE)               => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_DH_GROUP_LIST_TYPE)          => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_DH_TYPE)                     => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_CIPHER_TYPE)                 => {param_list[idx] = HIPParameter::new_unchecked(param_data)}, 
                (field::HIP_ESP_TRANSFORM_TYPE)          => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ESP_INFO_TYPE)               => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_HI_TYPE)                     => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_HIT_SUITS_TYPE)              => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_TRANSPORT_FORMAT_LIST_TYPE)  => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_MAC_TYPE)                    => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_MAC_2_TYPE)                  => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_SIG_TYPE)                    => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_SIG_2_TYPE)                  => {param_list[idx] = HIPParameter::new_unchecked(param_data)}, 
                (field::HIP_SEQ_TYPE)                    => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ACK_TYPE)                    => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ENCRYPTED_TYPE)              => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_NOTIFICATION_TYPE)           => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ECHO_REQUEST_SIGNED_TYPE)    => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ECHO_REQUEST_UNSIGNED_TYPE)  => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ECHO_RESPONSE_SIGNED_TYPE)   => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                (field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE) => {param_list[idx] = HIPParameter::new_unchecked(param_data)},
                _                                        => continue
            }
            idx += 1;
            offset += total_param_len as usize;
			if offset >= len as usize {
                has_more_params = false;
            }
        }
        param_list
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the next header field.
    #[inline]
    pub fn   set_next_header(&mut self, value: u8) {
       let data = self.buffer.as_mut();
       data[field::NXT_HDR] = value
    }

    /// Set the header length field.
    #[inline]
    pub fn   set_header_length(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HDR_LEN] = value
     }

     /// Set the packet type field.
     #[inline]
     pub fn  set_packet_type(&mut self, packet_type: u8) {
        let data = self.buffer.as_mut();
        data[field::PKT_TYPE] = packet_type & 0x7F;
    }

    /// Set the version length field.
    #[inline]
    pub fn  set_version(& mut self, version: u8 ) {
        let data = self.buffer.as_mut();
        data[field::VERSION] = 0x1;
        data[field::VERSION] = (version << 4) | data[field::VERSION];
    }

    /// Set the checksum field.
    #[inline]
    pub fn  set_checksum(&mut self, checksum: u16) {
        let data = self.buffer.as_mut();
        data[field::CHECKSUM.start] = ((checksum >> 8) & 0xFF) as u8;
        data[field::CHECKSUM.start + 1] = (checksum & 0xFF) as u8
    }

    /// Set the controls field.
    #[inline]
    pub fn  set_controls(&mut self, controls: u16) {
        let data = self.buffer.as_mut();
        data[field::CONTROLS.start] = ((controls >> 8) & 0xFF) as u8;
        data[field::CONTROLS.start + 1] = (controls & 0xFF) as u8
    }

    /// Set the `senders HIT` field.
    #[inline]
    pub fn  set_senders_hit(&mut self, hit: u128) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u128(&mut data[field::HIP_SENDERS_HIT], hit);
    }

    /// Set the `receivers HIT` field.
    #[inline]
    pub fn  set_receivers_hit(&mut self, hit: u128) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u128(&mut data[field::HIP_RECIEVERS_HIT], hit);
    }
}

/// A read/write wrapper around a generic HIP parameter buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct HIPParameter<T: AsRef<[u8]>> {
    buffer: T,
}

impl<T: AsRef<[u8]>> HIPParameter<T> {

    /// Imbue a raw octet buffer with HIP packet structure.
    pub fn new_unchecked(buffer: T) -> HIPParameter<T> {
        HIPParameter { buffer }
    }

    /// Return a parameter type field for a given HIP parameter. 
    #[inline]
    pub fn   get_type(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::HIP_TLV_TYPE_OFFSET.start] as u16) << 0x8) | data[field::HIP_TLV_TYPE_OFFSET.start + 1] as u16
    }

    /// Return the value of the critical bit field ( a value of 1 indicates parameter is critical; 0 - not critical)
    #[inline]
    pub fn   get_critical_bit(&self) -> u16 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::HIP_TLV_CRITICAL_BIT_OFFSET]);
        raw & 0x1
    }

    /// Returns the value of parameter's length field
    #[inline]
    pub fn   get_length(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::HIP_TLV_LENGTH_OFFSET.start] as u16) << 0x8) | data[field::HIP_TLV_LENGTH_OFFSET.start + 1] as u16
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn   into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HIPParameter<T> {
    /// Set the parameter type field for a given HIP parameter. 
    #[inline]
    pub fn   set_type(&mut self, pkt_type: u16) {
        let data = self.buffer.as_mut();
		data[field::HIP_TLV_TYPE_OFFSET.start] = ((pkt_type >> 8) & 0xFF) as u8;
        data[field::HIP_TLV_TYPE_OFFSET.start + 1] = (pkt_type & 0xFF) as u8;
    }

    /// Sets the value of parameter's length field
    #[inline]
    pub fn   set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
		data[field::HIP_TLV_LENGTH_OFFSET.start] = ((length >> 8) & 0xFF) as u8;
        data[field::HIP_TLV_LENGTH_OFFSET.start + 1] = (length & 0xFF) as u8;
    }
}

pub trait R1CounterParam {
    /// Initialize R1 parameter
    fn   init_r1_counter_param(&mut self);
    /// Returns the counter field in an R1 parameter
    fn   get_counter(&self) -> Result<u64>;
    /// Sets the counter field in an R1 parameter
    fn   set_counter(&mut self, value: u64) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> R1CounterParam for HIPParameter<T> {
     
     #[inline]
    fn   init_r1_counter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH  + 
                         field::HIP_TLV_TYPE_LENGTH    +
                         field::HIP_R1_COUNTER_RES_LEN +
                         field::HIP_R1_GEN_COUNTER_LEN)];
        self.set_type(field::HIP_R1_COUNTER_TYPE as u16);
        self.set_length(field::HIP_R1_COUNTER_LENGTH as u16);
 
    }
    
    #[inline]
    fn   get_counter(&self) -> Result<u64> {
        if self.get_type() == field::HIP_R1_COUNTER_TYPE as u16 {
            let data = self.buffer.as_ref();
            let counter = NetworkEndian::read_u64(&data[field::HIP_R1_COUNTER_OFFSET]);
            Ok(counter)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn   set_counter(&mut self, value: u64) -> Result<()> {
        if self.get_type() == field::HIP_R1_COUNTER_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u64(&mut data[field::HIP_R1_COUNTER_OFFSET], value))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

pub trait PuzzleParameter {
    /// Initialize puzzle parameter
    fn   init_puzzle_param(&mut self);
    /// Returns the `k` value of the puzzle parameter. #K is the number of verified bits
    fn   get_k_value(&self) -> Result<u8>;
    /// Sets the `k` value of the puzzle parameter. #K is the number of verified bits
    fn   set_k_value(&mut self, k: u8) -> Result<()>;
    /// Returns the puzzle lifetime of the puzzle parameter. puzzle lifetime 2^(value - 32) seconds
    fn   get_lifetime(&self) -> Result<u8>;
    /// Sets puzzle lifetime of the puzzle parameter. puzzle lifetime 2^(value - 32) seconds
    fn   set_lifetime(&mut self, lifetime: u8) -> Result<()>;
    /// Returns the opaque field value of the puzzle parameter i.e. data set by the Responder, indexing the puzzle.
    fn   get_opaque(&self) -> Result<u16>;
    /// Sets the opaque field value of the puzzle parameter i.e.data set by the Responder, indexing the puzzle
    fn   set_opaque(&mut self, value: u16) -> Result<()>;
    /// Returns the random number field of the puzzle parameter (of size RHASH_len bits).
    fn   get_random(&self) -> Result<u32>;
    /// Sets the random number field of the puzzle parameter.
    fn   set_random(&mut self, value: u32) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> PuzzleParameter for HIPParameter<T> {

    #[inline]
    fn init_puzzle_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH      + 
                         field::HIP_TLV_TYPE_LENGTH        +
                         field::HIP_PUZZLE_K_LENGTH        +
                         field::HIP_PUZZLE_LIFETIME_LENGTH +
                         field::HIP_PUZZLE_OPAQUE_LENGTH   +
                         field::HIP_PUZZLE_RANDOM_I_LENGTH)];
        self.set_type(field::HIP_PUZZLE_TYPE as u16);
        self.set_length(field::HIP_PUZZLE_LENGTH as u16);

    }

    #[inline]
    fn get_k_value(&self) -> Result<u8> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let data = self.buffer.as_ref();
            Ok(data[field::HIP_PUZZLE_K_OFFSET.start] & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_k_value(&mut self, k: u8) -> Result<()> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let mut data = self.buffer.as_mut();
            Ok(data[field::HIP_PUZZLE_K_OFFSET.start] = k & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_lifetime(&self) -> Result<u8> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let data = self.buffer.as_ref();
            Ok(data[field::HIP_PUZZLE_LIFETIME_OFFSET.start] & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_lifetime(&mut self, lifetime: u8) -> Result<()> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let mut data = self.buffer.as_mut();
            Ok(data[field::HIP_PUZZLE_LIFETIME_OFFSET.start] = lifetime & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_opaque(&self) -> Result<u16> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
        let data = self.buffer.as_ref();
        let opaque = NetworkEndian::read_u16(&data[field::HIP_PUZZLE_OPAQUE_OFFSET]);
        Ok(opaque)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque(&mut self, opaque: u16) -> Result<()> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_PUZZLE_OPAQUE_OFFSET], opaque))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_random(&self) -> Result<u32> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let data = self.buffer.as_ref();
            let random = NetworkEndian::read_u32(
                &data[field::HIP_PUZZLE_RANDOM_I_OFFSET.start..field::HIP_PUZZLE_RANDOM_I_LENGTH]);
            Ok(random)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_random(&mut self, random: u32) -> Result<()> {
        if self.get_type() == field::HIP_PUZZLE_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(
                &mut data[field::HIP_PUZZLE_RANDOM_I_OFFSET.start..field::HIP_PUZZLE_RANDOM_I_LENGTH], random))
        } else {
            Err(HIPError::Illegal)
        }
    }
}
/// [5.2.5.  SOLUTION]: https://tools.ietf.org/html/rfc7401#section-5.2.5 
pub trait SolutionParameter {
    /// Initialize solution parameter
    fn init_solution_param(&mut self);
    /// Returns the `k` value of the solution parameter. #K is the number of verified bits
    fn get_k_value(&self) -> Result<u8>;
    /// Sets the `k` value of the solution parameter. #K is the number of verified bits
    fn set_k_value(&mut self, k: u8) -> Result<()>;
    /// Returns the opaque field value of the solution parameter (copied unmodified from the received PUZZLE parameter)
    fn get_opaque(&self) -> Result<u16>;
    /// Sets the opaque field value of the solution parameter (copied unmodified from the received PUZZLE parameter)
    fn set_opaque(&mut self, opaque: u16) -> Result<()>;
    /// Returns the random number field of the solution parameter (of size RHASH_len bits).
    fn get_random(&self) -> Result<u32>;
    /// Sets the random number field of the solution parameter.
    fn set_random(&mut self, random: u32) -> Result<()>;
    /// Returns puzzle solution value
    fn get_solution(&self) -> Result<u32>;
    /// Set puzzle solution value
    fn set_solution(&mut self, solution: u32) -> Result <()>;
}


impl<T: AsRef<[u8]> + AsMut<[u8]>> SolutionParameter for HIPParameter<T> {

    #[inline]
    fn init_solution_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH        + 
                         field::HIP_TLV_TYPE_LENGTH          +
                         field::HIP_SOLUTION_K_LENGTH        +
                         field::HIP_SOLUTION_RESERVED_LENGTH +
                         field::HIP_SOLUTION_OPAQUE_LENGTH   +
                         field::HIP_SOLUTION_RANDOM_I_LENGTH +
                         field::HIP_SOLUTION_J_LENGTH)];
        self.set_type(field::HIP_SOLUTION_TYPE as u16);
        self.set_length(field::HIP_SOLUTION_LENGTH as u16);

    }

    #[inline]
    fn get_k_value(&self) -> Result<u8> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_ref();
            Ok(data[field::HIP_SOLUTION_K_OFFSET.start] & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_k_value(&mut self, k: u8) -> Result<()> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let mut data = self.buffer.as_mut();
            Ok(data[field::HIP_SOLUTION_K_OFFSET.start] = k & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_opaque(&self) -> Result<u16> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
        let data = self.buffer.as_ref();
        let opaque = NetworkEndian::read_u16(&data[field::HIP_SOLUTION_OPAQUE_OFFSET]);
        Ok(opaque)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque(&mut self, opaque: u16) -> Result<()> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_SOLUTION_OPAQUE_OFFSET], opaque))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_random(&self) -> Result<u32> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_ref();
            let random = NetworkEndian::read_u32(
                &data[field::HIP_SOLUTION_RANDOM_I_OFFSET.start..field::HIP_SOLUTION_RANDOM_I_LENGTH]);
            Ok(random)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_random(&mut self, random: u32) -> Result<()> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(
                &mut data[field::HIP_SOLUTION_RANDOM_I_OFFSET.start..field::HIP_SOLUTION_RANDOM_I_LENGTH], random))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_solution(&self) -> Result<u32> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_ref();
            let solution = NetworkEndian::read_u32(
                &data[field::HIP_SOLUTION_J_OFFSET.start..field::HIP_SOLUTION_J_LENGTH]);
            Ok(solution)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_solution(&mut self, solution: u32) -> Result<()> {
        if self.get_type() == field::HIP_SOLUTION_TYPE as u16 {
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(
                &mut data[field::HIP_SOLUTION_J_OFFSET.start..field::HIP_SOLUTION_J_LENGTH], solution))
        } else {
            Err(HIPError::Illegal)
        }
    }
}
/// DH_GROUP_LIST parameter contains the list of supported DH Group
/// IDs of a host. See [RFC 7401 5.2.6]
///
/// [RFC 7401 5.2.6]: https://tools.ietf.org/html/rfc7401#section-5.2.6 
pub trait DHGroupListParameter {
    /// Initialize DH groups list parameter
    fn init_dhgrouplist_param(&mut self);
    /// Returns a list of groups as a slice of u8's
    fn get_groups(&self) -> Result<&[u8]>;
    /// Sets the groups of lists, given a slice of u8's
    fn set_groups(&mut self, groups: &[u8]) -> Result<()>;
}

// DHGroupListParameter is a Variable length parameter
impl<T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> DHGroupListParameter for HIPParameter<&mut T> {
    
    #[inline]
   fn init_dhgrouplist_param(&mut self) {
       let mut data = self.buffer.as_mut();
       data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
       self.set_type(field::HIP_DH_GROUP_LIST_TYPE as u16);
       self.set_length(0);
   }

   #[inline]
   fn get_groups(&self) -> Result<&[u8]> {
       if self.get_type() == field::HIP_DH_GROUP_LIST_TYPE as u16 {
           let data = self.buffer.as_ref();
           let length = self.get_length();
           Ok(&data[field::HIP_DH_GROUP_LIST_OFFSET.start..field::HIP_DH_GROUP_LIST_OFFSET.start + length as usize])
       } else {
           Err(HIPError::Illegal)
       }
   }

   #[inline]
   fn set_groups(&mut self, groups: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_DH_GROUP_LIST_TYPE as u16 {
            let groups_len = groups.len();
            self.set_length(groups_len as u16);
            {
                let data = self.buffer.as_mut();
                // let bytes = NetworkEndian::read_uint(groups, groups.len());
                // NetworkEndian::write_uint(&mut data[4..4 + groups_len], bytes, groups_len);
                data[field::HIP_DH_GROUP_LIST_OFFSET.start..field::HIP_DH_GROUP_LIST_OFFSET.start + groups_len]
                        .copy_from_slice(groups);
            }
            let pad_len :usize = (8 - (4 + groups_len) % 8) % 8;  // pad_len is computed at runtime - i.e. a non-constant
            let padding = [0; 8];   // max padding is 8 bytes
            let pad_offset = 4 + groups_len;

            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    } else {
        Err(HIPError::Illegal)
    }
  }
}
/// A single DIFFIE_HELLMAN parameter may be included in selected HIP
/// packets based on the DH Group ID selected (Section 5.2.6) - [RFC 7401 5.2.7]
///
/// [RFC 7401 5.2.7]: https://tools.ietf.org/html/rfc7401#section-5.2.7
pub trait DHParameter {
    /// Initialize `DH Parameter` parameter
    fn init_dhparameter_param(&mut self);
    /// Returns the DH GROUP ID. This ID is used to ientify values for p and g as well as the KDF
    fn get_group_id(&self) -> Result<u8>;
    /// Sets the GROUP ID. This ID is used to identify values for p and g as well as the KDF
    fn set_group_id(&mut self, group_id: u8) -> Result<()>;
    /// Returns the length of the Public Value field in octets
    fn get_public_value_length(&self) -> Result<u16>;
    /// Sets the length of the Public Value field in octets
    fn set_public_value_length(&mut self, pub_len: u16) -> Result<()>;
    /// Returns the contents of the public value field i.e. sender's public Diffie-Hellman key
    fn get_public_value(&self) -> Result<&[u8]>;
    /// Sets the public value field i.e. sender's public Diffie-Hellman key.
    fn set_public_value(&mut self, pub_val: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DHParameter for HIPParameter<T> {

    #[inline]
    fn init_dhparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_GROUP_ID_LENGTH   +
                         field::HIP_PUBLIC_VALUE_LENGTH_LENGTH)];
        self.set_type(field::HIP_DH_TYPE as u16);
        self.set_length((field::HIP_GROUP_ID_LENGTH + field::HIP_PUBLIC_VALUE_LENGTH_LENGTH) as u16);
    }
    
    #[inline]
    fn get_group_id(&self) -> Result<u8> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            let data = self.buffer.as_ref();
            Ok(data[field::HIP_DH_GROUP_ID_OFFSET.start] & 0xFF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_group_id(&mut self, group_id: u8) -> Result<()> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            let mut data = self.buffer.as_mut();
            Ok(data[field::HIP_DH_GROUP_ID_OFFSET.start] = group_id)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_public_value_length(&self) -> Result<u16> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            let data = self.buffer.as_ref();
            Ok(((data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.start] as u16) << 0x8) | 
                (data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.start + 1] as u16))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_public_value_length(&mut self, pub_len: u16) -> Result<()> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            let mut data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET], pub_len))
        } else {
            Err(HIPError::Illegal)
        }    
    }

    #[inline]
    fn get_public_value(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            let data = self.buffer.as_ref();
            if let Ok(public_value_length) = self.get_public_value_length() {
                Ok(&data[field::HIP_PUBLIC_VALUE_OFFSET.start..
                    field::HIP_PUBLIC_VALUE_OFFSET.start + public_value_length as usize])
            } else {
                Err(HIPError::__Nonexhaustive) // This should probably be unreachable
            }
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_public_value(&mut self, pub_val: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_DH_TYPE as u16 {
            if let Ok(public_value_length) = self.get_public_value_length() {
                if public_value_length != 0x0 {return Err(HIPError::Illegal);};
                let mut len = self.get_length();
                len += pub_val.len() as u16;
                self.set_length(len);
                self.set_public_value_length(len as u16);
                {
                let mut data = self.buffer.as_mut();
                data[field::HIP_PUBLIC_VALUE_OFFSET.start..field::HIP_PUBLIC_VALUE_OFFSET.start + len as usize]
                    .copy_from_slice(pub_val);
                }
                let pad_len: usize = (8 - (4 + len as usize) % 8) % 8;  // pad_len is computed at runtime - i.e. non constant
                let padding = [0; 8];
                let pad_offset = 4 + len as usize;
            
                let data = self.buffer.as_mut();
                Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
            } else {
            Err(HIPError::Illegal)
            }
        } else {
            Err(HIPError::Illegal)
        }
    }
}


/// This parameter identifies the cipher algorithm to be used for
/// encrypting the contents of the ENCRYPTED parameter [RFC 7401 5.2.8]
///
/// [RFC 7401 5.2.8]: https://tools.ietf.org/html/rfc7401#section-5.2.8
pub trait CipherParameter {
    /// Intialize `Cipher Parameter` parameter
    fn init_cipherparameter_param(&mut self);
    /// Returns the list of ciphers IDs. Ciphers IDs identify the cipher algorithm to be used for
    /// encrypting the contents of the ENCRYPTED parameter
    fn get_ciphers(&self) -> Result<&[u8]>;
    /// Returns the list of ciphers IDs. Ciphers IDs identify the cipher algorithm to be used for
    /// encrypting the contents of the ENCRYPTED parameter 
    fn set_ciphers(&mut self, ciphers: &[u8]) -> Result<()>; 
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> CipherParameter for HIPParameter<T> {

    #[inline]
    fn init_cipherparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_CIPHER_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_ciphers(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_CIPHER_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let length = self.get_length();
            Ok(&data[field::HIP_CIPHER_LIST_OFFSET.start..field::HIP_CIPHER_LIST_OFFSET.start + length as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_ciphers(&mut self, ciphers: &[u8]) -> Result<()> {
        let length = self.get_length();
        if length > 0 { return Err(HIPError::FieldisAlreadySet);};
        // cipher ids are 2 byte fields and a HIP_CIPHER parameter MUST make sure that there are no
        // more than six (6) Cipher IDs in one HIP_CIPHER parameter. RFC 7401 - 5.2.8
        if (ciphers.len() % 2 != 0) && (ciphers.len() <= 12) {return Err(HIPError::Illegal);}; 
        self.set_length(ciphers.len() as u16);
        let mut counter = 0;
        let data = self.buffer.as_mut();

        for cipher in ciphers.iter().step_by(2) {
            let subslice = &ciphers[counter..counter + 2];
            // cipher_id[0] = (cipher >> 0x8) & 0xFF;
            // cipher_id[1] = cipher & 0xFF
            data[field::HIP_CIPHER_LIST_OFFSET.start + counter..
                    field::HIP_CIPHER_LIST_OFFSET.start + counter + 2].copy_from_slice(subslice);
            counter += 2;
        }

        let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  // pad_len is computed at runtime - i.e. non constant
        let padding = [0; 8];
        let pad_offset = 4 + self.get_length() as usize;
    
        let data = self.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// This parameter contains the actual Host Identity. [RFC 7401 5.2.9]
///
/// [RFC 7401 5.2.9]: https://tools.ietf.org/html/rfc7401#section-5.2.9
pub trait HostIdParameter {
    /// Initialize Host ID parameter.
    fn init_hostidparameter_param(&mut self);
    /// Returns length of the Host Identity in 2 octets 
    fn get_hi_length(&self) -> Result<u16>;
    /// Sets length of the Host Identity with 2 octets
    fn set_hi_length(&mut self, hi: u16) -> Result<()>;
    /// Returns length of the Domain Identifier field in 2 octets
    fn get_di_length(&self) -> Result<u16>;
    /// Sets length of the Domain Identifier field with 2 octets
    fn set_di_length(&mut self, di: u16) -> Result<()>;
    /// Returns type of the Domain Identifier field - 4 bit field.
    fn get_di_type(&self) -> Result<u8>;
    /// Sets type of the following Domain Identifier field - 4 bit field
    fn set_di_type(&mut self, di_type: u8) -> Result<()>;
    /// Returns a 2 bytes field for the employed algorithm as a u16
    fn get_algorithm(&self) -> Result<u16>;
    /// Sets a 2 bytes field for the employed algorithm with a u16
    fn set_algorithm(&mut self, algorithm: u16) -> Result<()>;
    /// Returns actual Host Identity - variable len field
    fn get_host_id(&self) -> Result<&[u8]>;
    /// Sets actual Host Identity - variable len field
    fn set_host_id(&mut self, hostid: &[u8]) -> Result<()>;
    /// Returns the identifier of the sender - see RFC 7401 5.2.9
    fn get_domain_id(&self) -> Result<&[u8]>;
    /// Sets the identifier of the sender - see RFC 7401 5.2.9
    fn set_domain_id(&mut self, domainid: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HostIdParameter for HIPParameter<T> { 

    #[inline]
    fn init_hostidparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_HI_LENGTH_LENGTH  +
                         field::HIP_DI_LENGTH_LENGTH  +
                         field::HIP_ALGORITHM_LENGTH)];
        self.set_type(field::HIP_HI_TYPE as u16);
        self.set_length((field::HIP_HI_LENGTH_LENGTH +
                        field::HIP_DI_LENGTH_LENGTH +
                        field::HIP_ALGORITHM_LENGTH) as u16);
    }

    #[inline]
    fn get_hi_length(&self) -> Result<u16> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_HI_LENGTH_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_hi_length(&mut self, hi: u16) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_HI_LENGTH_OFFSET], hi))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_di_length(&self) -> Result<u16> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_DI_LENGTH_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_di_length(&mut self, di: u16) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_DI_LENGTH_OFFSET], di))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_di_type(&self) -> Result<u8> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok((data[field::HIP_DI_LENGTH_OFFSET.start] >> 4) & 0xF)
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_di_type(&mut self, di_type: u8) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(data[field::HIP_DI_LENGTH_OFFSET.start] = (di_type << 4) | data[field::HIP_DI_LENGTH_OFFSET.start])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_algorithm(&self) -> Result<u16> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_ALGORITHM_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_algorithm(&mut self, algorithm: u16) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_ALGORITHM_OFFSET], algorithm))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_host_id(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            // let mut host_id = &[0];
            let data = self.buffer.as_ref();
            if let Ok(hi_length) = self.get_hi_length() {
                if hi_length == 0 { return Err(HIPError::FieldisNOTSet);};
            }
            Ok(&data[field::HIP_HI_OFFSET.start..field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_host_id(&mut self, hi: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   

            if let Ok(hi_length) = self.get_hi_length() {
                if hi_length > 0 {return Err(HIPError::FieldisAlreadySet);};
            }
            let data = self.buffer.as_mut();
            &mut data[field::HIP_HI_OFFSET.start..field::HIP_HI_OFFSET.start + hi.len()].copy_from_slice(hi);
            self.set_hi_length(hi.len() as u16);
            // self.set_algorithm(self.get_algorithm());
            let len = self.get_length() + hi.len() as u16;
            Ok(self.set_length(len))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_domain_id(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let di_length = self.get_di_length().unwrap();
            let offset = field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize;
            Ok(&data[offset..offset + di_length as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_domain_id(&mut self, di: &[u8]) -> Result<()> {
        let di_len = di.len();
        if let Ok(hi_len) = self.get_hi_length() {
            if hi_len == 0 {return Err(HIPError::FieldisNOTSet);};
        }

        let offset = field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize;
        let data = self.buffer.as_mut();

        &mut data[offset..offset + di_len].copy_from_slice(di);
        self.set_di_length(di_len as u16);
        // self.set_di_type(di_type)
        let len = self.get_length() + di_len as u16;
        self.set_length(len);

        let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  // pad_len is computed at runtime - i.e. non constant
        let padding = [0; 8];
        let pad_offset = 4 + self.get_length() as usize;
    
        let data = self.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        
    }
}

/// The HIT_SUITE_LIST parameter contains a list of the supported HIT
/// Suite IDs of the Responder [RFC 7401 5.2.10]
///
/// [RFC 7401 5.2.10]: https://tools.ietf.org/html/rfc7401#section-5.2.10
pub trait HITSuitListParameter {
    /// Initialize HIT Suit list Paramter
    fn init_hitsuitlistparameter_param(&mut self);
    /// Returns the list of HIT Suite ID supported by the host and is ordered by preference of the host.
    fn get_suits(&self) -> Result<&[u8]>;
    /// Returns the list of HIT Suite ID supported by the host and is ordered by preference of the host.
    fn set_suits(&mut self, suits: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HITSuitListParameter for HIPParameter<T> {

    #[inline]
    fn init_hitsuitlistparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_HIT_SUITS_TYPE as u16);
        self.set_length(0);
    } 
    
    #[inline]
    fn get_suits(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_HIT_SUITS_OFFSET.start..field::HIP_HIT_SUITS_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_suits(&mut self, suits: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_HI_TYPE as u16 {   
            let len = self.get_length();
            if len > 0 {return Err(HIPError::FieldisAlreadySet);};
            self.set_length(suits.len() as u16);
            
            {
            let data = self.buffer.as_mut();
            &mut data[field::HIP_HIT_SUITS_OFFSET.start..
                field::HIP_HIT_SUITS_OFFSET.start + suits.len() as usize].copy_from_slice(suits);
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8; 
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
            
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The HIT_SUITE_LIST parameter contains a list of the supported HIT
/// Suite IDs of the Responder [RFC 7401 5.2.10]
///
/// [RFC 7401 5.2.10]: https://tools.ietf.org/html/rfc7401#section-5.2.10
pub trait TransportListParameter {
    /// Initialize Transport List Parameter
    fn init_transportlistparameter_param(&mut self);
    /// Returns the list of the supported HIP transport formats (TFs) of the Responder.
    fn get_transport_formats(&self) -> Result<&[u8]>;
    /// Sets the list of the supported HIP transport formats (TFs)
    fn set_transport_formats(&mut self, formats: &[u8]) -> Result <()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> TransportListParameter for HIPParameter<T> {

    #[inline]
    fn init_transportlistparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_TRANSPORT_FORMAT_LIST_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_transport_formats(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_TRANSPORT_FORMAT_LIST_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start..
                field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_transport_formats(&mut self, formats: &[u8]) -> Result <()> {
        let length = self.get_length();
        if length > 0 { return Err(HIPError::FieldisAlreadySet);};
        // transport formats lists are 2 byte fields 
        if (formats.len() % 2 != 0) {return Err(HIPError::Illegal);}; 
        self.set_length(formats.len() as u16);
        let mut counter = 0;
        let data = self.buffer.as_mut();

        for cipher in formats.iter().step_by(2) {
            let subslice = &formats[counter..counter + 2];
            // cipher_id[0] = (cipher >> 0x8) & 0xFF;
            // cipher_id[1] = cipher & 0xFF
            data[field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + counter..
                    field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + counter + 2].copy_from_slice(subslice);
            counter += 2;
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
        let padding = [0; 8];
        let pad_offset = 4 + self.get_length() as usize;
    
        let data = self.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// HMAC computed over the HIP packet, excluding theHIP_MAC parameter and any following parameters,
/// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED. 
/// [RFC 7401 5.2.12]
///
/// [RFC 7401 5.2.12]: https://tools.ietf.org/html/rfc7401#section-5.2.12
pub trait MACParameter {
    /// Initialize MAC parameter
    fn init_macparamter_param(&mut self);
    /// Returns HMAC computed over the HIP packet, excluding the HIP_MAC parameter and any following parameters,
    /// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED.
    fn get_hmac(&self) -> Result<&[u8]>;
    /// Sets HMAC computed over the HIP packet, excluding the HIP_MAC parameter and any following parameters,
    /// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED.
    fn set_hmac(&mut self, hmac: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> MACParameter for HIPParameter<T> {

    #[inline]
    fn init_macparamter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_MAC_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_hmac(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_MAC_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_MAC_OFFSET.start..field::HIP_MAC_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_hmac(&mut self, hmac: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_MAC_TYPE as u16 {   
            self.set_length(hmac.len() as u16);
            let length = hmac.len();

            {
            let mut data = self.buffer.as_mut();
            &mut data[field::HIP_MAC_OFFSET.start..field::HIP_MAC_OFFSET.start + length].copy_from_slice(hmac);
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))

        } else {
            Err(HIPError::Illegal)
        }
        
    }
}

/// HMAC computed over the HIP packet, excluding the HIP_MAC_2 parameter and any following parameters
/// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED,
/// and including an additional sender's HOST_ID parameter during the HMAC calculation.  [RFC 7401 5.2.13]
///
/// [RFC 7401 5.2.13]: https://tools.ietf.org/html/rfc7401#section-5.2.13
pub trait MAC2Parameter {
    /// Initialize MAC 2 parameter
    fn init_mac2paramter_param(&mut self);
    /// Returns HMAC 2 computed over the HIP packet, , excluding the HIP_MAC_2 parameter and any following parameters
    /// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED,
    /// and including an additional sender's HOST_ID parameter during the HMAC calculation.
    fn get_hmac2(&self) -> Result<&[u8]>;
    /// Sets HMAC 2 computed over the HIP packet, , excluding the HIP_MAC_2 parameter and any following parameters
    /// such as HIP_SIGNATURE, HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED,
    /// and including an additional sender's HOST_ID parameter during the HMAC calculation.
    fn set_hmac2(&mut self, hmac: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> MAC2Parameter for HIPParameter<T> {

    #[inline]
    fn init_mac2paramter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_MAC_2_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_hmac2(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_MAC_2_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_MAC_2_OFFSET.start..field::HIP_MAC_2_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_hmac2(&mut self, hmac2: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_MAC_2_TYPE as u16 {   
            self.set_length(hmac2.len() as u16);
            let length = hmac2.len();
            
            {
            let mut data = self.buffer.as_mut();
            &mut data[field::HIP_MAC_2_OFFSET.start..field::HIP_MAC_2_OFFSET.start + length].copy_from_slice(hmac2);
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))

        } else {
            Err(HIPError::Illegal)
        }
        
    }
}

/// The Signature parameter contains the signature and ID used to sign 
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
pub trait SignatureParameter {
    /// Initialize Signature parameter
    fn init_signatureparameter(&mut self);
    /// Returns the signature calculated over the HIP packet, excluding the HIP_SIGNATURE parameter and any
    /// parameters that follow the HIP_SIGNATURE parameter.
    fn get_signature(&self) -> Result<&[u8]>;
    /// Sets the signature calculated over the HIP packet, excluding the HIP_SIGNATURE parameter and any
    /// parameters that follow the HIP_SIGNATURE parameter.
    fn set_signature(&mut self, signature: &[u8]) -> Result<()>;
    /// Returns a 2 byte signature algorithm ID 
    fn get_signature_algorithm(&self) -> Result<u16>;
    /// Sets a 2 bytes signature algorithm ID
    fn set_signature_algorithm(&mut self, algorithm: u16) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SignatureParameter for HIPParameter<T> {
    #[inline]
    fn init_signatureparameter(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_SIG_ALG_TYPE_LENGTH)];
        self.set_type(field::HIP_SIG_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_signature(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_SIG_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_SIG_OFFSET.start..
                field::HIP_SIG_OFFSET.start + len as usize - field::HIP_SIG_ALG_TYPE_LENGTH])
        } else {
            Err(HIPError::Illegal)
        }   
    }

    #[inline]
    fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_SIG_TYPE as u16 {   
            self.set_length((signature.len() + field::HIP_SIG_ALG_TYPE_LENGTH) as u16);
            let length = signature.len();
            
            {
            let mut data = self.buffer.as_mut();
            &mut data[field::HIP_SIG_OFFSET.start..
                field::HIP_SIG_OFFSET.start + length].copy_from_slice(signature);
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))

        } else {
            Err(HIPError::Illegal)
        }
    }
 
    #[inline]
    fn get_signature_algorithm(&self) -> Result<u16> {
        if self.get_type() == field::HIP_SIG_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_SIG_ALG_TYPE_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }   
    }

    #[inline]
    fn set_signature_algorithm(&mut self, algorithm: u16) -> Result<()> {
        if self.get_type() == field::HIP_SIG_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_SIG_ALG_TYPE_OFFSET], algorithm))
        } else {
            Err(HIPError::Illegal)
        }
    }

}

/// The Signature parameter contains the signature and ID used to sign 
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
pub trait Signature2Parameter {
    /// Initialize Signature 2 parameter
    fn init_signature2parameter_param(&mut self);
    /// Returns the signature calculated over the HIP packet. HIP_SIGNATURE_2 excludes 
    /// the variable parameters in the R1 packet to allow R1 pre-creation.  
    /// The parameter structure is the same as the structure shown in Section 5.2.14.
    fn get_signature_2(&self) -> Result<&[u8]>;
    /// Sets the signature calculated over the HIP packet. HIP_SIGNATURE_2 excludes 
    /// the variable parameters in the R1 packet to allow R1 pre-creation.  
    /// The parameter structure is the same as the structure shown in Section 5.2.14.
    fn set_signature_2(&mut self, signature: &[u8]) -> Result<()>;
    /// Returns a 2 byte signature algorithm ID 
    fn get_signature_algorithm_2(&self) -> Result<u16>;
    /// Sets a 2 bytes signature algorithm ID
    fn set_signature_algorithm_2(&mut self, algorithm: u16) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Signature2Parameter for HIPParameter<T> {

    #[inline]
    fn init_signature2parameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_SIG_ALG_TYPE_LENGTH_2)];
        self.set_type(field::HIP_SIG_2_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_signature_2(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_SIG_2_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_SIG_OFFSET_2.start..
                field::HIP_SIG_OFFSET_2.start + len as usize - field::HIP_SIG_ALG_TYPE_LENGTH_2])
        } else {
            Err(HIPError::Illegal)
        }   
    }

    #[inline]
    fn set_signature_2(&mut self, signature: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_SIG_2_TYPE as u16 {   
            self.set_length((signature.len() + field::HIP_SIG_ALG_TYPE_LENGTH_2) as u16);
            let length = signature.len();
            
            {
            let mut data = self.buffer.as_mut();
            &mut data[field::HIP_SIG_OFFSET_2.start..
                field::HIP_SIG_OFFSET_2.start + length].copy_from_slice(signature);
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))

        } else {
            Err(HIPError::Illegal)
        }
    }
 
    #[inline]
    fn get_signature_algorithm_2(&self) -> Result<u16> {
        if self.get_type() == field::HIP_SIG_2_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_SIG_ALG_TYPE_OFFSET_2]))
        } else {
            Err(HIPError::Illegal)
        }   
    }

    #[inline]
    fn set_signature_algorithm_2(&mut self, algorithm: u16) -> Result<()> {
        if self.get_type() == field::HIP_SIG_2_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_SIG_ALG_TYPE_OFFSET_2], algorithm))
        } else {
            Err(HIPError::Illegal)
        }
    }

}

/// The Signature parameter contains the signature and ID used to sign 
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
pub trait SequenceParameter {
    /// Initialize Signature 2 parameter
    fn init_sequenceparameter_param(&mut self);
    /// Returns a 32-bit sequence number 
    fn get_seq(&self) -> Result<u32>;
    /// Sets a 32-bit sequence number
    fn set_seq(&mut self, seq: u32) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SequenceParameter for HIPParameter<T> {

    #[inline]
    fn init_sequenceparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_UPDATE_ID_LENGTH)];
        self.set_type(field::HIP_SEQ_TYPE as u16);
        self.set_length(field::HIP_UPDATE_ID_LENGTH as u16);
    }

    fn get_seq(&self) -> Result<u32> {
        if self.get_type() == field::HIP_SEQ_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u32(&data[field::HIP_UPDATE_ID_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }   
    }

    fn set_seq(&mut self, seq: u32) -> Result<()> {
        if self.get_type() == field::HIP_SEQ_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(&mut data[field::HIP_UPDATE_ID_OFFSET], seq))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ACK parameter includes one or more Update IDs that have been
/// received from the peer.  The number of peer Update IDs can be
/// inferred from the length by dividing it by 4. 
/// [RFC 7401 5.2.17.  ACK]
///
/// [RFC 7401 5.2.17.  ACK]: https://tools.ietf.org/html/rfc7401#section-5.2.17]
pub trait AckParameter {
    /// Initialize ACK parameter
    fn init_ackparameter_param(&mut self);
   /// Returns one or more Update IDs that have been received from the peer.  
   /// The number of peer Update IDs can be inferred from the length by dividing it by 4
    fn get_ackd_ids(&self) -> Result<&[u8]>;
    /// Sender sets one or more Update IDs.  
    fn set_ackd_ids(&mut self, acks: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AckParameter for HIPParameter<T> {

    #[inline]
    fn init_ackparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_ACK_TYPE as u16);
        self.set_length(0);
    }
    
    fn get_ackd_ids(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_ACK_ID_OFFSET.start..
                field::HIP_ACK_ID_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    fn set_ackd_ids(&mut self, acks: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let length = self.get_length();
            if length > 0 { return Err(HIPError::FieldisAlreadySet);};
            // updates IDs are 4 byte fields 
            if (acks.len() % 4 != 0) {return Err(HIPError::Illegal);}; 
            self.set_length(acks.len() as u16);
            let mut counter = 0;
            let data = self.buffer.as_mut();

            for cipher in acks.iter().step_by(4) {
                let subslice = &acks[counter..counter + 4];
                // cipher_id[0] = (cipher >> 0x8) & 0xFF;
                // cipher_id[1] = cipher & 0xFF
                data[field::HIP_ACK_ID_OFFSET.start + counter..
                        field::HIP_ACK_ID_OFFSET.start + counter + 4].copy_from_slice(subslice);
                counter += 4;
            }

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }

}

/// The ENCRYPTED parameter encapsulates other parameters, the encrypted
/// data, which holds one or more HIP parameters in block encrypted form
/// [RFC 7401 5.2.18.  ENCRYPTED]
///
/// [RFC 7401 5.2.18.  ENCRYPTED]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
pub trait EncryptedParameter {
    /// Initialize Encrypted parameter 
    fn init_encrypytedparameter_param(&mut self);
    /// Returns the  Initialization vector. The length of the IV is inferred from
    /// the HIP_CIPHER.
    fn get_iv(&self, iv_length: u8) -> Result<&[u8]>;
    /// Sets the Initialization vector. The length of the IV is inferred from
    /// the HIP_CIPHER
    fn set_iv(&mut self, iv: &[u8]) -> Result<()>;
    /// Returns encrypted data contained in the param. Data is encrypted using the encryption algorithm 
    /// defined in the HIP_CIPHER parameter
    fn get_encrypted_data(&self, iv_length: u8) -> Result<&[u8]>;
    /// Adds encrypted data to the param. Data is encrypted using the encryption algorithm 
    /// defined in the HIP_CIPHER parameter
    fn set_encrypted_data(&mut self, iv_length: u8, enc_data: &[u8]) ->  Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EncryptedParameter for HIPParameter<T> { 
    #[inline]
    fn init_encrypytedparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_ENCRYPTED_RESERVED_LENGTH)];
        self.set_type(field::HIP_ENCRYPTED_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_iv(&self, iv_length: u8) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ENCRYPTED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            if self.get_length() == (field::HIP_TLV_LENGTH_LENGTH + 
                                     field::HIP_TLV_TYPE_LENGTH   +
                                     field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
                 { return Err(HIPError::FieldisNOTSet);};
            let offset = field::HIP_ENCRYPTED_IV_OFFSET.start;
            Ok(&data[offset..offset + iv_length as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ENCRYPTED_TYPE as u16 {   
            if self.get_length() != (field::HIP_TLV_LENGTH_LENGTH + 
                                     field::HIP_TLV_TYPE_LENGTH   +
                                     field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
                 {return Err(HIPError::FieldisAlreadySet);};
            let data = self.buffer.as_mut();
            let offset = field::HIP_ENCRYPTED_IV_OFFSET.start;
            data[offset..offset + iv.len()].copy_from_slice(iv);
            let mut len = self.get_length();
            len += iv.len() as u16;
            Ok(self.set_length(len))
        } else {
            Err(HIPError::Illegal)
        }
    }
    
    fn get_encrypted_data(&self, iv_length: u8) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ENCRYPTED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            if self.get_length() <= (field::HIP_TLV_LENGTH_LENGTH + 
                                     field::HIP_TLV_TYPE_LENGTH   +
                                     field::HIP_ENCRYPTED_RESERVED_LENGTH + iv_length as usize) as u16
                 { return Err(HIPError::FieldisNOTSet);};
            let length = self.get_length();
            let offset = field::HIP_ENCRYPTED_IV_OFFSET.start + iv_length as usize;
            let enc_data_len = length - (field::HIP_ENCRYPTED_RESERVED_LENGTH + iv_length as usize) as u16;
            Ok(&data[offset..offset + enc_data_len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_encrypted_data(&mut self, iv_length: u8, enc_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ENCRYPTED_TYPE as u16 {   
 
            if self.get_length() == (field::HIP_TLV_LENGTH_LENGTH + 
                                     field::HIP_TLV_TYPE_LENGTH   +
                                     field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
                 {return Err(HIPError::FieldisNOTSet);};
            let data = self.buffer.as_mut();
            let offset = field::HIP_ENCRYPTED_IV_OFFSET.start + iv_length as usize;
            data[offset..offset + enc_data.len()].copy_from_slice(enc_data);
            // Some extra padding
            let extra_pad_len = 4 - enc_data.len() % 4;
            let extra_pad = [0; 4];
            data[offset + enc_data.len()..offset + enc_data.len() + 
                extra_pad_len].copy_from_slice(&extra_pad[..extra_pad_len]);

            let mut len = self.get_length();
            len += enc_data.len() as u16;
            self.set_length(len);

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + extra_pad_len + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + extra_pad_len + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))

        } else {
            Err(HIPError::Illegal)
        }
    }

}

///  The NOTIFICATION parameter is used to transmit informational data,
///  such as error conditions and state transitions, to a HIP peer.  A
///  NOTIFICATION parameter may appear in NOTIFY packets. [RFC 7401 5.2.19.  NOTIFICATION]
///
/// [RFC 7401 5.2.19.  NOTIFICATION]: https://tools.ietf.org/html/rfc7401#section-5.2.19]
pub trait NotificationParameter {
    /// Initialize Notification parameter
    fn init_notificationparameter_param(&mut self);
    /// 
    fn get_notify_message_type(&self) -> Result<u16>;
    ///
    fn set_notify_message_type(&mut self, notify_type: u16) -> Result<()>;
    ///
    fn get_notification_data(&self) -> Result<&[u8]>;
    ///
    fn set_notification_data(&mut self, notify_data: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NotificationParameter for HIPParameter<T> { 

    #[inline]
    fn init_notificationparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH)];
        self.set_type(field::HIP_NOTIFICATION_TYPE as u16);
        self.set_length((field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16);
    }

    #[inline]
    fn get_notify_message_type(&self) -> Result<u16> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_NOTIFY_MESSAGE_TYPE_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_notify_message_type(&mut self, notify_type: u16) -> Result<()> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_NOTIFY_MESSAGE_TYPE_OFFSET], notify_type))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_notification_data(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            if len == (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16 
                {return Err(HIPError::FieldisNOTSet);};
            let offset = field::HIP_NOTIFICATION_DATA_OFFSET.start;
            let data_boundary = len - (field::HIP_NOTIFICATION_RESERVED_LENGTH + 
                                           field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16;
            Ok(&data[offset..offset + data_boundary as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_notification_data(&mut self, notify_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ACK_TYPE as u16 {   
            let len = self.get_length();
            if len > (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16 
                {return Err(HIPError::FieldisAlreadySet);};
            
            let data = self.buffer.as_mut();
            let offset = field::HIP_NOTIFICATION_DATA_OFFSET.start;
            data[offset..offset + notify_data.len()].copy_from_slice(notify_data);
            // Some extra padding
            let extra_pad_len = 4 - notify_data.len() % 4;
            let extra_pad = [0; 4];
            data[offset + notify_data.len()..offset + notify_data.len() + 
                extra_pad_len].copy_from_slice(&extra_pad[..extra_pad_len]);

            let mut len = self.get_length();
            len += notify_data.len() as u16;
            self.set_length(len);

            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + extra_pad_len + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + extra_pad_len + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ECHO_REQUEST_SIGNED parameter contains an opaque blob of data
/// that the sender wants to get echoed back in the corresponding reply packet. [RFC 7401 5.2.20.  ECHO_REQUEST_SIGNED]
/// 
/// [RFC 7401 5.2.20.  ECHO_REQUEST_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.20]
pub trait EchoRequestSignedParameter {
    /// Initialize Echo Request Signed parameter
    fn init_echorequestsignedparameter(&mut self);
    /// Returns opaque data, supposed to be meaningful only to the node that sends ECHO_REQUEST_SIGNED and
    /// receives a corresponding ECHO_RESPONSE_SIGNED or ECHO_RESPONSE_UNSIGNED
    fn get_opaque_data(&self) -> Result<&[u8]>;
    /// Sets opaque data field.
    fn set_opaque_data(&mut self, data: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoRequestSignedParameter for HIPParameter<T> { 

    #[inline]
    fn init_echorequestsignedparameter(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_ECHO_REQUEST_SIGNED_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_opaque_data(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ECHO_REQUEST_SIGNED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start..
                field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque_data(&mut self, op_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ECHO_REQUEST_SIGNED_TYPE as u16 {
            {   
            let data = self.buffer.as_mut();
            data[field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start..
                field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start + op_data.len()].copy_from_slice(op_data);
            }
            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ECHO_REQUEST_UNSIGNED parameter contains an opaque blob of data
/// that the sender wants to get echoed back in the corresponding reply packet. 
/// The ECHO_REQUEST_UNSIGNED is not covered by the HIP_MAC and SIGNATURE.
/// [RFC 7401 5.2.21.  ECHO_REQUEST_UNSIGNED]
/// 
/// [RFC 7401 5.2.21.  ECHO_REQUEST_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.21]
pub trait EchoRequestUnsignedParameter {
    /// Initialize Echo Request Unsigned parameter
    fn init_echorequestunsignedparameter_param(&mut self);
    /// Returns opaque data, supposed to be meaningful only to the node that sends ECHO_REQUEST_SIGNED and
    /// receives a corresponding ECHO_RESPONSE_SIGNED or ECHO_RESPONSE_UNSIGNED
    fn get_opaque_data_ureq(&self) -> Result<&[u8]>;
    /// Sets opaque data field.
    fn set_opaque_data_ureq(&mut self, data: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoRequestUnsignedParameter for HIPParameter<T> { 

    #[inline]
    fn init_echorequestunsignedparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_ECHO_REQUEST_UNSIGNED_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_opaque_data_ureq(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ECHO_REQUEST_UNSIGNED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start..
                field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque_data_ureq(&mut self, op_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ECHO_REQUEST_UNSIGNED_TYPE as u16 {
            {   
            let data = self.buffer.as_mut();
            data[field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start..
                field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start + op_data.len()].copy_from_slice(op_data);
            }
            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ECHO_RESPONSE_SIGNED parameter contains an opaque blob of data that the sender of the ECHO_REQUEST_SIGNED 
/// wants to get echoed back. The opaque data is copied unmodified from the ECHO_REQUEST_SIGNED parameter
/// [RFC 7401 5.2.22.  ECHO_RESPONSE_SIGNED]
/// 
/// [RFC 7401 5.2.22.  ECHO_RESPONSE_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.22]
pub trait EchoResponseSignedParameter {
    /// Initialize Echo Response Signed parameter
    fn init_echoresponse_signedparameter_param(&mut self);
    /// Returns echo signed response data.
    fn get_opaque_data_sres(&self) -> Result<&[u8]>;
    /// Sets echo signed response data.
    fn set_opaque_data_sres(&mut self, data: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoResponseSignedParameter for HIPParameter<T> { 

    #[inline]
    fn init_echoresponse_signedparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_ECHO_RESPONSE_SIGNED_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_opaque_data_sres(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ECHO_RESPONSE_SIGNED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start..
                field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque_data_sres(&mut self, op_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ECHO_RESPONSE_SIGNED_TYPE as u16 {
            {   
            let data = self.buffer.as_mut();
            data[field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start..
                field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start + op_data.len()].copy_from_slice(op_data);
            }
            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ECHO_RESPONSE_UNSIGNED parameter contains an opaque blob of data that the sender of the ECHO_REQUEST_SIGNED 
/// wants to get echoed back. The opaque data is copied unmodified from the ECHO_REQUEST_SIGNED parameter
/// The ECHO_RESPONSE_UNSIGNED is not covered by the HIP_MAC and SIGNATURE.
/// [RFC 7401 5.2.23.  ECHO_RESPONSE_UNSIGNED]
/// 
/// [RFC 7401 5.2.23.  ECHO_RESPONSE_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.23]
pub trait EchoResponseUnsignedParameter {
    /// Initialize Echo Response Signed parameter
    fn init_echoresponse_unsignedparameter_param(&mut self);
    /// Returns echo signed response data.
    fn get_opaque_data_ures(&self) -> Result<&[u8]>;
    /// Sets echo signed response data.
    fn set_opaque_data_ures(&mut self, data: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoResponseUnsignedParameter for HIPParameter<T> { 

    #[inline]
    fn init_echoresponse_unsignedparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH)];
        self.set_type(field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE as u16);
        self.set_length(0);
    }

    #[inline]
    fn get_opaque_data_ures(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start..
                field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_opaque_data_ures(&mut self, op_data: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE as u16 {
            {   
            let data = self.buffer.as_mut();
            data[field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start..
                field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start + op_data.len()].copy_from_slice(op_data);
            }
            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// The ESP_TRANSFORM parameter is used during ESP SA establishment. The first party sends a selection of 
/// transform families in the ESP_TRANSFORM parameter, and the peer must select one of the proposed
/// values and include it in the response ESP_TRANSFORM parameter. [RFC 7402 5.1.2.  ESP_TRANSFORM]
///
/// [RFC 7402 5.1.2.  ESP_TRANSFORM]: https://tools.ietf.org/html/rfc7402#section-5.1.2
pub trait ESPTransformParameter {
    /// Initialize ESP Transform parameter
    fn init_esptransformparameter_param(&mut self);
    /// Returns the list of ESP Suites to be used.
    fn get_esp_suits(&self) -> Result<&[u8]>;
    /// Sets the ESP suites
    fn set_esp_suits(&mut self, suits: &[u8]) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ESPTransformParameter for HIPParameter<T> { 

    #[inline]
    fn init_esptransformparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_SUITS_RESERVED_LENGTH)];
        self.set_type(field::HIP_ESP_TRANSFORM_TYPE as u16);
        self.set_length(field::HIP_SUITS_RESERVED_LENGTH as u16);
    }

    #[inline]
    fn get_esp_suits(&self) -> Result<&[u8]> {
        if self.get_type() == field::HIP_ESP_TRANSFORM_TYPE as u16 {   
            let data = self.buffer.as_ref();
            let len = self.get_length();
            Ok(&data[field::HIP_SUITS_LIST_OFFSET.start..
                field::HIP_SUITS_LIST_OFFSET.start + len as usize])
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_esp_suits(&mut self, suits: &[u8]) -> Result<()> {
        if self.get_type() == field::HIP_ESP_TRANSFORM_TYPE as u16 {
            self.set_length(suits.len() as u16 + 1);
            let mut counter = 0;
            let data = self.buffer.as_mut();

            for suit in suits.iter().step_by(2) {
                let subslice = &suits[counter..counter + 2];
                data[field::HIP_SUITS_LIST_OFFSET.start + counter..
                        field::HIP_SUITS_LIST_OFFSET.start + counter + 2].copy_from_slice(subslice);
                counter += 2;
            }
            // pad_len is computed at runtime - i.e. non constant
            let pad_len: usize = (8 - (4 + self.get_length() as usize) % 8) % 8;  
            let padding = [0; 8];
            let pad_offset = 4 + self.get_length() as usize;
        
            let data = self.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// During the establishment and update of an ESP SA, the SPI value of
/// both hosts must be transmitted between the hosts.  In addition, hosts
/// need the index value to the KEYMAT when they are drawing keys from
/// the generated keying material.  The ESP_INFO parameter is used to
/// transmit the SPI values and the KEYMAT index information between the
/// hosts [RFC 7402 5.1.1.  ESP_INFO]
///
/// [RFC 7402 5.1.1.  ESP_INFO]: https://tools.ietf.org/html/rfc7402#section-5.1.1
pub trait ESPInfoParameter {
    /// Initialize ESP Info parameter
    fn init_espinfoparameter_param(&mut self);
    /// Returns the index to `keymat field` of ESP info parameter
    fn get_keymat_index(&self) -> Result<u16>;
    /// Sets the `keymat field` of ESP info parameter
    fn set_keymat_index(&mut self, idx: u16) -> Result<()>;
    /// Returns the old SPI value 
    fn get_old_spi(&self) -> Result<u32>;
    /// Sets the old SPI value in the ESP info parameter
    fn set_old_spi(&mut self, old_spi: u32) -> Result<()>;
    /// Returns the new SPI value 
    fn get_new_spi(&self) -> Result<u32>;
    /// Sets the new SPI value in the ESP info parameter
    fn set_new_spi(&mut self, new_spi: u32) -> Result<()>;
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ESPInfoParameter for HIPParameter<T> { 

    #[inline]
    fn init_espinfoparameter_param(&mut self) {
        let mut data = self.buffer.as_mut();
        data = &mut [0; (field::HIP_TLV_LENGTH_LENGTH + 
                         field::HIP_TLV_TYPE_LENGTH   +
                         field::HIP_ESP_INFO_RESERVED_LENGTH     +
                         field::HIP_ESP_INFO_KEYMAT_INDEX_LENGTH +
                         field::HIP_ESP_INFO_OLD_SPI_LENGTH      +
                         field::HIP_ESP_INFO_NEW_SPI_LENGTH)];
        self.set_type(field::HIP_ESP_INFO_TYPE as u16);
        self.set_length((field::HIP_ESP_INFO_RESERVED_LENGTH    +
                        field::HIP_ESP_INFO_KEYMAT_INDEX_LENGTH +
                        field::HIP_ESP_INFO_OLD_SPI_LENGTH      +
                        field::HIP_ESP_INFO_NEW_SPI_LENGTH) as u16);
    }

    #[inline]
    fn get_keymat_index(&self) -> Result<u16> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u16(&data[field::HIP_ESP_INFO_KEYMAT_INDEX_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }
    
    #[inline]
    fn set_keymat_index(&mut self, idx: u16) -> Result<()> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u16(&mut data[field::HIP_ESP_INFO_KEYMAT_INDEX_OFFSET], idx))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_old_spi(&self) -> Result<u32> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u32(&data[field::HIP_ESP_INFO_OLD_SPI_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_old_spi(&mut self, old_spi: u32) -> Result<()> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(&mut data[field::HIP_ESP_INFO_OLD_SPI_OFFSET], old_spi))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn get_new_spi(&self) -> Result<u32> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_ref();
            Ok(NetworkEndian::read_u32(&data[field::HIP_ESP_INFO_NEW_SPI_OFFSET]))
        } else {
            Err(HIPError::Illegal)
        }
    }

    #[inline]
    fn set_new_spi(&mut self, new_spi: u32) -> Result<()> {
        if self.get_type() == field::HIP_ESP_INFO_TYPE as u16 {   
            let data = self.buffer.as_mut();
            Ok(NetworkEndian::write_u32(&mut data[field::HIP_ESP_INFO_NEW_SPI_OFFSET], new_spi))
        } else {
            Err(HIPError::Illegal)
        }
    }


}