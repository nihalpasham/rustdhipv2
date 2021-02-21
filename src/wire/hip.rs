#![no_std]
#![deny(unsafe_code)]
#![allow(warnings)]

use byteorder::{ByteOrder, NetworkEndian};
use field::HIP_SOLUTION_RANDOM_I_LENGTH;
// use core::{cmp, fmt, i32, ops};
use core::convert::TryInto;

use super::constants::field;
use crate::utils::hi::{ECDSAHostId, HostIdTypes};
use crate::{HIPError, Result};

/// A trait to convert from a `Parameter<T> to a Parameter<&[u8]>`
///
/// My initial assumuption was that this could be achieved
/// with the `From` trait but it kept throwing the `conflicting impls` error.
/// So just went with my own.
///
/// Another issue - why is `Self: Sized` needed here (exactly)
pub trait FromType<Q> {
    fn fromtype(from: Q) -> Result<Self>
    where
        Self: Sized;
}
/// A read/write wrapper around a Host Identity Protocol packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct HIPPacket<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> HIPPacket<T> {
    /// Imbue a raw octet buffer with HIP packet structure.
    pub fn new_unchecked(buffer: T) -> HIPPacket<T> {
        HIPPacket { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<HIPPacket<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::Malformed)` if the header length field has a
    /// value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_header_len].
    ///
    /// [set_header_len]: #method.set_header_len
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::HIP_RECIEVERS_HIT.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let header_len = ((1 + self.get_header_length()) * 8) as usize;
            if len < header_len {
                Err(HIPError::Bufferistooshort)
            } else if header_len != 8 && header_len < field::HIP_RECIEVERS_HIT.end {
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
    pub fn get_packet_type(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::PKT_TYPE] & 0x7F
    }

    /// Return the HIP `version` field
    #[inline]
    pub fn get_version(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VERSION] >> 0x4) & 0xFF
    }

    /// Return the checksum field
    #[inline]
    pub fn get_checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::CHECKSUM.start] as u16) << 0x8) | data[field::CHECKSUM.start + 1] as u16
    }

    /// Return the `controls` field value
    #[inline]
    pub fn get_controls(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::CONTROLS.start] as u16) << 0x8) | data[field::CONTROLS.start + 1] as u16
    }

    /// Return the sender's 128-bit HIT value
    #[inline]
    pub fn get_senders_hit(&self) -> [u8; 16] {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u128(&data[field::HIP_SENDERS_HIT]).to_be_bytes()
    }

    /// Return the receiver's 128-bit HIT value
    #[inline]
    pub fn get_receivers_hit(&self) -> [u8; 16] {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u128(&data[field::HIP_RECIEVERS_HIT]).to_be_bytes()
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> HIPPacket<&'a T> {
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
    pub fn get_parameters(&self) -> Option<[HIPParamsTypes<&[u8]>; 10]> {
        let mut offset = field::HIP_RECIEVERS_HIT.end;
        let mut has_more_params = false;
        let len = self.get_header_length() * 8 + 8;
        if len > field::HIP_FIXED_HEADER_LENGTH_EXCL_8_BYTES as u8 {
            has_more_params = true;
        };
        if len != self.buffer.as_ref().len() as u8 {
            return None;
        };

        let mut idx = 0;
        let mut param_list = [HIPParamsTypes::Default; 10]; // In practice, the no: of params in a given HIP packet is < 10
        let data = self.buffer.as_ref();
        while has_more_params {
            let param_type = NetworkEndian::read_u16(&data[offset..offset + 2]);
            let param_len = NetworkEndian::read_u16(&data[offset + 2..offset + 4]);
            let total_param_len = 11 + param_len - (param_len + 3) % 8;

            let param_data = &data[offset..offset + total_param_len as usize];
            match param_type as usize {
                field::HIP_R1_COUNTER_TYPE => {
                    param_list[idx] =
                        HIPParamsTypes::R1Counter(R1CounterParam::new_checked(param_data).unwrap())
                }
                field::HIP_PUZZLE_TYPE => {
                    param_list[idx] = HIPParamsTypes::PuzzleParam(
                        PuzzleParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_SOLUTION_TYPE => {
                    param_list[idx] = HIPParamsTypes::SolutionParam(
                        SolutionParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_DH_GROUP_LIST_TYPE => {
                    param_list[idx] = HIPParamsTypes::DHGroupListParam(
                        DHGroupListParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_DH_TYPE => {
                    param_list[idx] =
                        HIPParamsTypes::DHParam(DHParameter::new_checked(param_data).unwrap())
                }
                field::HIP_CIPHER_TYPE => {
                    param_list[idx] = HIPParamsTypes::CipherParam(
                        CipherParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_ESP_TRANSFORM_TYPE => {
                    param_list[idx] = HIPParamsTypes::ESPTransformParam(
                        ESPTransformParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_ESP_INFO_TYPE => {
                    param_list[idx] = HIPParamsTypes::ESPInfoParam(
                        ESPInfoParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_HI_TYPE => {
                    param_list[idx] = HIPParamsTypes::HostIdParam(
                        HostIdParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_HIT_SUITS_TYPE => {
                    param_list[idx] = HIPParamsTypes::HITSuitListParam(
                        HITSuitListParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_TRANSPORT_FORMAT_LIST_TYPE => {
                    param_list[idx] = HIPParamsTypes::TransportListParam(
                        TransportListParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_MAC_TYPE => {
                    param_list[idx] =
                        HIPParamsTypes::MACParam(MACParameter::new_checked(param_data).unwrap())
                }
                field::HIP_MAC_2_TYPE => {
                    param_list[idx] =
                        HIPParamsTypes::MAC2Param(MAC2Parameter::new_checked(param_data).unwrap())
                }
                field::HIP_SIG_TYPE => {
                    param_list[idx] = HIPParamsTypes::SignatureParam(
                        SignatureParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_SIG_2_TYPE => {
                    param_list[idx] = HIPParamsTypes::Signature2Param(
                        Signature2Parameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_SEQ_TYPE => {
                    param_list[idx] = HIPParamsTypes::SequenceParam(SequenceParameter::new(
                        HIPParameter::new_unchecked(param_data),
                    ))
                }
                field::HIP_ACK_TYPE => {
                    param_list[idx] = HIPParamsTypes::AckParam(AckParameter::new(
                        HIPParameter::new_unchecked(param_data),
                    ))
                }
                field::HIP_ENCRYPTED_TYPE => {
                    param_list[idx] = HIPParamsTypes::EncryptedParam(EncryptedParameter::new(
                        HIPParameter::new_unchecked(param_data),
                    ))
                }
                field::HIP_NOTIFICATION_TYPE => {
                    param_list[idx] = HIPParamsTypes::NotificationParam(NotificationParameter::new(
                        HIPParameter::new_unchecked(param_data),
                    ))
                }
                field::HIP_ECHO_REQUEST_SIGNED_TYPE => {
                    param_list[idx] = HIPParamsTypes::EchoRequestSignedParam(
                        EchoRequestSignedParameter::new(HIPParameter::new_unchecked(param_data)),
                    )
                }
                field::HIP_ECHO_REQUEST_UNSIGNED_TYPE => {
                    param_list[idx] = HIPParamsTypes::EchoRequestUnsignedParam(
                        EchoRequestUnsignedParameter::new(HIPParameter::new_unchecked(param_data)),
                    )
                }
                field::HIP_ECHO_RESPONSE_SIGNED_TYPE => {
                    param_list[idx] = HIPParamsTypes::EchoResponseSignedParam(
                        EchoResponseSignedParameter::new_checked(param_data).unwrap(),
                    )
                }
                field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE => {
                    param_list[idx] = HIPParamsTypes::EchoResponseUnsignedParam(
                        EchoResponseUnsignedParameter::new_checked(param_data).unwrap(),
                    )
                }
                _ => continue,
            }
            idx += 1;
            offset += total_param_len as usize;
            if offset >= len as usize {
                has_more_params = false;
            }
        }
        Some(param_list)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HIPPacket<T> {
    /// Set the next header field.
    #[inline]
    pub fn set_next_header(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::NXT_HDR] = value
    }

    /// Set the header length field.
    #[inline]
    pub fn set_header_length(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::HDR_LEN] = value
    }

    /// Set the packet type field.
    #[inline]
    pub fn set_packet_type(&mut self, packet_type: u8) {
        let data = self.buffer.as_mut();
        data[field::PKT_TYPE] = packet_type & 0x7F;
    }

    /// Set the version length field.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        let data = self.buffer.as_mut();
        data[field::VERSION] = 0x1;
        data[field::VERSION] = (version << 4) | data[field::VERSION];
    }

    /// Set the checksum field.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        let data = self.buffer.as_mut();
        data[field::CHECKSUM.start] = ((checksum >> 8) & 0xFF) as u8;
        data[field::CHECKSUM.start + 1] = (checksum & 0xFF) as u8
    }

    /// Set the controls field.
    #[inline]
    pub fn set_controls(&mut self, controls: u16) {
        let data = self.buffer.as_mut();
        data[field::CONTROLS.start] = ((controls >> 8) & 0xFF) as u8;
        data[field::CONTROLS.start + 1] = (controls & 0xFF) as u8
    }

    /// Set the `senders HIT` field.
    #[inline]
    pub fn set_senders_hit(&mut self, hit: &[u8]) {
        let data = self.buffer.as_mut();
        data[field::HIP_SENDERS_HIT].copy_from_slice(hit);
    }

    /// Set the `receivers HIT` field.
    #[inline]
    pub fn set_receivers_hit(&mut self, hit: &[u8]) {
        let data = self.buffer.as_mut();
        data[field::HIP_RECIEVERS_HIT].copy_from_slice(hit);
    }
}

/// The HIP header values for the I1 packet:
///
///      Header:
///       - Packet Type = 1
///       - SRC HIT = Initiator's HIT
///       - DST HIT = Responder's HIT, or NULL
///
///      IP ( HIP ( DH_GROUP_LIST ) )
///
///    The I1 packet contains the fixed HIP header and the Initiator's
///    DH_GROUP_LIST.
#[derive(Debug, PartialEq, Clone)]
pub struct I1Packet<T> {
    pub packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> I1Packet<T> {
    /// Construct a new I1Packet packet struct.
    pub fn new(packet: HIPPacket<T>) -> I1Packet<T> {
        I1Packet { packet }
    }

    /// An I1 packet contains a fixed HIP header and the Initiator's
    /// DH_GROUP_LIST.
    ///
    /// RFC 7401 has 6 defined DH_GROUP_LIST(s), each of which is 1 byte in
    /// length.
    ///
    /// Using a buffer size of (40 + 40)
    #[inline]
    pub fn new_i1packet() -> Result<I1Packet<[u8; 80]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 80])?;
        fixed_hip_header.set_packet_type(field::HIP_I1_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(I1Packet::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[header_len as usize..header_len as usize + param_len].copy_from_slice(param_as_slice);
        let new_len = header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8 - 8) / 8);
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.packet.buffer
    }
}

///    The HIP header values for the R1 packet:
///
///      Header:
///       - Packet Type = 2
///       - SRC HIT = Responder's HIT
///       - DST HIT = Initiator's HIT
///
///      IP ( HIP ( [ R1_COUNTER, ] - Optional
///                 PUZZLE,
///                 DIFFIE_HELLMAN,
///                 HIP_CIPHER,
///                 HOST_ID,
///                 HIT_SUITE_LIST,
///                 DH_GROUP_LIST,
///                 [ ECHO_REQUEST_SIGNED, ] - Optional
///                 TRANSPORT_FORMAT_LIST,
///                 HIP_SIGNATURE_2 )
///                 <, ECHO_REQUEST_UNSIGNED >i) - Optional and not included in
/// signature
///
///    Valid control bits: A
#[derive(Debug, PartialEq, Clone)]
pub struct R1Packet<T> {
    pub packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> R1Packet<T> {
    /// Construct a new R1Packet packet struct.
    pub fn new(packet: HIPPacket<T>) -> R1Packet<T> {
        R1Packet { packet }
    }

    /// R1 is the packet that the responder sends, as a response to the I1
    /// packet, to the initiator. A R1 packet contains a Diffie-Hellman value, a
    /// cryptographic puzzle and the responder’s public key. The responder uses
    /// its private key to sign the packet. The cryptographic puzzle contains a
    /// random number and a difficulty
    ///
    /// In practice, R1 packets have a length of about 640 bytes + or - 16 but
    /// as we could encounter optional `ECHO_REQUEST_*` parameters in a HIP base
    /// exchange, I chose a buffer size of 1024 bytes or 128 quad words.
    pub fn new_r1packet() -> Result<R1Packet<[u8; 1024]>> {
        let mut r1packet_buffer = HIPPacket::new_checked([0; 1024])?;
        r1packet_buffer.set_packet_type(field::HIP_R1_PACKET as u8);
        r1packet_buffer.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(R1Packet::new(r1packet_buffer))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.packet.buffer
    }
}

///   The HIP header values for the I2 packet:
///
///      Header:
///       - Packet Type = 3
///       - SRC HIT = Initiator's HIT
///       - DST HIT = Responder's HIT
///
///      IP ( HIP ( [R1_COUNTER,] - Optional
///                 SOLUTION,
///                 DIFFIE_HELLMAN,
///                 HIP_CIPHER,
///                 ENCRYPTED { HOST_ID } or HOST_ID,
///                 [ ECHO_RESPONSE_SIGNED, ] - Optional
///                 TRANSPORT_FORMAT_LIST,
///                 HIP_MAC,
///                 HIP_SIGNATURE
///                 <, ECHO_RESPONSE_UNSIGNED>i ) ) - Optional and not included
/// in signature
//    Valid control bits: A
#[derive(Debug, PartialEq, Clone)]
pub struct I2Packet<T> {
    pub packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> I2Packet<T> {
    /// Construct a new I2Packet packet struct.
    pub fn new(packet: HIPPacket<T>) -> I2Packet<T> {
        I2Packet { packet }
    }

    /// I2 is the second packet from the initiator and is a response to the R1
    /// packet. An I2 packet contains a solution to the cryptographic puzzle and
    /// Diffie-Hellman values. A hashed message authentication code (HMAC) is
    /// included in the packet and is used as an additional protection against
    /// attacks. The packet is signed before the transmission.
    ///
    /// In practice, I2 packets have a length of about 640 bytes + or - 16 but
    /// as we could encounter optional `ECHO_REQUEST_*` parameters in a HIP base
    /// exchange, I chose a buffer size of 1024 bytes or 128 quad words.
    pub fn new_i2packet() -> Result<I2Packet<[u8; 1024]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 1024])?;
        fixed_hip_header.set_packet_type(field::HIP_I2_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(I2Packet::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.packet.buffer
    }
}

///   The HIP header values for the R2 packet:
///
///      Header:
///       - Packet Type = 4
///       - SRC HIT = Responder's HIT
///       - DST HIT = Initiator's HIT
///
///      IP ( HIP ( HIP_MAC_2, HIP_SIGNATURE ) )

//    Valid control bits: None
#[derive(Debug, PartialEq, Clone)]
pub struct R2Packet<T> {
    pub packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> R2Packet<T> {
    /// Construct a new R2 Packet  struct.
    pub fn new(packet: HIPPacket<T>) -> R2Packet<T> {
        R2Packet { packet }
    }

    /// R2 is the second packet from the responder and is a response to the I2
    /// packet. It contains a HMAC and a HIP_SIGNATURE. R2 is the fourth and the
    /// last packet in HIP Base Exchange. If the puzzle is solved and all
    /// parameters are correct, a HIP connection is established and data
    /// can flow between the two hosts.
    ///
    /// In practice, R2 packets have a length of about 208 bytes + or - 16 but
    /// as we could encounter optional `ECHO_REQUEST_*` parameters in a HIP base
    /// exchange, I chose a buffer size of 512 bytes or 64 quad words.
    pub fn new_r2packet() -> Result<R2Packet<[u8; 512]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 512])?;
        fixed_hip_header.set_packet_type(field::HIP_R2_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(R2Packet::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.packet.buffer
    }
}

///    The HIP header values for the UPDATE packet:
///
///      Header:
///       - Packet Type = 16
///       - SRC HIT = Sender's HIT
///       - DST HIT = Recipient's HIT
///
///      IP ( HIP ( [SEQ, ACK, ] HIP_MAC, HIP_SIGNATURE ) )
///
///    Valid control bits: None
#[derive(Debug, PartialEq, Clone)]
pub struct UpdatePacket<T> {
    packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> UpdatePacket<T> {
    /// Construct a new UpdatePacket packet struct.
    pub fn new(packet: HIPPacket<T>) -> UpdatePacket<T> {
        UpdatePacket { packet }
    }

    /// An UPDATE packet is used to send information about the HIP association
    /// to the other part. When a host changes its network location an UPDATE
    /// packet is sent to the other part containing the new IP address. If an
    /// UPDATE packet contains a SEQ parameter the responder needs to confirm
    /// the UPDATE with an ACK parameter.
    ///
    /// In practice, Update packets have a length of about 208 bytes + or - 16
    /// (i.e. HMAC and a signature) To account for this, we use a buffer size of
    /// 512 bytes or 64 quad words.
    pub fn new_update_packet(&mut self) -> Result<UpdatePacket<[u8; 512]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 512])?;
        fixed_hip_header.set_packet_type(field::HIP_UPDATE_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(UpdatePacket::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }
}

///   The HIP header values for the NOTIFY packet:
///
///      Header:
///       - Packet Type = 17
///       - SRC HIT = Sender's HIT
///       - DST HIT = Recipient's HIT, or zero if unknown
///
///      IP ( HIP (<NOTIFICATION>i, [HOST_ID, ] HIP_SIGNATURE) ) - The NOTIFY
/// packet is used to carry one   or more NOTIFICATION parameters.

//    Valid control bits: None
#[derive(Debug, PartialEq, Clone)]
pub struct NotifyPacket<T> {
    packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NotifyPacket<T> {
    /// Construct a new NotifyPacket packet struct.
    pub fn new(packet: HIPPacket<T>) -> NotifyPacket<T> {
        NotifyPacket { packet }
    }

    /// A NOTIFY packet is used to inform the other host about protocol errors
    /// and negotiation failure. A NOTIFY packet is a pure information packet.
    ///
    /// In practice, Notify packets have a length of about 208 bytes + or - 16
    /// (i.e. Notification + signature) To account for this, we use a buffer
    /// size of 512 bytes or 64 quad words.
    pub fn new_notify_packet(&mut self) -> Result<NotifyPacket<[u8; 512]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 512])?;
        fixed_hip_header.set_packet_type(field::HIP_NOTIFY_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(NotifyPacket::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct ClosePacket<T> {
    packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ClosePacket<T> {
    /// Construct a new ClosePacket packet struct.
    pub fn new(packet: HIPPacket<T>) -> ClosePacket<T> {
        ClosePacket { packet }
    }

    /// A CLOSE packet is used to terminate an existing HIP association.
    /// A CLOSE packet contains a HMAC and a HIP_SIGNATURE.
    ///
    /// In practice, Close packets have a length of about 208 bytes (i.e. HMAC +
    /// signature) + ECHO_REQUEST_SIGNED used to validate CLOSE_ACK received in
    /// response. To account for this, we use a buffer size of 512 bytes
    /// or 64 quad words.
    pub fn new_close_packet(&mut self) -> Result<ClosePacket<[u8; 512]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 512])?;
        fixed_hip_header.set_packet_type(field::HIP_CLOSE_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(ClosePacket::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }
}

///    The HIP header values for the CLOSE_ACK packet:
///
///      Header:
///       - Packet Type = 19
///       - SRC HIT = Sender's HIT
///       - DST HIT = Recipient's HIT
///
///      IP ( HIP ( ECHO_RESPONSE_SIGNED, HIP_MAC, HIP_SIGNATURE ) )
///
///    Valid control bits: None
#[derive(Debug, PartialEq, Clone)]
pub struct CloseAckPacket<T> {
    packet: HIPPacket<T>,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> CloseAckPacket<T> {
    /// Construct a new CloseAckPacket packet struct.
    pub fn new(packet: HIPPacket<T>) -> CloseAckPacket<T> {
        CloseAckPacket { packet }
    }

    /// A CLOSE_ACK packet is sent in response to a CLOSE packet and confirms
    /// the shut-down of a HIP association. A HIP_SIGNATURE is included for
    /// verifying its validity.
    ///
    /// In practice, CloseAck packets have a length of about 208 bytes (i.e.
    /// HMAC + signature) + ECHO_RESPONSE_SIGNED. To account for this, we use a
    /// buffer size of 512 bytes or 64 quad words.
    pub fn new_closeack_packet(&mut self) -> Result<CloseAckPacket<[u8; 512]>> {
        let mut fixed_hip_header = HIPPacket::new_checked([0; 512])?;
        fixed_hip_header.set_packet_type(field::HIP_CLOSE_ACK_PACKET as u8);
        fixed_hip_header.set_header_length((field::HIP_HEADER_LENGTH as u8 - 8) / 8);
        Ok(CloseAckPacket::new(fixed_hip_header))
    }

    /// A method to sequentially add HIP parameters to a HIP packet
    pub fn add_param(&mut self, param: HIPParamsTypes<&[u8]>) {
        let fixed_header_len = self.packet.get_header_length() * 8 + 8;
        let param_len = param.param_len();
        let param_as_slice = param.into_inner();
        let data = self.packet.buffer.as_mut();

        data[fixed_header_len as usize..fixed_header_len as usize + param_len]
            .copy_from_slice(param_as_slice);
        let new_len = fixed_header_len as usize + param_len;
        self.packet.set_header_length((new_len as u8) / 8);
    }
}

/// A read/write wrapper around a generic HIP parameter buffer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct HIPParameter<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> HIPParameter<T> {
    /// Imbue a raw octet buffer with the HIP Parameter packet structure.
    pub fn new_unchecked(buffer: T) -> HIPParameter<T> {
        HIPParameter { buffer }
    }

    /// Return a parameter type field for a given HIP parameter.
    #[inline]
    pub fn get_type(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::HIP_TLV_TYPE_OFFSET.start] as u16) << 0x8)
            | data[field::HIP_TLV_TYPE_OFFSET.start + 1] as u16
    }

    /// Return the value of the critical bit field ( a value of 1 indicates
    /// parameter is critical; 0 - not critical)
    #[inline]
    pub fn get_critical_bit(&self) -> u16 {
        let data = self.buffer.as_ref();
        let raw = NetworkEndian::read_u16(&data[field::HIP_TLV_CRITICAL_BIT_OFFSET]);
        raw & 0x1
    }

    /// Returns the value of parameter's length field
    #[inline]
    pub fn get_length(&self) -> u16 {
        let data = self.buffer.as_ref();
        ((data[field::HIP_TLV_LENGTH_OFFSET.start] as u16) << 0x8)
            | data[field::HIP_TLV_LENGTH_OFFSET.start + 1] as u16
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<T: AsMut<[u8]>> HIPParameter<T> {
    /// Set the parameter type field for a given HIP parameter.
    #[inline]
    fn set_type(&mut self, pkt_type: u16) {
        let data = self.buffer.as_mut();
        data[field::HIP_TLV_TYPE_OFFSET.start] = ((pkt_type >> 8) & 0xFF) as u8;
        data[field::HIP_TLV_TYPE_OFFSET.start + 1] = (pkt_type & 0xFF) as u8;
    }

    /// Sets the value of parameter's length field
    #[inline]
    fn set_length(&mut self, length: u16) {
        let data = self.buffer.as_mut();
        data[field::HIP_TLV_LENGTH_OFFSET.start] = ((length >> 8) & 0xFF) as u8;
        data[field::HIP_TLV_LENGTH_OFFSET.start + 1] = (length & 0xFF) as u8;
    }
}

/// A marker trait for all HIP parameters
pub trait ParamMarker<'a, T> {
    fn inner_ref(&self) -> &'_ T;
}
/// A read/write wrapper around a R1Counter parameter buffer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct R1CounterParam<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for R1CounterParam<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a R1CounterParam<T>> for R1CounterParam<&'a [u8]> {
    fn fromtype(from: &'a R1CounterParam<T>) -> Result<Self> {
        R1CounterParam::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> R1CounterParam<T> {
    /// Construct a new unchecked R1CounterParam packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> R1CounterParam<T> {
        R1CounterParam { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_R1_COUNTER_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_R1_COUNTER_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the counter field in an R1 parameter
    #[inline]
    pub fn get_counter(&self) -> Result<u64> {
        let data = self.buffer.buffer.as_ref();
        let counter = NetworkEndian::read_u64(&data[field::HIP_R1_COUNTER_OFFSET]);
        Ok(counter)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> R1CounterParam<T> {
    /// Initialize R1 parameter
    #[inline]
    pub fn init_r1_counter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_R1_COUNTER_RES_LEN
            + field::HIP_R1_GEN_COUNTER_LEN];
        self.buffer.set_type(field::HIP_R1_COUNTER_TYPE as u16);
        self.buffer.set_length(field::HIP_R1_COUNTER_LENGTH as u16);
    }

    /// Sets the counter field in an R1 parameter
    #[inline]
    pub fn set_counter(&mut self, value: u64) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u64(
            &mut data[field::HIP_R1_COUNTER_OFFSET],
            value,
        ))
    }
}

/// A read/write wrapper around a Puzzle parameter buffer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct PuzzleParameter<T> {
    buffer: HIPParameter<T>,
}

// impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a PuzzleParameter<T>> for
// PuzzleParameter<&'a [u8]> {     fn from(buffer: &'a PuzzleParameter<T>) ->
// Self {         PuzzleParameter::new_checked(buffer.inner_ref().as_ref()).
// unwrap()     }
// }

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a PuzzleParameter<T>> for PuzzleParameter<&'a [u8]> {
    fn fromtype(from: &'a PuzzleParameter<T>) -> Result<Self> {
        PuzzleParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> PuzzleParameter<T> {
    /// Construct a new unchecked PuzzleParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> PuzzleParameter<T> {
        PuzzleParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<PuzzleParameter<T>> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_PUZZLE_OPAQUE_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_PUZZLE_OPAQUE_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the `k` value of the puzzle parameter. #K is the number of
    /// verified bits
    #[inline]
    pub fn get_k_value(&self) -> Result<u8> {
        let data = self.buffer.buffer.as_ref();
        Ok(data[field::HIP_PUZZLE_K_OFFSET.start] & 0xFF)
    }

    /// Returns the puzzle lifetime of the puzzle parameter. puzzle lifetime
    /// 2^(value - 32) seconds
    #[inline]
    pub fn get_lifetime(&self) -> Result<u8> {
        let data = self.buffer.buffer.as_ref();
        Ok(data[field::HIP_PUZZLE_LIFETIME_OFFSET.start] & 0xFF)
    }

    /// Returns the opaque field value of the puzzle parameter i.e. data set by
    /// the Responder, indexing the puzzle.
    #[inline]
    pub fn get_opaque(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        let opaque = NetworkEndian::read_u16(&data[field::HIP_PUZZLE_OPAQUE_OFFSET]);
        Ok(opaque)
    }

    /// Returns the random number field of the puzzle parameter (of size
    /// `rhash_len bytes`).
    #[inline]
    pub fn get_random(&self, rhash_len: u8) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let random = &data[field::HIP_PUZZLE_RANDOM_I_OFFSET.start
            ..field::HIP_PUZZLE_RANDOM_I_OFFSET.start + rhash_len as usize];
        Ok(random)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> PuzzleParameter<T> {
    /// Initialize puzzle parameter
    #[inline]
    pub fn init_puzzle_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_PUZZLE_K_LENGTH
            + field::HIP_PUZZLE_LIFETIME_LENGTH
            + field::HIP_PUZZLE_OPAQUE_LENGTH];
        self.buffer.set_type(field::HIP_PUZZLE_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the `k` value of the puzzle parameter. #K is the number of verified
    /// bits
    #[inline]
    pub fn set_k_value(&mut self, k: u8) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_PUZZLE_K_OFFSET.start] = k & 0xFF)
    }

    /// Sets puzzle lifetime of the puzzle parameter. puzzle lifetime 2^(value -
    /// 32) seconds
    #[inline]
    pub fn set_lifetime(&mut self, lifetime: u8) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_PUZZLE_LIFETIME_OFFSET.start] = lifetime & 0xFF)
    }

    /// Sets the opaque field value of the puzzle parameter i.e.data set by the
    /// Responder, indexing the puzzle
    #[inline]
    pub fn set_opaque(&mut self, opaque: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_PUZZLE_OPAQUE_OFFSET],
            opaque,
        ))
    }

    /// Sets the random number field of the puzzle parameter.
    #[inline]
    pub fn set_random(&mut self, random: &[u8], len: u8) -> Result<()> {
        self.buffer.set_length(4 + len as u16);
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_PUZZLE_RANDOM_I_OFFSET.start
            ..field::HIP_PUZZLE_RANDOM_I_OFFSET.start + len as usize]
            .copy_from_slice(random))
    }
}

/// [5.2.5.  SOLUTION]: https://tools.ietf.org/html/rfc7401#section-5.2.5
/// A read/write wrapper around a R1Counter parameter buffer.
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SolutionParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for SolutionParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a SolutionParameter<T>> for SolutionParameter<&'a [u8]> {
    fn fromtype(from: &'a SolutionParameter<T>) -> Result<Self> {
        SolutionParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> SolutionParameter<T> {
    /// Construct a new unchecked SolutionParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> SolutionParameter<T> {
        SolutionParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_SOLUTION_J_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_SOLUTION_J_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the `k` value of the solution parameter. #K is the number of
    /// verified bits
    #[inline]
    pub fn get_k_value(&self) -> Result<u8> {
        let data = self.buffer.buffer.as_ref();
        Ok(data[field::HIP_SOLUTION_K_OFFSET.start] & 0xFF)
    }

    /// Returns the opaque field value of the solution parameter (copied
    /// unmodified from the received PUZZLE parameter)
    #[inline]
    pub fn get_opaque(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        let opaque = NetworkEndian::read_u16(&data[field::HIP_SOLUTION_OPAQUE_OFFSET]);
        Ok(opaque)
    }

    /// Returns the random number field of the solution parameter (of size
    /// RHASH_len bytes).
    #[inline]
    pub fn get_random(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let random =
            &data[field::HIP_SOLUTION_RANDOM_I_OFFSET.start..field::HIP_SOLUTION_RANDOM_I_LENGTH];
        Ok(random)
    }

    /// Returns puzzle solution value
    #[inline]
    pub fn get_solution(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let solution = &data[field::HIP_SOLUTION_J_OFFSET.start..field::HIP_SOLUTION_J_LENGTH];
        Ok(solution)
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SolutionParameter<T> {
    /// Initialize solution parameter
    #[inline]
    pub fn init_solution_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_SOLUTION_K_LENGTH
            + field::HIP_SOLUTION_RESERVED_LENGTH
            + field::HIP_SOLUTION_OPAQUE_LENGTH
            + field::HIP_SOLUTION_RANDOM_I_LENGTH
            + field::HIP_SOLUTION_J_LENGTH];
        self.buffer.set_type(field::HIP_SOLUTION_TYPE as u16);
        self.buffer.set_length(field::HIP_SOLUTION_LENGTH as u16);
    }

    /// Sets the `k` value of the solution parameter. #K is the number of
    /// verified bits
    #[inline]
    pub fn set_k_value(&mut self, k: u8) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_SOLUTION_K_OFFSET.start] = k & 0xFF)
    }

    /// Sets the opaque field value of the solution parameter (copied unmodified
    /// from the received PUZZLE parameter)
    #[inline]
    pub fn set_opaque(&mut self, opaque: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_SOLUTION_OPAQUE_OFFSET],
            opaque,
        ))
    }

    /// Sets the random number field of the solution parameter.
    #[inline]
    pub fn set_random(&mut self, random: &[u8]) -> Result<()> {
        let len = random.len();
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_SOLUTION_RANDOM_I_OFFSET.start
            ..field::HIP_SOLUTION_RANDOM_I_OFFSET.start + len]
            .copy_from_slice(random))
    }

    /// Set puzzle solution value
    #[inline]
    pub fn set_solution(&mut self, solution: &[u8]) -> Result<()> {
        let len = solution.len();
        let data = self.buffer.buffer.as_mut();
        Ok(
            data[field::HIP_SOLUTION_J_OFFSET.start..field::HIP_SOLUTION_J_OFFSET.start + len]
                .copy_from_slice(solution),
        )
    }
}

/// DH_GROUP_LIST parameter contains the list of supported DH Group
/// IDs of a host. See [RFC 7401 5.2.6]
// /// [RFC 7401 5.2.6]: https://tools.ietf.org/html/rfc7401#section-5.2.6
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct DHGroupListParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a DHGroupListParameter<T>>
    for DHGroupListParameter<&'a [u8]>
{
    fn fromtype(from: &'a DHGroupListParameter<T>) -> Result<Self> {
        DHGroupListParameter::new_checked(from.inner_ref().as_ref())
    }
}

// DHGroupListParameter is a Variable length parameter
impl<T: AsRef<[u8]>> DHGroupListParameter<T> {
    /// Construct a new unchecked DHGroupListParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> DHGroupListParameter<T> {
        DHGroupListParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_DH_GROUP_LIST_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_DH_GROUP_LIST_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns a list of groups as a slice of u8's
    #[inline]
    pub fn get_groups(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let length = self.buffer.get_length();
        Ok(&data[field::HIP_DH_GROUP_LIST_OFFSET.start
            ..field::HIP_DH_GROUP_LIST_OFFSET.start + length as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DHGroupListParameter<T> {
    /// Initialize DH groups list parameter
    #[inline]
    pub fn init_dhgrouplist_param(&mut self) {
        let mut _data = self.buffer.buffer.as_mut();
        _data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_DH_GROUP_LIST_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the `groups list`, given a slice of u8's
    #[inline]
    pub fn set_groups(&mut self, groups: &[u8]) -> Result<()> {
        let groups_len = groups.len();
        self.buffer.set_length(groups_len as u16);
        {
            let data = self.buffer.buffer.as_mut();
            // let bytes = NetworkEndian::read_uint(groups, groups.len());
            // NetworkEndian::write_uint(&mut data[4..4 + groups_len], bytes, groups_len);
            data[field::HIP_DH_GROUP_LIST_OFFSET.start
                ..field::HIP_DH_GROUP_LIST_OFFSET.start + groups_len]
                .copy_from_slice(groups);
        }
        let pad_len: usize = (8 - (4 + groups_len) % 8) % 8; // pad_len is computed at runtime - i.e. a non-constant
        let padding = [0; 8]; // max padding is 8 bytes
        let pad_offset = 4 + groups_len;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// A single DIFFIE_HELLMAN parameter may be included in selected HIP
/// packets based on the DH Group ID selected (Section 5.2.6) - [RFC 7401 5.2.7]
///
/// [RFC 7401 5.2.7]: https://tools.ietf.org/html/rfc7401#section-5.2.7
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct DHParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for DHParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a DHParameter<T>> for DHParameter<&'a [u8]> {
    fn fromtype(from: &'a DHParameter<T>) -> Result<Self> {
        DHParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> DHParameter<T> {
    /// Construct a new unchecked DHParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> DHParameter<T> {
        DHParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the DH GROUP ID. This ID is used to ientify values for p and g
    /// as well as the KDF
    #[inline]
    pub fn get_group_id(&self) -> Result<u8> {
        let data = self.buffer.buffer.as_ref();
        Ok(data[field::HIP_DH_GROUP_ID_OFFSET.start] & 0xFF)
    }

    /// Returns the length of the Public Value field in octets
    #[inline]
    pub fn get_public_value_length(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(
            ((data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.start] as u16) << 0x8)
                | (data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET.start + 1] as u16),
        )
    }

    /// Returns the contents of the public value field i.e. sender's public
    /// Diffie-Hellman key
    #[inline]
    pub fn get_public_value(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        if let Ok(public_value_length) = self.get_public_value_length() {
            Ok(&data[field::HIP_PUBLIC_VALUE_OFFSET.start
                ..field::HIP_PUBLIC_VALUE_OFFSET.start + public_value_length as usize])
        } else {
            Err(HIPError::__Nonexhaustive) // This should probably be unreachable
        }
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> DHParameter<T> {
    /// Initialize `DH Parameter` parameter
    #[inline]
    pub fn init_dhparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_GROUP_ID_LENGTH
            + field::HIP_PUBLIC_VALUE_LENGTH_LENGTH];
        self.buffer.set_type(field::HIP_DH_TYPE as u16);
        self.buffer.set_length(
            (field::HIP_GROUP_ID_LENGTH + field::HIP_PUBLIC_VALUE_LENGTH_LENGTH) as u16,
        );
    }

    /// Sets the GROUP ID. This ID is used to identify values for p and g as
    /// well as the KDF
    #[inline]
    pub fn set_group_id(&mut self, group_id: u8) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_DH_GROUP_ID_OFFSET.start] = group_id)
    }

    /// Sets the length of the Public Value field in octets
    #[inline]
    pub fn set_public_value_length(&mut self, pub_len: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_PUBLIC_VALUE_LENGTH_OFFSET],
            pub_len,
        ))
    }

    /// Sets the public value field i.e. sender's public Diffie-Hellman key.
    #[inline]
    pub fn set_public_value(&mut self, pub_val: &[u8]) -> Result<()> {
        if let Ok(public_value_length) = self.get_public_value_length() {
            if public_value_length != 0x0 {
                return Err(HIPError::Illegal);
            };
            let mut len = self.buffer.get_length();
            len += pub_val.len() as u16;
            self.buffer.set_length(len);
            self.set_public_value_length(len as u16)?;
            {
                let data = self.buffer.buffer.as_mut();
                data[field::HIP_PUBLIC_VALUE_OFFSET.start
                    ..field::HIP_PUBLIC_VALUE_OFFSET.start + len as usize]
                    .copy_from_slice(pub_val);
            }
            let pad_len: usize = (8 - (4 + len as usize) % 8) % 8; // pad_len is computed at runtime - i.e. non constant
            let padding = [0; 8];
            let pad_offset = 4 + len as usize;

            let data = self.buffer.buffer.as_mut();
            Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
        } else {
            Err(HIPError::Illegal)
        }
    }
}

/// This parameter identifies the cipher algorithm to be used for
/// encrypting the contents of the ENCRYPTED parameter [RFC 7401 5.2.8]
///
/// [RFC 7401 5.2.8]: https://tools.ietf.org/html/rfc7401#section-5.2.8
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct CipherParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for CipherParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a CipherParameter<T>> for CipherParameter<&'a [u8]> {
    fn fromtype(from: &'a CipherParameter<T>) -> Result<Self> {
        CipherParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> CipherParameter<T> {
    /// Construct a new unchecked CipherParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> CipherParameter<T> {
        CipherParameter { buffer }
    }
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_CIPHER_LIST_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_CIPHER_LIST_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the list of ciphers IDs. Ciphers IDs identify the cipher
    /// algorithm to be used for encrypting the contents of the ENCRYPTED
    /// parameter
    #[inline]
    pub fn get_ciphers(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let length = self.buffer.get_length();
        Ok(&data[field::HIP_CIPHER_LIST_OFFSET.start
            ..field::HIP_CIPHER_LIST_OFFSET.start + length as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> CipherParameter<T> {
    /// Intialize `Cipher Parameter` parameter
    #[inline]
    pub fn init_cipherparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_CIPHER_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Returns the list of ciphers IDs. Ciphers IDs identify the cipher
    /// algorithm to be used for encrypting the contents of the ENCRYPTED
    /// parameter
    #[inline]
    pub fn set_ciphers(&mut self, ciphers: &[u8]) -> Result<()> {
        let length = self.buffer.get_length();
        if length > 0 {
            return Err(HIPError::FieldisAlreadySet);
        };
        // cipher ids are 2 byte fields and a HIP_CIPHER parameter MUST make sure that
        // there are no more than six (6) Cipher IDs in one HIP_CIPHER parameter. RFC
        // 7401 - 5.2.8
        if (ciphers.len() % 2 != 0) && (ciphers.len() <= 12) {
            return Err(HIPError::Illegal);
        };
        self.buffer.set_length(ciphers.len() as u16);
        let mut counter = 0;
        let data = self.buffer.buffer.as_mut();

        for _cipher in ciphers.iter().step_by(2) {
            let subslice = &ciphers[counter..counter + 2];
            // cipher_id[0] = (cipher >> 0x8) & 0xFF;
            // cipher_id[1] = cipher & 0xFF
            data[field::HIP_CIPHER_LIST_OFFSET.start + counter
                ..field::HIP_CIPHER_LIST_OFFSET.start + counter + 2]
                .copy_from_slice(subslice);
            counter += 2;
        }

        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8; // pad_len is computed at runtime - i.e. non constant
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// This parameter contains the actual Host Identity. [RFC 7401 5.2.9]
///
/// [RFC 7401 5.2.9]: https://tools.ietf.org/html/rfc7401#section-5.2.9
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct HostIdParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for HostIdParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a HostIdParameter<T>> for HostIdParameter<&'a [u8]> {
    fn fromtype(from: &'a HostIdParameter<T>) -> Result<Self> {
        HostIdParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> HostIdParameter<T> {
    /// Construct a new unchecked HostIdParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> HostIdParameter<T> {
        HostIdParameter { buffer }
    }
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_ALGORITHM_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_ALGORITHM_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns length of the Host Identity in 2 octets
    #[inline]
    pub fn get_hi_length(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(&data[field::HIP_HI_LENGTH_OFFSET]))
    }

    /// Returns length of the Domain Identifier field in 2 octets
    #[inline]
    pub fn get_di_length(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(&data[field::HIP_DI_LENGTH_OFFSET]))
    }

    /// Returns type of the Domain Identifier field - 4 bit field.
    #[inline]
    pub fn get_di_type(&self) -> Result<u8> {
        let data = self.buffer.buffer.as_ref();
        Ok((data[field::HIP_DI_LENGTH_OFFSET.start] >> 4) & 0xF)
    }

    /// Returns a 2 bytes field for the employed algorithm as a u16
    #[inline]
    pub fn get_algorithm(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(&data[field::HIP_ALGORITHM_OFFSET]))
    }

    /// Returns actual Host Identity - variable len field
    #[inline]
    pub fn get_host_id(&self) -> Result<&[u8]> {
        // let mut host_id = &[0];
        let data = self.buffer.buffer.as_ref();
        if let Ok(hi_length) = self.get_hi_length() {
            if hi_length == 0 {
                return Err(HIPError::FieldisNOTSet);
            };
        }
        Ok(&data[field::HIP_HI_OFFSET.start
            ..field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize])
    }

    /// Returns the domain identifier of the sender - see RFC 7401 5.2.9
    #[inline]
    pub fn get_domain_id(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let di_length = self.get_di_length().unwrap();
        let offset = field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize;
        Ok(&data[offset..offset + di_length as usize])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> HostIdParameter<T> {
    /// Initialize Host ID parameter.
    #[inline]
    pub fn init_hostidparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_HI_LENGTH_LENGTH
            + field::HIP_DI_LENGTH_LENGTH
            + field::HIP_ALGORITHM_LENGTH];
        self.buffer.set_type(field::HIP_HI_TYPE as u16);
        self.buffer.set_length(
            (field::HIP_HI_LENGTH_LENGTH
                + field::HIP_DI_LENGTH_LENGTH
                + field::HIP_ALGORITHM_LENGTH) as u16,
        );
    }

    /// Sets length of the Host Identity with 2 octets
    #[inline]
    pub fn set_hi_length(&mut self, hi: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_HI_LENGTH_OFFSET],
            hi,
        ))
    }

    /// Sets length of the Domain Identifier field with 2 octets
    #[inline]
    pub fn set_di_length(&mut self, di: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_DI_LENGTH_OFFSET],
            di,
        ))
    }

    /// Sets type of the following Domain Identifier field - 4 bit field.
    /// Only call this method after setting the DI length i.e. `set_di_length()`
    #[inline]
    pub fn set_di_type(&mut self, di_type: u8) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(data[field::HIP_DI_LENGTH_OFFSET.start] =
            (di_type << 4) | data[field::HIP_DI_LENGTH_OFFSET.start])
    }

    /// Sets a 2 bytes field for the employed algorithm with a u16
    #[inline]
    pub fn set_algorithm(&mut self, algorithm: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_ALGORITHM_OFFSET],
            algorithm,
        ))
    }

    /// Sets actual Host Identity - variable len field
    #[inline]
    pub fn set_host_id(&mut self, hi: &[u8], alg: &HostIdTypes) -> Result<()> {
        if let Ok(hi_length) = self.get_hi_length() {
            if hi_length > 0 {
                return Err(HIPError::FieldisAlreadySet);
            };
        }
        let data = self.buffer.buffer.as_mut();
        &mut data[field::HIP_HI_OFFSET.start..field::HIP_HI_OFFSET.start + hi.len()]
            .copy_from_slice(hi);
        self.set_hi_length(hi.len() as u16)?;
        self.set_algorithm(ECDSAHostId::get_algorithm(alg) as u16);
        let len = self.buffer.get_length() + hi.len() as u16;
        Ok(self.buffer.set_length(len))
    }

    /// Sets the identifier of the sender - see RFC 7401 5.2.9
    #[inline]
    pub fn set_domain_id(&mut self, di: &[u8]) -> Result<()> {
        let di_len = di.len();
        if let Ok(hi_len) = self.get_hi_length() {
            if hi_len == 0 {
                return Err(HIPError::FieldisNOTSet);
            };
        }

        let offset = field::HIP_HI_OFFSET.start + self.get_hi_length().unwrap() as usize;
        let data = self.buffer.buffer.as_mut();

        &mut data[offset..offset + di_len].copy_from_slice(di);
        self.set_di_length(di_len as u16)?;
        self.set_di_type(0x2); // for now, we're only using network access identifiers - so only 0x2 is valid.
        let len = self.buffer.get_length() + di_len as u16;
        self.buffer.set_length(len);

        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8; // pad_len is computed at runtime - i.e. non constant
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The HIT_SUITE_LIST parameter contains a list of the supported HIT
/// Suite IDs of the Responder [RFC 7401 5.2.10]
///
/// [RFC 7401 5.2.10]: https://tools.ietf.org/html/rfc7401#section-5.2.10
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct HITSuitListParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a HITSuitListParameter<T>>
    for HITSuitListParameter<&'a [u8]>
{
    fn fromtype(from: &'a HITSuitListParameter<T>) -> Result<Self> {
        HITSuitListParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> HITSuitListParameter<T> {
    /// Construct a new unchecked HITSuitListParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> HITSuitListParameter<T> {
        HITSuitListParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_HIT_SUITS_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_HIT_SUITS_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the list of HIT Suite ID supported by the host and is ordered by
    /// preference of the host.
    #[inline]
    pub fn get_suits(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data
            [field::HIP_HIT_SUITS_OFFSET.start..field::HIP_HIT_SUITS_OFFSET.start + len as usize])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> HITSuitListParameter<T> {
    /// Initialize HIT Suit list Paramter
    #[inline]
    pub fn init_hitsuitlistparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_HIT_SUITS_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Returns the list of HIT Suite ID supported by the host and is ordered by
    /// preference of the host.
    #[inline]
    pub fn set_suits(&mut self, suits: &[u8]) -> Result<()> {
        let len = self.buffer.get_length();
        if len > 0 {
            return Err(HIPError::FieldisAlreadySet);
        };
        self.buffer.set_length(suits.len() as u16);

        {
            let data = self.buffer.buffer.as_mut();
            &mut data[field::HIP_HIT_SUITS_OFFSET.start
                ..field::HIP_HIT_SUITS_OFFSET.start + suits.len() as usize]
                .copy_from_slice(suits);
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The HIT_SUITE_LIST parameter contains a list of the supported HIT
/// Suite IDs of the Responder [RFC 7401 5.2.10]
///
/// [RFC 7401 5.2.10]: https://tools.ietf.org/html/rfc7401#section-5.2.10
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct TransportListParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for TransportListParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a TransportListParameter<T>>
    for TransportListParameter<&'a [u8]>
{
    fn fromtype(from: &'a TransportListParameter<T>) -> Result<Self> {
        TransportListParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> TransportListParameter<T> {
    /// Construct a new unchecked TransportListParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> TransportListParameter<T> {
        TransportListParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the list of the supported HIP transport formats (TFs) of the
    /// Responder.
    #[inline]
    pub fn get_transport_formats(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start
            ..field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + len as usize])
    }
}

impl<T: AsMut<[u8]> + AsRef<[u8]>> TransportListParameter<T> {
    /// Initialize Transport List Parameter
    #[inline]
    pub fn init_transportlistparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer
            .set_type(field::HIP_TRANSPORT_FORMAT_LIST_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the list of the supported HIP transport formats (TFs)
    #[inline]
    pub fn set_transport_formats(&mut self, formats: &[u8]) -> Result<()> {
        let length = self.buffer.get_length();
        if length > 0 {
            return Err(HIPError::FieldisAlreadySet);
        };
        // transport formats lists are 2 byte fields
        if formats.len() % 2 != 0 {
            return Err(HIPError::Illegal);
        };
        self.buffer.set_length(formats.len() as u16);
        let mut counter = 0;
        let data = self.buffer.buffer.as_mut();

        for _cipher in formats.iter().step_by(2) {
            let subslice = &formats[counter..counter + 2];
            data[field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + counter
                ..field::HIP_TRANSPORT_FORMAT_LIST_OFFSET.start + counter + 2]
                .copy_from_slice(subslice);
            counter += 2;
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// HMAC computed over the HIP packet, excluding theHIP_MAC parameter and any
/// following parameters, such as HIP_SIGNATURE, HIP_SIGNATURE_2,
/// ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED. [RFC 7401 5.2.12]
///
/// [RFC 7401 5.2.12]: https://tools.ietf.org/html/rfc7401#section-5.2.12
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct MACParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for MACParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a MACParameter<T>> for MACParameter<&'a [u8]> {
    fn fromtype(from: &'a MACParameter<T>) -> Result<Self> {
        MACParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> MACParameter<T> {
    /// Construct a new unchecked MACParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> MACParameter<T> {
        MACParameter { buffer }
    }
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_MAC_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_MAC_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }
    /// Returns HMAC computed over the HIP packet, excluding the HIP_MAC
    /// parameter and any following parameters, such as HIP_SIGNATURE,
    /// HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED.
    #[inline]
    pub fn get_hmac(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_MAC_OFFSET.start..field::HIP_MAC_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> MACParameter<T> {
    /// Initialize MAC parameter
    #[inline]
    pub fn init_macparamter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_MAC_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets HMAC computed over the HIP packet, excluding the HIP_MAC parameter
    /// and any following parameters, such as HIP_SIGNATURE, HIP_SIGNATURE_2,
    /// ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED.
    #[inline]
    pub fn set_hmac(&mut self, hmac: &[u8]) -> Result<()> {
        self.buffer.set_length(hmac.len() as u16);
        let length = hmac.len();

        {
            let data = self.buffer.buffer.as_mut();
            &mut data[field::HIP_MAC_OFFSET.start..field::HIP_MAC_OFFSET.start + length]
                .copy_from_slice(hmac);
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// HMAC computed over the HIP packet, excluding the HIP_MAC_2 parameter and any
/// following parameters such as HIP_SIGNATURE, HIP_SIGNATURE_2,
/// ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED, and including an
/// additional sender's HOST_ID parameter during the HMAC calculation.  [RFC
/// 7401 5.2.13]
///
/// [RFC 7401 5.2.13]: https://tools.ietf.org/html/rfc7401#section-5.2.13
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct MAC2Parameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for MAC2Parameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a MAC2Parameter<T>> for MAC2Parameter<&'a [u8]> {
    fn fromtype(from: &'a MAC2Parameter<T>) -> Result<Self> {
        MAC2Parameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> MAC2Parameter<T> {
    /// Construct a new unchecked MAC2Parameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> MAC2Parameter<T> {
        MAC2Parameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_MAC_2_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_MAC_2_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns HMAC 2 computed over the HIP packet, , excluding the HIP_MAC_2
    /// parameter and any following parameters such as HIP_SIGNATURE,
    /// HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED,
    #[inline]
    pub fn get_hmac2(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_MAC_2_OFFSET.start..field::HIP_MAC_2_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> MAC2Parameter<T> {
    /// Initialize MAC 2 parameter
    #[inline]
    pub fn init_mac2paramter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_MAC_2_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets HMAC 2 computed over the HIP packet, , excluding the HIP_MAC_2
    /// parameter and any following parameters such as HIP_SIGNATURE,
    /// HIP_SIGNATURE_2, ECHO_REQUEST_UNSIGNED, or ECHO_RESPONSE_UNSIGNED,
    /// and including an additional sender's HOST_ID parameter during the HMAC
    /// calculation.
    #[inline]
    pub fn set_hmac2(&mut self, hmac2: &[u8]) -> Result<()> {
        self.buffer.set_length(hmac2.len() as u16);
        let length = hmac2.len();

        {
            let data = self.buffer.buffer.as_mut();
            &mut data[field::HIP_MAC_2_OFFSET.start..field::HIP_MAC_2_OFFSET.start + length]
                .copy_from_slice(hmac2);
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The Signature parameter contains the signature and ID used to sign
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SignatureParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a SignatureParameter<T>> for SignatureParameter<&'a [u8]> {
    fn fromtype(from: &'a SignatureParameter<T>) -> Result<Self> {
        SignatureParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> SignatureParameter<T> {
    /// Construct a new unchecked SignatureParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> SignatureParameter<T> {
        SignatureParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_SIG_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_SIG_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the signature calculated over the HIP packet, excluding the
    /// HIP_SIGNATURE parameter and any parameters that follow the HIP_SIGNATURE
    /// parameter.
    #[inline]
    pub fn get_signature(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_SIG_OFFSET.start
            ..field::HIP_SIG_OFFSET.start + len as usize - field::HIP_SIG_ALG_TYPE_LENGTH])
    }

    /// Returns a 2 byte signature algorithm ID
    #[inline]
    pub fn get_signature_algorithm(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(
            &data[field::HIP_SIG_ALG_TYPE_OFFSET],
        ))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SignatureParameter<T> {
    /// Initialize Signature parameter
    #[inline]
    pub fn init_signatureparameter(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_SIG_ALG_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_SIG_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the signature calculated over the HIP packet, excluding the
    /// HIP_SIGNATURE parameter and any parameters that follow the HIP_SIGNATURE
    /// parameter.
    #[inline]
    pub fn set_signature(&mut self, signature: &[u8]) -> Result<()> {
        self.buffer
            .set_length((signature.len() + field::HIP_SIG_ALG_TYPE_LENGTH) as u16);
        let length = signature.len();

        {
            let data = self.buffer.buffer.as_mut();
            &mut data[field::HIP_SIG_OFFSET.start..field::HIP_SIG_OFFSET.start + length]
                .copy_from_slice(signature);
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }

    /// Sets a 2 bytes signature algorithm ID
    #[inline]
    pub fn set_signature_algorithm(&mut self, algorithm: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_SIG_ALG_TYPE_OFFSET],
            algorithm,
        ))
    }
}

/// The Signature parameter contains the signature and ID used to sign
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Signature2Parameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for Signature2Parameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a Signature2Parameter<T>>
    for Signature2Parameter<&'a [u8]>
{
    fn fromtype(from: &'a Signature2Parameter<T>) -> Result<Self> {
        Signature2Parameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> Signature2Parameter<T> {
    /// Construct a new unchecked Signature2Parameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> Signature2Parameter<T> {
        Signature2Parameter { buffer }
    }
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_SIG_OFFSET_2.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_SIG_OFFSET_2.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the signature calculated over the HIP packet. HIP_SIGNATURE_2
    /// excludes the variable parameters in the R1 packet to allow R1
    /// pre-creation. The parameter structure is the same as the structure shown
    /// in Section 5.2.14.
    #[inline]
    pub fn get_signature_2(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_SIG_OFFSET_2.start
            ..field::HIP_SIG_OFFSET_2.start + len as usize - field::HIP_SIG_ALG_TYPE_LENGTH_2])
    }

    /// Returns a 2 byte signature algorithm ID
    #[inline]
    pub fn get_signature_algorithm_2(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(
            &data[field::HIP_SIG_ALG_TYPE_OFFSET_2],
        ))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Signature2Parameter<T> {
    /// Initialize Signature 2 parameter
    #[inline]
    pub fn init_signature2parameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_SIG_ALG_TYPE_LENGTH_2];
        self.buffer.set_type(field::HIP_SIG_2_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the signature calculated over the HIP packet. HIP_SIGNATURE_2
    /// excludes the variable parameters in the R1 packet to allow R1
    /// pre-creation. The parameter structure is the same as the structure shown
    /// in Section 5.2.14.
    pub fn set_signature_2(&mut self, signature: &[u8]) -> Result<()> {
        self.buffer
            .set_length((signature.len() + field::HIP_SIG_ALG_TYPE_LENGTH_2) as u16);
        let length = signature.len();

        {
            let data = self.buffer.buffer.as_mut();
            &mut data[field::HIP_SIG_OFFSET_2.start..field::HIP_SIG_OFFSET_2.start + length]
                .copy_from_slice(signature);
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }

    /// Sets a 2 bytes signature algorithm ID
    #[inline]
    pub fn set_signature_algorithm_2(&mut self, algorithm: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_SIG_ALG_TYPE_OFFSET_2],
            algorithm,
        ))
    }
}

/// The Signature parameter contains the signature and ID used to sign
/// [RFC 7401 5.2.14]
///
/// [RFC 7401 5.2.14]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct SequenceParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T: AsRef<[u8]>> SequenceParameter<T> {
    /// Construct a new unchecked SequenceParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> SequenceParameter<T> {
        SequenceParameter { buffer }
    }

    /// Returns a 32-bit sequence number
    #[inline]
    pub fn get_seq(&self) -> Result<u32> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u32(&data[field::HIP_UPDATE_ID_OFFSET]))
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> SequenceParameter<T> {
    /// Initialize Signature 2 parameter
    #[inline]
    pub fn init_sequenceparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_UPDATE_ID_LENGTH];
        self.buffer.set_type(field::HIP_SEQ_TYPE as u16);
        self.buffer.set_length(field::HIP_UPDATE_ID_LENGTH as u16);
    }

    /// Sets a 32-bit sequence number
    #[inline]
    pub fn set_seq(&mut self, seq: u32) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u32(
            &mut data[field::HIP_UPDATE_ID_OFFSET],
            seq,
        ))
    }
}

/// The ACK parameter includes one or more Update IDs that have been
/// received from the peer.  The number of peer Update IDs can be
/// inferred from the length by dividing it by 4.
/// [RFC 7401 5.2.17.  ACK]
///
/// [RFC 7401 5.2.17.  ACK]: https://tools.ietf.org/html/rfc7401#section-5.2.17]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct AckParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T> AckParameter<T> {
    /// Construct a new unchecked AckParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> AckParameter<T> {
        AckParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> AckParameter<T> {
    /// Returns one or more Update IDs that have been received from the peer.  
    /// The number of peer Update IDs can be inferred from the length by
    /// dividing it by 4
    pub fn get_ackd_ids(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_ACK_ID_OFFSET.start..field::HIP_ACK_ID_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AckParameter<T> {
    /// Initialize ACK parameter
    #[inline]
    pub fn init_ackparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_ACK_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sender sets one or more Update IDs
    pub fn set_ackd_ids(&mut self, acks: &[u8]) -> Result<()> {
        let length = self.buffer.get_length();
        if length > 0 {
            return Err(HIPError::FieldisAlreadySet);
        };
        // updates IDs are 4 byte fields
        if acks.len() % 4 != 0 {
            return Err(HIPError::Illegal);
        };
        self.buffer.set_length(acks.len() as u16);
        let mut counter = 0;
        let data = self.buffer.buffer.as_mut();

        for _cipher in acks.iter().step_by(4) {
            let subslice = &acks[counter..counter + 4];
            data[field::HIP_ACK_ID_OFFSET.start + counter
                ..field::HIP_ACK_ID_OFFSET.start + counter + 4]
                .copy_from_slice(subslice);
            counter += 4;
        }

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ENCRYPTED parameter encapsulates other parameters, the encrypted
/// data, which holds one or more HIP parameters in block encrypted form
/// [RFC 7401 5.2.18.  ENCRYPTED]
///
/// [RFC 7401 5.2.18.  ENCRYPTED]: https://tools.ietf.org/html/rfc7401#section-5.2.14]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EncryptedParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T> EncryptedParameter<T> {
    /// Construct a new unchecked EncryptedParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> EncryptedParameter<T> {
        EncryptedParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> EncryptedParameter<T> {
    /// Returns the  Initialization vector. The length of the IV is inferred
    /// from the HIP_CIPHER.
    #[inline]
    pub fn get_iv(&self, iv_length: u8) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        if self.buffer.get_length()
            == (field::HIP_TLV_LENGTH_LENGTH
                + field::HIP_TLV_TYPE_LENGTH
                + field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
        {
            return Err(HIPError::FieldisNOTSet);
        };
        let offset = field::HIP_ENCRYPTED_IV_OFFSET.start;
        Ok(&data[offset..offset + iv_length as usize])
    }

    /// Returns encrypted data contained in the param. Data is encrypted using
    /// the encryption algorithm defined in the HIP_CIPHER parameter
    #[inline]
    pub fn get_encrypted_data(&self, iv_length: u8) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        if self.buffer.get_length()
            <= (field::HIP_TLV_LENGTH_LENGTH
                + field::HIP_TLV_TYPE_LENGTH
                + field::HIP_ENCRYPTED_RESERVED_LENGTH
                + iv_length as usize) as u16
        {
            return Err(HIPError::FieldisNOTSet);
        };
        let length = self.buffer.get_length();
        let offset = field::HIP_ENCRYPTED_IV_OFFSET.start + iv_length as usize;
        let enc_data_len =
            length - (field::HIP_ENCRYPTED_RESERVED_LENGTH + iv_length as usize) as u16;
        Ok(&data[offset..offset + enc_data_len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EncryptedParameter<T> {
    /// Initialize Encrypted parameter
    #[inline]
    pub fn init_encrypytedparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_ENCRYPTED_RESERVED_LENGTH];
        self.buffer.set_type(field::HIP_ENCRYPTED_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the Initialization vector. The length of the IV is inferred from
    /// the HIP_CIPHER
    #[inline]
    pub fn set_iv(&mut self, iv: &[u8]) -> Result<()> {
        if self.buffer.get_length()
            != (field::HIP_TLV_LENGTH_LENGTH
                + field::HIP_TLV_TYPE_LENGTH
                + field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
        {
            return Err(HIPError::FieldisAlreadySet);
        };
        let data = self.buffer.buffer.as_mut();
        let offset = field::HIP_ENCRYPTED_IV_OFFSET.start;
        data[offset..offset + iv.len()].copy_from_slice(iv);
        let mut len = self.buffer.get_length();
        len += iv.len() as u16;
        Ok(self.buffer.set_length(len))
    }

    /// Adds encrypted data to the param. Data is encrypted using the encryption
    /// algorithm defined in the HIP_CIPHER parameter
    #[inline]
    pub fn set_encrypted_data(&mut self, iv_length: u8, enc_data: &[u8]) -> Result<()> {
        if self.buffer.get_length()
            == (field::HIP_TLV_LENGTH_LENGTH
                + field::HIP_TLV_TYPE_LENGTH
                + field::HIP_ENCRYPTED_RESERVED_LENGTH) as u16
        {
            return Err(HIPError::FieldisNOTSet);
        };
        let data = self.buffer.buffer.as_mut();
        let offset = field::HIP_ENCRYPTED_IV_OFFSET.start + iv_length as usize;
        data[offset..offset + enc_data.len()].copy_from_slice(enc_data);
        // Some extra padding
        let extra_pad_len = 4 - enc_data.len() % 4;
        let extra_pad = [0; 4];
        data[offset + enc_data.len()..offset + enc_data.len() + extra_pad_len]
            .copy_from_slice(&extra_pad[..extra_pad_len]);

        let mut len = self.buffer.get_length();
        len += enc_data.len() as u16;
        self.buffer.set_length(len);

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + extra_pad_len + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + extra_pad_len + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

///  The NOTIFICATION parameter is used to transmit informational data,
///  such as error conditions and state transitions, to a HIP peer.  A
///  NOTIFICATION parameter may appear in NOTIFY packets. [RFC 7401 5.2.19.
/// NOTIFICATION]
///
/// [RFC 7401 5.2.19.  NOTIFICATION]: https://tools.ietf.org/html/rfc7401#section-5.2.19]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct NotificationParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T> NotificationParameter<T> {
    /// Construct a new unchecked NotificationParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> NotificationParameter<T> {
        NotificationParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> NotificationParameter<T> {
    ///
    #[inline]
    pub fn get_notify_message_type(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(
            &data[field::HIP_NOTIFY_MESSAGE_TYPE_OFFSET],
        ))
    }

    ///
    #[inline]
    pub fn get_notification_data(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        if len
            == (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16
        {
            return Err(HIPError::FieldisNOTSet);
        };
        let offset = field::HIP_NOTIFICATION_DATA_OFFSET.start;
        let data_boundary = len
            - (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16;
        Ok(&data[offset..offset + data_boundary as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> NotificationParameter<T> {
    /// Initialize Notification parameter
    #[inline]
    pub fn init_notificationparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_NOTIFICATION_RESERVED_LENGTH
            + field::HIP_NOTIFY_DATA_TYPE_LENGTH];
        self.buffer.set_type(field::HIP_NOTIFICATION_TYPE as u16);
        self.buffer.set_length(
            (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16,
        );
    }

    ///
    #[inline]
    pub fn set_notify_message_type(&mut self, notify_type: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_NOTIFY_MESSAGE_TYPE_OFFSET],
            notify_type,
        ))
    }

    ///
    #[inline]
    pub fn set_notification_data(&mut self, notify_data: &[u8]) -> Result<()> {
        let len = self.buffer.get_length();
        if len
            > (field::HIP_NOTIFICATION_RESERVED_LENGTH + field::HIP_NOTIFY_DATA_TYPE_LENGTH) as u16
        {
            return Err(HIPError::FieldisAlreadySet);
        };

        let data = self.buffer.buffer.as_mut();
        let offset = field::HIP_NOTIFICATION_DATA_OFFSET.start;
        data[offset..offset + notify_data.len()].copy_from_slice(notify_data);
        // Some extra padding
        let extra_pad_len = 4 - notify_data.len() % 4;
        let extra_pad = [0; 4];
        data[offset + notify_data.len()..offset + notify_data.len() + extra_pad_len]
            .copy_from_slice(&extra_pad[..extra_pad_len]);

        let mut len = self.buffer.get_length();
        len += notify_data.len() as u16;
        self.buffer.set_length(len);

        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + extra_pad_len + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + extra_pad_len + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ECHO_REQUEST_SIGNED parameter contains an opaque blob of data
/// that the sender wants to get echoed back in the corresponding reply packet.
/// [RFC 7401 5.2.20.  ECHO_REQUEST_SIGNED]
///
/// [RFC 7401 5.2.20.  ECHO_REQUEST_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.20]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EchoRequestSignedParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T> EchoRequestSignedParameter<T> {
    /// Construct a new unchecked EchoRequestSignedParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> EchoRequestSignedParameter<T> {
        EchoRequestSignedParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> EchoRequestSignedParameter<T> {
    /// Returns opaque data, supposed to be meaningful only to the node that
    /// sends ECHO_REQUEST_SIGNED and receives a corresponding
    /// ECHO_RESPONSE_SIGNED or ECHO_RESPONSE_UNSIGNED
    #[inline]
    pub fn get_opaque_data(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start
            ..field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoRequestSignedParameter<T> {
    /// Initialize Echo Request Signed parameter
    #[inline]
    pub fn init_echorequestsignedparameter(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer
            .set_type(field::HIP_ECHO_REQUEST_SIGNED_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets opaque data field.
    #[inline]
    pub fn set_opaque_data(&mut self, op_data: &[u8]) -> Result<()> {
        {
            let data = self.buffer.buffer.as_mut();
            data[field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start
                ..field::HIP_ECHO_REQUEST_SIGNED_OFFSET.start + op_data.len()]
                .copy_from_slice(op_data);
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ECHO_REQUEST_UNSIGNED parameter contains an opaque blob of data
/// that the sender wants to get echoed back in the corresponding reply packet.
/// The ECHO_REQUEST_UNSIGNED is not covered by the HIP_MAC and SIGNATURE.
/// [RFC 7401 5.2.21.  ECHO_REQUEST_UNSIGNED]
///
/// [RFC 7401 5.2.21.  ECHO_REQUEST_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.21]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EchoRequestUnsignedParameter<T> {
    buffer: HIPParameter<T>,
}

impl<T> EchoRequestUnsignedParameter<T> {
    /// Construct a new unchecked EchoRequestUnsignedParameter packet structure.
    #[inline]
    pub fn new(buffer: HIPParameter<T>) -> EchoRequestUnsignedParameter<T> {
        EchoRequestUnsignedParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> EchoRequestUnsignedParameter<T> {
    /// Returns opaque data, supposed to be meaningful only to the node that
    /// sends ECHO_REQUEST_SIGNED and receives a corresponding
    /// ECHO_RESPONSE_SIGNED or ECHO_RESPONSE_UNSIGNED
    #[inline]
    pub fn get_opaque_data(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start
            ..field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoRequestUnsignedParameter<T> {
    /// Initialize Echo Request Unsigned parameter
    #[inline]
    pub fn init_echorequestunsignedparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer
            .set_type(field::HIP_ECHO_REQUEST_UNSIGNED_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets opaque data field.
    #[inline]
    pub fn set_opaque_data(&mut self, op_data: &[u8]) -> Result<()> {
        {
            let data = self.buffer.buffer.as_mut();
            data[field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start
                ..field::HIP_ECHO_REQUEST_UNSIGNED_OFFSET.start + op_data.len()]
                .copy_from_slice(op_data);
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ECHO_RESPONSE_SIGNED parameter contains an opaque blob of data that the
/// sender of the ECHO_REQUEST_SIGNED wants to get echoed back. The opaque data
/// is copied unmodified from the ECHO_REQUEST_SIGNED parameter [RFC 7401 5.2.
/// 22.  ECHO_RESPONSE_SIGNED]
///
/// [RFC 7401 5.2.22.  ECHO_RESPONSE_SIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.22]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EchoResponseSignedParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a EchoResponseSignedParameter<T>>
    for EchoResponseSignedParameter<&'a [u8]>
{
    fn fromtype(from: &'a EchoResponseSignedParameter<T>) -> Result<Self> {
        EchoResponseSignedParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T> EchoResponseSignedParameter<T> {
    /// Construct a new unchecked EchoResponseSignedParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> EchoResponseSignedParameter<T> {
        EchoResponseSignedParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> EchoResponseSignedParameter<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns echo signed response data.
    #[inline]
    pub fn get_opaque_data(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start
            ..field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoResponseSignedParameter<T> {
    /// Initialize Echo Response Signed parameter
    #[inline]
    pub fn init_echoresponse_signed_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer
            .set_type(field::HIP_ECHO_RESPONSE_SIGNED_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets echo signed response data.
    #[inline]
    pub fn set_opaque_data(&mut self, op_data: &[u8]) -> Result<()> {
        let len = op_data.len();
        {
            let data = self.buffer.buffer.as_mut();
            data[field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start
                ..field::HIP_ECHO_RESPONSE_SIGNED_OFFSET.start + op_data.len()]
                .copy_from_slice(op_data);
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;
        self.buffer.set_length((len + pad_len) as u16);

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ECHO_RESPONSE_UNSIGNED parameter contains an opaque blob of data that
/// the sender of the ECHO_REQUEST_SIGNED wants to get echoed back. The opaque
/// data is copied unmodified from the ECHO_REQUEST_SIGNED parameter
/// The ECHO_RESPONSE_UNSIGNED is not covered by the HIP_MAC and SIGNATURE.
/// [RFC 7401 5.2.23.  ECHO_RESPONSE_UNSIGNED]
///
/// [RFC 7401 5.2.23.  ECHO_RESPONSE_UNSIGNED]: https://tools.ietf.org/html/rfc7401#section-5.2.23]
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct EchoResponseUnsignedParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a EchoResponseUnsignedParameter<T>>
    for EchoResponseUnsignedParameter<&'a [u8]>
{
    fn fromtype(from: &'a EchoResponseUnsignedParameter<T>) -> Result<Self> {
        EchoResponseUnsignedParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T> EchoResponseUnsignedParameter<T> {
    /// Construct a new unchecked EchoResponseUnsignedParameter packet
    /// structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> EchoResponseUnsignedParameter<T> {
        EchoResponseUnsignedParameter { buffer }
    }
}

impl<T: AsRef<[u8]>> EchoResponseUnsignedParameter<T> {
    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns echo signed response data
    #[inline]
    pub fn get_opaque_data(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data[field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start
            ..field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start + len as usize])
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> EchoResponseUnsignedParameter<T> {
    /// Initialize Echo Response Signed parameter
    #[inline]
    pub fn init_echoresponse_unsigned_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH + field::HIP_TLV_TYPE_LENGTH];
        self.buffer
            .set_type(field::HIP_ECHO_RESPONSE_UNSIGNED_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets echo signed response data.
    #[inline]
    pub fn set_opaque_data(&mut self, op_data: &[u8]) -> Result<()> {
        let len = op_data.len();
        {
            let data = self.buffer.buffer.as_mut();
            data[field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start
                ..field::HIP_ECHO_RESPONSE_UNSIGNED_OFFSET.start + op_data.len()]
                .copy_from_slice(op_data);
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;
        self.buffer.set_length((len + pad_len) as u16);

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
    }
}

/// The ESP_TRANSFORM parameter is used during ESP SA establishment. The first
/// party sends a selection of transform families in the ESP_TRANSFORM
/// parameter, and the peer must select one of the proposed values and include
/// it in the response ESP_TRANSFORM parameter. [RFC 7402 5.1.2.  ESP_TRANSFORM]
///
/// [RFC 7402 5.1.2.  ESP_TRANSFORM]: https://tools.ietf.org/html/rfc7402#section-5.1.2
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ESPTransformParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for ESPTransformParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a ESPTransformParameter<T>>
    for ESPTransformParameter<&'a [u8]>
{
    fn fromtype(from: &'a ESPTransformParameter<T>) -> Result<Self> {
        ESPTransformParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T: AsRef<[u8]>> ESPTransformParameter<T> {
    /// Construct a new unchecked ESPTransformParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> ESPTransformParameter<T> {
        ESPTransformParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<ESPTransformParameter<T>> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_SUITS_LIST_OFFSET.start {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_SUITS_LIST_OFFSET.start {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the list of ESP Suites to be used.
    #[inline]
    pub fn get_esp_suits(&self) -> Result<&[u8]> {
        let data = self.buffer.buffer.as_ref();
        let len = self.buffer.get_length();
        Ok(&data
            [field::HIP_SUITS_LIST_OFFSET.start..field::HIP_SUITS_LIST_OFFSET.start + len as usize])
    }
}
impl<T: AsRef<[u8]> + AsMut<[u8]>> ESPTransformParameter<T> {
    /// Initialize ESP Transform parameter
    #[inline]
    pub fn init_esptransformparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_SUITS_RESERVED_LENGTH];
        self.buffer.set_type(field::HIP_ESP_TRANSFORM_TYPE as u16);
        self.buffer.set_length(0);
    }

    /// Sets the ESP suites
    #[inline]
    pub fn set_esp_suits(&mut self, suits: &[u8]) -> Result<()> {
        self.buffer
            .set_length(suits.len() as u16 + field::HIP_SUITS_RESERVED_LENGTH as u16);
        let mut counter = 0;
        let data = self.buffer.buffer.as_mut();

        for _suit in suits.iter().step_by(2) {
            let subslice = &suits[counter..counter + 2];
            data[field::HIP_SUITS_LIST_OFFSET.start + counter
                ..field::HIP_SUITS_LIST_OFFSET.start + counter + 2]
                .copy_from_slice(subslice);
            counter += 2;
        }
        // pad_len is computed at runtime - i.e. non constant
        let pad_len: usize = (8 - (4 + self.buffer.get_length() as usize) % 8) % 8;
        let padding = [0; 8];
        let pad_offset = 4 + self.buffer.get_length() as usize;

        let data = self.buffer.buffer.as_mut();
        Ok(data[pad_offset..pad_offset + pad_len].copy_from_slice(&padding[..pad_len]))
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
#[derive(Debug, PartialEq, Clone, Copy)]
pub struct ESPInfoParameter<T> {
    buffer: HIPParameter<T>,
}

impl<'a, T: 'a + AsRef<[u8]>> ParamMarker<'a, T> for ESPInfoParameter<T> {
    fn inner_ref(&self) -> &'_ T {
        &self.buffer.buffer
    }
}

impl<'a, T: 'a + AsRef<[u8]>> FromType<&'a ESPInfoParameter<T>> for ESPInfoParameter<&'a [u8]> {
    fn fromtype(from: &'a ESPInfoParameter<T>) -> Result<Self> {
        ESPInfoParameter::new_checked(from.inner_ref().as_ref())
    }
}

impl<T> ESPInfoParameter<T> {}

impl<T: AsRef<[u8]>> ESPInfoParameter<T> {
    /// Construct a new unchecked ESPInfoParameter packet structure.
    #[inline]
    pub fn new_unchecked(buffer: HIPParameter<T>) -> ESPInfoParameter<T> {
        ESPInfoParameter { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Self> {
        let packet = Self::new_unchecked(HIPParameter::new_unchecked(buffer));
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    /// Returns `Err(HIPError::Bufferistooshort)` if the buffer is too short.
    /// Returns `Err(HIPError::IncorrectHeaderLength)` if the header length
    /// field has a value smaller than the minimal header length.
    ///
    /// The result of this check is invalidated by calling [set_length].
    ///
    /// [set_length]: #method.set_length
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.buffer.as_ref().len();
        if len < field::HIP_ESP_INFO_NEW_SPI_OFFSET.end {
            Err(HIPError::Bufferistooshort)
        } else {
            let param_len =
                (11 + self.buffer.get_length() - ((self.buffer.get_length() + 3) % 8)) as usize;
            if len < param_len {
                Err(HIPError::Bufferistooshort)
            } else if param_len < field::HIP_ESP_INFO_NEW_SPI_OFFSET.end {
                Err(HIPError::IncorrectHeaderLength)
            } else {
                Ok(())
            }
        }
    }

    /// Returns a ref to the underlying buffer.
    pub fn inner_ref(&self) -> &T {
        &self.buffer.buffer
    }

    /// Returns the index to `keymat field` of ESP info parameter
    #[inline]
    pub fn get_keymat_index(&self) -> Result<u16> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u16(
            &data[field::HIP_ESP_INFO_KEYMAT_INDEX_OFFSET],
        ))
    }

    /// Returns the old SPI value
    #[inline]
    pub fn get_old_spi(&self) -> Result<u32> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u32(
            &data[field::HIP_ESP_INFO_OLD_SPI_OFFSET],
        ))
    }

    /// Returns the new SPI value
    #[inline]
    pub fn get_new_spi(&self) -> Result<u32> {
        let data = self.buffer.buffer.as_ref();
        Ok(NetworkEndian::read_u32(
            &data[field::HIP_ESP_INFO_NEW_SPI_OFFSET],
        ))
    }
}

impl<T: AsMut<[u8]>> ESPInfoParameter<T> {
    /// Initialize ESP Info parameter
    #[inline]
    pub fn init_espinfoparameter_param(&mut self) {
        let mut data = self.buffer.buffer.as_mut();
        data = &mut [0; field::HIP_TLV_LENGTH_LENGTH
            + field::HIP_TLV_TYPE_LENGTH
            + field::HIP_ESP_INFO_RESERVED_LENGTH
            + field::HIP_ESP_INFO_KEYMAT_INDEX_LENGTH
            + field::HIP_ESP_INFO_OLD_SPI_LENGTH
            + field::HIP_ESP_INFO_NEW_SPI_LENGTH];
        self.buffer.set_type(field::HIP_ESP_INFO_TYPE as u16);
        self.buffer.set_length(
            (field::HIP_ESP_INFO_RESERVED_LENGTH
                + field::HIP_ESP_INFO_KEYMAT_INDEX_LENGTH
                + field::HIP_ESP_INFO_OLD_SPI_LENGTH
                + field::HIP_ESP_INFO_NEW_SPI_LENGTH) as u16,
        );
    }

    /// Sets the `keymat field` of ESP info parameter
    #[inline]
    pub fn set_keymat_index(&mut self, idx: u16) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u16(
            &mut data[field::HIP_ESP_INFO_KEYMAT_INDEX_OFFSET],
            idx,
        ))
    }

    /// Sets the old SPI value in the ESP info parameter
    #[inline]
    pub fn set_old_spi(&mut self, old_spi: u32) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u32(
            &mut data[field::HIP_ESP_INFO_OLD_SPI_OFFSET],
            old_spi,
        ))
    }

    /// Sets the new SPI value in the ESP info parameter
    #[inline]
    pub fn set_new_spi(&mut self, new_spi: u32) -> Result<()> {
        let data = self.buffer.buffer.as_mut();
        Ok(NetworkEndian::write_u32(
            &mut data[field::HIP_ESP_INFO_NEW_SPI_OFFSET],
            new_spi,
        ))
    }
}
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum HIPParamsTypes<T: AsRef<[u8]>> {
    R1Counter(R1CounterParam<T>),
    PuzzleParam(PuzzleParameter<T>),
    SolutionParam(SolutionParameter<T>),
    DHGroupListParam(DHGroupListParameter<T>),
    DHParam(DHParameter<T>),
    CipherParam(CipherParameter<T>),
    HostIdParam(HostIdParameter<T>),
    HITSuitListParam(HITSuitListParameter<T>),
    TransportListParam(TransportListParameter<T>),
    MACParam(MACParameter<T>),
    MAC2Param(MAC2Parameter<T>),
    SignatureParam(SignatureParameter<T>),
    Signature2Param(Signature2Parameter<T>),
    SequenceParam(SequenceParameter<T>),
    AckParam(AckParameter<T>),
    EncryptedParam(EncryptedParameter<T>),
    NotificationParam(NotificationParameter<T>),
    EchoRequestSignedParam(EchoRequestSignedParameter<T>),
    EchoRequestUnsignedParam(EchoRequestUnsignedParameter<T>),
    EchoResponseSignedParam(EchoResponseSignedParameter<T>),
    EchoResponseUnsignedParam(EchoResponseUnsignedParameter<T>),
    ESPTransformParam(ESPTransformParameter<T>),
    ESPInfoParam(ESPInfoParameter<T>),
    Default,
}

// impl Copy for HIPParamsTypes<&[u8]>{}

impl<'a> HIPParamsTypes<&'a [u8]> {
    pub fn param_len(&self) -> usize {
        match &self {
            &HIPParamsTypes::R1Counter(s) => 4 + s.buffer.get_length() as usize,
            &HIPParamsTypes::PuzzleParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::SolutionParam(s) => 4 + s.buffer.get_length() as usize,
            &HIPParamsTypes::DHGroupListParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::DHParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::CipherParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::HostIdParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::HITSuitListParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::TransportListParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::MACParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::MAC2Param(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::SignatureParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::Signature2Param(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::SequenceParam(s) => 4 + s.buffer.get_length() as usize,
            &HIPParamsTypes::AckParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::EncryptedParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::NotificationParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::EchoRequestSignedParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::EchoRequestUnsignedParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::EchoResponseSignedParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::EchoResponseUnsignedParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::ESPTransformParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::ESPInfoParam(s) => {
                (11 + s.buffer.get_length() - ((s.buffer.get_length() + 3) % 8)) as usize
            }
            &HIPParamsTypes::Default => 0,
        }
    }

    pub fn into_inner(self) -> &'a [u8] {
        match self {
            HIPParamsTypes::R1Counter(s) => s.buffer.into_inner(),
            HIPParamsTypes::PuzzleParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::SolutionParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::DHGroupListParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::DHParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::CipherParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::HostIdParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::HITSuitListParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::TransportListParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::MACParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::MAC2Param(s) => s.buffer.into_inner(),
            HIPParamsTypes::SignatureParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::Signature2Param(s) => s.buffer.into_inner(),
            HIPParamsTypes::SequenceParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::AckParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::EncryptedParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::NotificationParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::EchoRequestSignedParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::EchoRequestUnsignedParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::EchoResponseSignedParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::EchoResponseUnsignedParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::ESPTransformParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::ESPInfoParam(s) => s.buffer.into_inner(),
            HIPParamsTypes::Default => &[],
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    /// R1Counter is a `fixed length parameter`.
    fn test_r1counter_param() -> Result<()> {
        let mut buffer = [1; 16];
        let mut r1counter_param = R1CounterParam::new_checked(&mut buffer)?;
        r1counter_param.init_r1_counter_param();
        match r1counter_param.set_counter(5618237362871) {
            Ok(s) => s,
            Err(e) => panic!("Error: {:?}", e),
        };
        assert_eq!(Ok(5618237362871), r1counter_param.get_counter());
        assert_eq!(
            &[0, 129, 0, 12, 1, 1, 1, 1, 0, 0, 5, 28, 25, 10, 210, 183],
            r1counter_param.buffer.buffer
        );
        assert_eq!(129, r1counter_param.buffer.get_type());
        assert_eq!(12, r1counter_param.buffer.get_length());
        Ok(())
    }

    #[test]
    /// Cipher Parameter packet - set, get ciphers test. Cipher Parameter is a
    /// `variable length` parameter
    fn test_cipher_param() -> Result<()> {
        let mut buffer = [1; 16];
        let cipher_ids = [0, 4, 0, 2, 0, 6];
        let mut cipherparam =
            CipherParameter::new_unchecked(HIPParameter::new_unchecked(&mut buffer));
        cipherparam.init_cipherparameter_param();
        match cipherparam.set_ciphers(&cipher_ids) {
            Ok(s) => s,
            Err(e) => panic!("Error: {:?}", e),
        }
        let pad_len = (8 - (4 + cipherparam.buffer.get_length() as usize) % 8) % 8;

        assert_eq!(Ok(&cipher_ids[..]), cipherparam.get_ciphers());
        assert_eq!(
            &[2, 67, 0, 6, 0, 4, 0, 2, 0, 6, 0, 0, 0, 0, 0, 0],
            cipherparam.buffer.buffer
        );
        assert_eq!(0x243, cipherparam.buffer.get_type());
        assert_eq!(6, cipherparam.buffer.get_length());
        assert_eq!(
            cipherparam.buffer.buffer[(4 + cipherparam.buffer.get_length()) as usize..].len(),
            pad_len
        );
        Ok(())
    }

    #[test]
    ///  Test to see, if we can access with just a reference
    fn test_cipher_param_ref() -> Result<()> {
        let buf = [2, 67, 0, 6, 0, 4, 0, 2, 0, 6, 0, 0, 0, 0, 0, 0];
        let cipherparam = CipherParameter::new_unchecked(HIPParameter::new_unchecked(&buf));
        assert_eq!(Ok(&[0, 4, 0, 2, 0, 6][..]), cipherparam.get_ciphers());
        Ok(())
    }
}
