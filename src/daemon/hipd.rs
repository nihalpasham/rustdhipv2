#![allow(warnings)]

use core::convert::TryInto;

use crate::storage::SecurityAssociations::{
    SAData, SARecordStore, SecurityAssociationDatabase, SecurityAssociationRecord,
};
use crate::{storage::HIPState::*, utils::puzzles};

use crate::crypto::{digest::*, ecdh::*, factory::*, signatures::*};
use crate::time::*;
use crate::utils::{hi::*, hit::*, misc::*, puzzles::*};
use crate::wire::constants::field::*;
use crate::wire::hip::*;
use crate::{HIPError, Result};

use elliptic_curve::{pkcs8, sec1::EncodedPoint as EncodedPointP384};
use generic_array::GenericArray;
use heapless::{consts::*, Vec};

// use smoltcp::time::{Duration, Instant};
use smoltcp::socket::{RawSocket, SocketRef};
use smoltcp::wire::{IpProtocol, Ipv4Address, Ipv4Packet, Ipv6Address, Ipv6Packet};

pub fn option_as_ref<'a, Q: 'a + ParamMarker<'a, T>, T: 'a + AsRef<[u8]>>(
    val: Option<&'a Q>,
) -> Result<&'a [u8]> {
    Ok(val
        .ok_or_else(|| HIPError::FieldNotSet)?
        .inner_ref()
        .as_ref())
}
///
pub struct HIPDaemon<'a> {
    pubkey: Option<&'a [u8]>,
    privkey: Option<&'a [u8]>,
    hi: HostIdTypes,
    hit_as_hexstring: Option<&'a str>,
    hit_as_bytes: [u8; 16],
    hip_state_machine: StateMachine<'a>,
    keymat_map: Storage<'a, [u8; 800]>,
    dh_map: Storage<'a, InitiatorDHKeys>,
    cipher_map: Storage<'a, Option<u8>>,
    pubkey_map: Storage<'a, ResponderPubKey>,
    state_vars_map: Storage<'a, StateVariables>,
    key_info_map: Storage<'a, KeyInfo>,
    sa_map: SecurityAssociationDatabase<'a>,
    selected_esp_transform: Option<u8>,
}

impl<'a> HIPDaemon<'a> {
    /// Construct a new HIP Daemon.
    pub fn new(
        pubkey: Option<&'a [u8]>,
        privkey: Option<&'a [u8]>,
        hi: HostIdTypes,
        hit_as_hexstring: Option<&'a str>,
        hit_as_bytes: [u8; 16],
        state_store: &'a mut StateStore,
        keymat_store: &'a mut GenericValueStore<[u8; 800]>,
        dh_map: &'a mut GenericValueStore<InitiatorDHKeys>,
        cipher_map: &'a mut GenericValueStore<Option<u8>>,
        pubkey_map: &'a mut GenericValueStore<ResponderPubKey>,
        state_vars_map: &'a mut GenericValueStore<StateVariables>,
        key_info_map: &'a mut GenericValueStore<KeyInfo>,
        sa_map: &'a mut SARecordStore,
    ) -> Self {
        HIPDaemon {
            pubkey,
            privkey,
            hi,
            hit_as_hexstring,
            hit_as_bytes,
            hip_state_machine: StateMachine::new(state_store),
            keymat_map: Storage::new(keymat_store),
            dh_map: Storage::new(dh_map),
            cipher_map: Storage::new(cipher_map),
            pubkey_map: Storage::new(pubkey_map),
            state_vars_map: Storage::new(state_vars_map),
            key_info_map: Storage::new(key_info_map),
            sa_map: SecurityAssociationDatabase::new(sa_map),
            selected_esp_transform: None,
        }
    }

    /// A method to process individual HIP packets `(I1, R1, I2, R2, UPDATE,
    /// NOTIFY, CLOSE)`
    ///
    /// For now, this method is a pretty huge monolith. Must see if we can split
    /// it into smaller chunks to improve readability.
    pub fn process_hip_packet(&mut self, mut hip_socket: SocketRef<RawSocket>) -> Result<()> {
        let ipv4_packet = hip_socket
            .recv()
            .and_then(Ipv4Packet::new_checked)
            .map_err(|_| HIPError::Bufferistooshort)?;
        let mut src = ipv4_packet.src_addr();
        let mut dst = ipv4_packet.dst_addr();

        // Sequence of checks
        // Check to see if the ipv4 packet's protocol header is correctly set to HIP
        // protocol identifier.
        let protocol = if let IpProtocol::Unknown(val) = ipv4_packet.protocol() {
            val
        } else {
            return Err(HIPError::Unrecognized);
        };

        if protocol as usize != HIP_PROTOCOL {
            hip_debug!("Invalid protocol type {:?}", protocol);
        }

        // All HIP packets are a multiple of 8 bytes.
        if ipv4_packet.payload().len() % 8 != 0 {
            hip_debug!("Invalid payload. HIP payload (i.e. packet) must be a multiple of 8 bytes");
        }

        let hip_packet = HIPPacket::new_checked(ipv4_packet.payload())?;
        let ihit = hip_packet.get_senders_hit();
        let rhit = hip_packet.get_receivers_hit();
        let mut hip_state = None;

        // Get the key from the `hip_state_machine` and if it doesn't exist, add one.
        if Utils::is_hit_smaller(&ihit, &rhit) {
            self.hip_state_machine
                .get(&rhit, &ihit)?
                .and_then(|state| Some(hip_state = Some(*state)));
        } else {
            self.hip_state_machine
                .get(&ihit, &rhit)?
                .and_then(|state| Some(hip_state = Some(*state)));
        }
        if hip_packet.get_version() as usize != HIP_VERSION {
            hip_trace!("Only HIP version 2 is supported");
        }

        // Check if the `responders HIT` is our hit or if its a null HIT.
        if !Utils::hits_equal(&rhit, &self.hit_as_bytes) && !Utils::hits_equal(&rhit, &[0; 16]) {
            hip_debug!("Not our HIT");
            hip_debug!(
                "rhit: {:?}",
                Utils::hex_formatted_hit_bytes(None, Some(&rhit))
                    .unwrap()
                    .as_str()
            );
            hip_debug!(
                "own_hit: {:?}",
                Utils::hex_formatted_hit_bytes(Some(&self.hit_as_bytes), None)
                    .unwrap()
                    .as_str()
            );
        }

        let original_checksum = hip_packet.get_checksum();

        let mut rec_hip_packet = Vec::<u8, U1024>::from_slice(ipv4_packet.payload())
            .map_err(|_| HIPError::Bufferistooshort)?;
        rec_hip_packet[CHECKSUM.start] = 0;
        rec_hip_packet[CHECKSUM.end - 1] = 0;
        hip_debug!("{:?}", &rec_hip_packet[..].len());
        hip_debug!("{:?}", &rec_hip_packet[..]);
        // hip_packet.set_checksum(0x0);
        let computed_checksum = Utils::hip_ipv4_checksum(
            &src.0,
            &dst.0,
            protocol,
            (1 + hip_packet.get_header_length() as u16) * 8,
            &rec_hip_packet[..],
        );
        if original_checksum != computed_checksum {
            hip_trace!("Invalid checksum");
        }

        match hip_packet.get_packet_type() as usize {
            HIP_I1_PACKET => {
                hip_debug!("Received I1 Packet");

                if hip_state
                    .ok_or_else(|| HIPError::InvalidState)?
                    .is_i1_sent()
                    && Utils::is_hit_smaller(&rhit, &ihit)
                {
                    hip_debug!("Staying in I1-SENT");
                }

                let is_hit_smaller = Utils::is_hit_smaller(&rhit, &ihit);
                if is_hit_smaller {
                    self.state_vars_map.save(
                        &rhit,
                        &ihit,
                        StateVariables::new(
                            hip_state
                                .map(|state| state.get_state())
                                .ok_or_else(|| HIPError::InvalidState)?,
                            &ihit,
                            &rhit,
                            &src.0,
                            &dst.0,
                            None,
                        ),
                    );
                } else {
                    self.state_vars_map.save(
                        &ihit,
                        &rhit,
                        StateVariables::new(
                            hip_state
                                .map(|state| state.get_state())
                                .ok_or_else(|| HIPError::InvalidState)?,
                            &ihit,
                            &rhit,
                            &src.0,
                            &dst.0,
                            None,
                        ),
                    );
                }

                // Construct R1 packet
                let mut hip_r1_packet = R1Packet::<[u8; 1024]>::new_r1packet().unwrap();
                hip_r1_packet.packet.set_senders_hit(&rhit);
                hip_r1_packet.packet.set_receivers_hit(&ihit);
                hip_r1_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_r1_packet.packet.set_version(HIP_VERSION as u8);

                let rhash = HIT::get_responders_hash_alg(&rhit);
                let rhash_len = match rhash {
                    DigestTypes::SHA256(h) => SHA256Digest::get_length(),
                    DigestTypes::SHA384(h) => SHA384Digest::get_length(),
                    _ => return Err(HIPError::__Nonexhaustive),
                };

                // Prepare puzzle
                // Fixed test seed used here - for debugging purposes.
                // HIPv2 standard recommends an irandom size of `rhash_len` and
                // that it must be pseudo-random
                //
                // - `irandom` initialized to [0] * 32 or 48 upon allocation
                // - `opaque` to [0; 2] via `init_puzzle_param` method upon allocation
                let puzzle_param = match rhash_len {
                    0x20 => {
                        let mut puzzle_param = PuzzleParameter::new_checked([0; 40])?;
                        puzzle_param.init_puzzle_param();
                        puzzle_param.set_k_value(0x10); // 16-bit difficulty
                        puzzle_param.set_lifetime(37);
                        (
                            HIPParamsTypes::PuzzleParam(puzzle_param),
                            HIPParamsTypes::Default,
                        )
                    }
                    0x30 => {
                        let mut puzzle_param = PuzzleParameter::new_checked([0; 56])?;
                        puzzle_param.init_puzzle_param();
                        puzzle_param.set_k_value(0x10); // 16-bit difficulty
                        puzzle_param.set_lifetime(37);
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::PuzzleParam(puzzle_param),
                        )
                    }
                    _ => unimplemented!(),
                };

                // HIP DH Groups Parameter. An R1 packet will have a 8-byte DH Groups parameter
                // (i.e. 4 byte TLV + 1 byte selected dh group + 3 bytes of padding)
                let mut dhgroups_param = DHGroupListParameter::new_checked([0; 8])?;
                dhgroups_param.init_dhgrouplist_param();
                let params = hip_packet
                    .get_parameters()
                    .ok_or_else(|| HIPError::FieldNotSet)?;
                let mut rec_dh_grouplist = None;
                params.iter().for_each(|param| {
                    if let HIPParamsTypes::DHGroupListParam(val) = *param {
                        rec_dh_grouplist = Some(val);
                    } else {
                    }
                });

                if rec_dh_grouplist.is_none() {
                    hip_debug!("DH groups parameter NOT found. Dropping I1 packet");
                }

                let dhlist_param = rec_dh_grouplist.ok_or_else(|| HIPError::FieldNotSet)?;
                let advertised_dh_groups = dhlist_param.get_groups()?; // supposed to be ordered by initiator's preference
                let supported_dh_groups = [0x7, 0x9, 0x8, 0x3, 0x4, 0xa];
                let mut selected_dh_group = None;
                for (idx, group_id) in advertised_dh_groups.iter().enumerate() {
                    if supported_dh_groups.contains(group_id) {
                        let group = [*group_id; 1];
                        dhgroups_param.set_groups(&group);
                        selected_dh_group = Some(advertised_dh_groups[idx]);
                        break;
                    }
                }
                if selected_dh_group == None {
                    hip_debug!("Unsupported DH groups");
                }

                let dhtypes =
                    DHFactory::get(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                let (sk256, pk256, sk384, pk384) = match dhtypes {
                    DHTypes::ECDH256(val) => {
                        let sk = ECDHNISTP256::generate_private_key([12; 32]);
                        (
                            Some(sk.clone()),
                            Some(ECDHNISTP256::generate_public_key(&sk)),
                            None,
                            None,
                        )
                    }
                    DHTypes::ECDH384(val) => {
                        let sk = ECDHNISTP384::<48>::generate_private_key([12; 32]);
                        (
                            None,
                            None,
                            Some(sk.clone()),
                            Some(ECDHNISTP384::<48>::generate_public_key(&sk)),
                        )
                    }
                    _ => unimplemented!(),
                };

                let dh_is_ecdh256 = sk256.is_some() && pk256.is_some();
                let dh_is_ecdh384 = sk384.is_some() && pk384.is_some();
                if is_hit_smaller && dh_is_ecdh256 {
                    // 7 is the `dh identifier` for ECDHNISTP256
                    self.dh_map.save(
                        &rhit,
                        &ihit,
                        InitiatorDHKeys::EcdhP256(sk256.unwrap(), pk256.unwrap()),
                    );
                } else if dh_is_ecdh256 {
                    self.dh_map.save(
                        &ihit,
                        &rhit,
                        InitiatorDHKeys::EcdhP256(sk256.unwrap(), pk256.unwrap()),
                    );
                } else if is_hit_smaller && dh_is_ecdh384 {
                    // 8 is the `dh identifier` for ECDHNISTP384
                    self.dh_map.save(
                        &rhit,
                        &ihit,
                        InitiatorDHKeys::EcdhP384(sk384.unwrap(), pk384.unwrap()),
                    );
                } else if dh_is_ecdh384 {
                    self.dh_map.save(
                        &ihit,
                        &rhit,
                        InitiatorDHKeys::EcdhP384(sk384.unwrap(), pk384.unwrap()),
                    );
                }

                // HIP DH Parameter
                let dh_param = match (dh_is_ecdh256, dh_is_ecdh384) {
                    (true, _) => {
                        let dh_param_buffer = [0; 80];
                        let mut dh_param256 = DHParameter::new_checked(dh_param_buffer)?;
                        dh_param256.init_dhparameter_param();
                        dh_param256
                            .set_group_id(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                        dh_param256.set_public_value_length(0x40 + 1); // uncompressed pubkey len for ECDH256
                        dh_param256.set_public_value(&pk256.unwrap().to_bytes()[..])?;
                        (
                            HIPParamsTypes::DHParam(dh_param256),
                            HIPParamsTypes::Default,
                        )
                    }

                    (_, true) => {
                        let dh_param_buffer = [0; 112];
                        let mut dh_param384 = DHParameter::new_checked(dh_param_buffer)?;
                        dh_param384.init_dhparameter_param();
                        dh_param384
                            .set_group_id(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                        dh_param384.set_public_value_length(0x60 + 1); // uncompressed pubkey len for ECDH384
                        dh_param384.set_public_value(&pk384.unwrap().to_bytes()[..])?;
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::DHParam(dh_param384),
                        )
                    }
                    (_, _) => unimplemented!(),
                };

                // HIP Cipher Parameter. We're advertising a maximum of 3 ciphers
                let mut cipher_param = CipherParameter::new_checked([0; 16])?;
                cipher_param.init_cipherparameter_param();
                cipher_param.set_ciphers(&[0x00, 0x4, 0x00, 0x2, 0x00, 0x1]); // aes256 -0x4, aes128 - 0x2, null -0x1

                // HIP ESP Transform Parameter. We're advertising a maximum of 3 ESP suits
                let mut esp_transform_param = ESPTransformParameter::new_checked([0; 16])?;
                esp_transform_param.init_esptransformparameter_param();
                // AES-128-CBC with HMAC-SHA-256 (0x8), AES-256-CBC with HMAC-SHA-256 (0x9) NULL
                // with HMAC-SHA-256 (0x7),
                esp_transform_param.set_esp_suits(&[0x00, 0x9, 0x00, 0x8, 0x00, 0x7]);

                // Host Identity Parameter.
                let mut hi_param = match self.hi {
                    HostIdTypes::ECDSAId256(hi) => {
                        let mut hi_256 = HostIdParameter::new_checked([0; 104])?;
                        hi_256.init_hostidparameter_param();
                        hi_256.set_host_id(&hi, &self.hi);
                        hi_256.set_domain_id(&DOMAIN_ID().into_bytes()[..]);
                        (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default)
                    }
                    HostIdTypes::ECDSAId384(hi) => {
                        let mut hi_384 = HostIdParameter::new_checked([0; 136])?;
                        hi_384.init_hostidparameter_param();
                        hi_384.set_host_id(&hi, &self.hi);
                        hi_384.set_domain_id(&DOMAIN_ID().into_bytes()[..]);
                        (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384))
                    }
                    _ => unimplemented!(),
                };

                // HIT Suit List Parameter
                let mut hit_suitlist_param = HITSuitListParameter::new_checked([0; 8])?;
                hit_suitlist_param.init_hitsuitlistparameter_param();
                hit_suitlist_param.set_suits(&[0x10, 0x20, 0x30]); // SHA256 (0x1), SHA384 (0x2), SHA1 (0x3)

                // Transport List Parameter
                let mut transfmt_param = TransportListParameter::new_checked([0; 8])?;
                transfmt_param.init_transportlistparameter_param();
                transfmt_param.set_transport_formats(&[0x0F, 0xFF]);

                // Signature Parameter
                let signer_tuple = match self.privkey {
                    Some(val) if val.len() == 0x20 => {
                        let mut signature_param = Signature2Parameter::new_checked([0; 72])?;
                        signature_param.init_signature2parameter_param();
                        let signer = ECDSASHA256Signature(val.try_into().unwrap(), [0; 64]);
                        (Some((signature_param, signer)), None)
                    }
                    Some(val) if val.len() == 0x30 => {
                        let mut signature_param = Signature2Parameter::new_checked([0; 104])?;
                        signature_param.init_signature2parameter_param();
                        let signer = ECDSASHA384Signature(
                            val.try_into().unwrap(),
                            EncodedPointP384::identity(),
                        );
                        (None, Some((signature_param, signer)))
                    }
                    Some(_) => unimplemented!(),
                    None => unreachable!(),
                };

                // Concatenate constructed parameter buffers into a heapless Vec
                let buf: Result<Vec<u8, _>> = match (puzzle_param, dh_param, hi_param) {
                    (
                        (HIPParamsTypes::PuzzleParam(puzzle_256), HIPParamsTypes::Default),
                        (HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
                        (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
                    ) => {
                        let mut param_buf: Vec<u8, U400> = Vec::new();
                        for byte in puzzle_256
                            .inner_ref()
                            .as_ref()
                            .iter()
                            .chain(dh_256.as_bytes().iter())
                            .chain(cipher_param.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.inner_ref().as_ref().iter())
                            .chain(hi_256.inner_ref().as_ref().iter())
                            .chain(hit_suitlist_param.inner_ref().as_ref().iter())
                            .chain(dhgroups_param.inner_ref().as_ref().iter())
                            .chain(transfmt_param.inner_ref().as_ref().iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort);
                        }
                        Ok(param_buf)
                    }
                    (
                        (HIPParamsTypes::Default, HIPParamsTypes::PuzzleParam(puzzle_384)),
                        (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
                        (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
                    ) => {
                        let mut param_buf: Vec<u8, U400> = Vec::new();
                        for byte in puzzle_384
                            .inner_ref()
                            .as_ref()
                            .iter()
                            .chain(dh_384.inner_ref().as_ref().iter())
                            .chain(cipher_param.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.inner_ref().as_ref().iter())
                            .chain(hi_384.inner_ref().as_ref().iter())
                            .chain(hit_suitlist_param.inner_ref().as_ref().iter())
                            .chain(dhgroups_param.inner_ref().as_ref().iter())
                            .chain(transfmt_param.inner_ref().as_ref().iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        Ok(param_buf)
                    }
                    _ => unimplemented!(),
                };

                let data_tobe_signed: Result<Vec<u8, _>> = match buf {
                    Ok(val) => {
                        let current_r1pkt_len = hip_r1_packet.packet.get_header_length();
                        let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &val.len();
                        hip_r1_packet.packet.set_header_length((pkt_len / 8) as u8);
                        let mut s: Vec<u8, U400> = Vec::new();
                        for byte in hip_r1_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                            .iter()
                            .chain(val[..].iter())
                        {
                            s.push(*byte).map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        Ok(s)
                    }
                    Err(e) => unreachable!(),
                };

                hip_debug!("data_tobe_signed: {:?}", data_tobe_signed);

                let signature_param = match signer_tuple {
                    (Some((mut signature_param, signer)), None) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        hip_debug!("computed_signature: {:?}", signature);
                        signature_param.set_signature_algorithm_2(0x7);
                        signature_param.set_signature_2(&signature?[..]);
                        (
                            HIPParamsTypes::Signature2Param(signature_param),
                            HIPParamsTypes::Default,
                        )
                    }
                    (None, Some((mut signature_param, signer))) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        signature_param.set_signature_algorithm_2(0x7);
                        signature_param.set_signature_2(&signature?[..]);
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::Signature2Param(signature_param),
                        )
                    }
                    (_, _) => unimplemented!(),
                };

                // Reset R1 packet length. We'll progressively `set header_len` when adding each
                // parameter.
                hip_r1_packet
                    .packet
                    .set_header_length(HIP_DEFAULT_PACKET_LENGTH as u8);

                // set puzzle parameter fields irandom and opaque
                // cant mutate `enum variants in place`. So, pattern match and assign the mutated `puzzle_param` to a new variable
                // This is something I need to check on - can associated data of `enum variants` be mutated in place.
                let puzzle_param = match puzzle_param {
                    (HIPParamsTypes::PuzzleParam(mut puzzle_256), HIPParamsTypes::Default) => {
                        let irandom = getrandom::<32>([12; 32]);
                        let opaque = getrandom::<2>([10; 32]);
                        puzzle_256.set_random(&irandom, 0x20);
                        puzzle_256.set_opaque(u16::from_be_bytes(opaque));
                        (
                            HIPParamsTypes::PuzzleParam(puzzle_256),
                            HIPParamsTypes::Default,
                        )
                    }
                    (HIPParamsTypes::Default, HIPParamsTypes::PuzzleParam(mut puzzle_384)) => {
                        let irandom = getrandom::<48>([12; 32]);
                        let opaque = getrandom::<2>([10; 32]);
                        puzzle_384.set_random(&irandom, 0x30);
                        puzzle_384.set_opaque(u16::from_be_bytes(opaque));
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::PuzzleParam(puzzle_384),
                        )
                    }
                    (_, _) => unreachable!(),
                };

                #[rustfmt::skip]
                // Add R1 parameters. List of mandatory parameters in an R1 packet
				match (puzzle_param, dh_param, hi_param, signature_param) {
					(
						(HIPParamsTypes::PuzzleParam(puzzle_256), HIPParamsTypes::Default),
						(HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
						(HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
						(HIPParamsTypes::Signature2Param(sign_param_256), HIPParamsTypes::Default),
					) => {
						hip_r1_packet.add_param(HIPParamsTypes::PuzzleParam(PuzzleParameter::fromtype(&puzzle_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::HITSuitListParam(HITSuitListParameter::fromtype(&hit_suitlist_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHGroupListParam(DHGroupListParameter::fromtype(&dhgroups_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::Signature2Param(Signature2Parameter::fromtype(&sign_param_256)?));
					}
					(
						(HIPParamsTypes::Default, HIPParamsTypes::PuzzleParam(puzzle_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::Signature2Param(sign_param_384)),
					) => {
						hip_r1_packet.add_param(HIPParamsTypes::PuzzleParam(PuzzleParameter::fromtype(&puzzle_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::HITSuitListParam(HITSuitListParameter::fromtype(&hit_suitlist_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHGroupListParam(DHGroupListParameter::fromtype(&dhgroups_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::Signature2Param(Signature2Parameter::fromtype(&sign_param_384)?));
					}
					_ => unimplemented!(),
				}

                // Swap src & dst IPv6 addresses
                core::mem::swap(&mut src, &mut dst);

                // Construct IPv4 packet
                let ipv4_payload_len = (1 + hip_r1_packet.packet.get_header_length() as u16) * 8;
                let ipv4_fixed_header_len = 0x14u8;
                let mut ipv4_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                let mut ipv4_packet = Ipv4Packet::new_checked(
                    &mut ipv4_buffer[..ipv4_fixed_header_len as usize + ipv4_payload_len as usize],
                )
                .map_err(|_| HIPError::Bufferistooshort)?;
                ipv4_packet.set_version(IPV4_VERSION as u8);
                ipv4_packet.set_dst_addr(dst);
                ipv4_packet.set_src_addr(src);
                ipv4_packet.set_hop_limit(IPV4_DEFAULT_TTL as u8);
                ipv4_packet.set_protocol(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                ipv4_packet.set_header_len((IPV4_IHL_NO_OPTIONS * 4) as u8);
                ipv4_packet.set_total_len(ipv4_fixed_header_len as u16 + ipv4_payload_len);

                // // Construct IPv6 packet
                // let ipv6_payload_len = (hip_r1_packet.packet.get_header_length() * 8 + 8) as u16;
                // let ipv6_fixed_header_len = 0x28u8;
                // let mut ipv6_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                // let mut ipv6_packet = Ipv6Packet::new_checked(
                //     &mut ipv6_buffer[..ipv6_fixed_header_len as usize + ipv6_payload_len as usize],
                // )
                // .map_err(|_| HIPError::Bufferistooshort)?;
                // ipv6_packet.set_version(IPV6_VERSION as u8);
                // ipv6_packet.set_dst_addr(dst);
                // ipv6_packet.set_src_addr(src);
                // ipv6_packet.set_next_header(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                // ipv6_packet.set_hop_limit(1);
                // ipv6_packet.set_payload_len(ipv6_payload_len);

                // Compute and set HIP checksum
                let checksum = Utils::hip_ipv4_checksum(
                    &src.0,
                    &dst.0,
                    protocol,
                    ipv4_payload_len,
                    &hip_r1_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );
                hip_r1_packet.packet.set_checksum(checksum);
                ipv4_packet.payload_mut().copy_from_slice(
                    &hip_r1_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );

                hip_debug!("Sending R1 packet");
                if hip_socket.can_send() {
                    hip_socket.send_slice(ipv4_packet.as_ref());
                } else {
                    hip_trace!("failed to send R1 packet");
                }
            }

            HIP_R1_PACKET => {
                hip_debug!("Received R1 packet");

                if hip_state
                    .ok_or_else(|| HIPError::InvalidState)?
                    .is_unassociated()
                    || hip_state
                        .ok_or_else(|| HIPError::InvalidState)?
                        .is_r2_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::InvalidState)?
                        .is_established()
                {
                    hip_debug!(
                        "Not expecting an R1 packet. Dropping packet... {:?}",
                        hip_state
                    );
                }

                let oga_id = HIT::get_responders_oga_id(&rhit);
                let oga = oga_id << 4;
                match oga {
                    0x10 | 0x20 | 0x30 => {}
                    _ => {
                        hip_debug!("Unsupported HIT suit");
                        hip_debug!("OGA {:?}", oga_id);
                        hip_debug!("supported_hit_suits: {:?}", [0x10, 0x20, 0x30]);
                    }
                }

                let mut puzzle_param = None;
                let mut copy_of_puzzle_param = None;
                let mut r1_counter_param = None;
                let mut irandom = None;
                let mut opaque = None;
                let mut esp_transform_param = None;
                let mut dh_param = None;
                let mut cipher_param = None;
                let mut hi_param = None;
                let mut hit_suit_param = None;
                let mut dh_groups_param = None;
                let mut transport_param = None;
                let mut echo_request_signed_opaque_data = None;
                let mut signature_param = None;
                let mut responder_pubkey256 = Some(Ok([0; 64]));
                let mut responder_pubkey384 = Some(Ok([0; 96]));
                let mut echo_request_unisgned_opaque_data = None;
                let mut parameters = hip_packet.get_parameters();

                // Construct R1 packet
                let mut hip_r1_packet = R1Packet::<[u8; 1024]>::new_r1packet().unwrap();
                hip_r1_packet
                    .packet
                    .set_senders_hit(&hip_packet.get_senders_hit());
                hip_r1_packet
                    .packet
                    .set_receivers_hit(&hip_packet.get_receivers_hit());
                hip_r1_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_r1_packet.packet.set_version(HIP_VERSION as u8);

                let rhash = HIT::get_responders_hash_alg(&ihit);
                let rhash_len = match &rhash {
                    DigestTypes::SHA256(_) => SHA256Digest::get_length(),
                    DigestTypes::SHA384(_) => SHA384Digest::get_length(),
                    _ => return Err(HIPError::__Nonexhaustive),
                };

                let param_list = parameters.ok_or_else(|| HIPError::FieldNotSet)?;
                param_list.iter().for_each(|param| match param {
                    HIPParamsTypes::DHGroupListParam(val) => {
                        hip_debug!("DH groups parameter");
                        dh_groups_param = Some(val);
                    }
                    HIPParamsTypes::R1Counter(val) => {
                        hip_debug!("R1 Counter parameter");
                        r1_counter_param = Some(val);
                    }
                    HIPParamsTypes::PuzzleParam(val) => {
                        hip_debug!("Puzzle parameter");
                        puzzle_param = Some(val);
                        irandom = puzzle_param.map(|param| param.get_random(rhash_len));
                        opaque = puzzle_param.map(|param| param.get_opaque());

                        // get a copy of puzzle param
                        let mut param = Vec::<u8, U128>::from_slice(val.inner_ref().as_ref())
                            .map_err(|_| HIPError::Bufferistooshort)
                            .expect("puzzle parameter not set");
                        // param.resize(len, 0u8);
                        copy_of_puzzle_param = Some(param);
                    }
                    HIPParamsTypes::DHParam(val) => {
                        hip_debug!("DH parameter");
                        dh_param = Some(val);
                    }
                    HIPParamsTypes::HostIdParam(val) => {
                        hip_debug!("Host ID");
                        hi_param = Some(val);
                        if Some(hi_param.map(|param| param.get_algorithm()))
                            == Some(Some(Ok(0x7 as u16)))
                        {
                            let responder_hi = hi_param.map(|param| param.get_host_id());
                            let oga = HIT::get_responders_oga_id(&ihit);
                            hip_debug!("Responder's OGA ID {:?}", oga);
                            hip_debug!("Responder HI: {:?}", responder_hi);
                            let hi = match responder_hi {
                                Some(Ok(val)) => val,
                                _ => {
                                    hip_debug!("HostID missing");
                                    &[]
                                }
                            };
                            match hi[0..2] {
                                [0, 1] => {
                                    let responders_hit = HIT::compute_hit::<82>(hi, oga);
                                    hip_debug!("Responder's computed HIT: {:?}", responders_hit);
                                    hip_debug!("Responder's actual HIT: {:?}", &ihit);
                                    hip_debug!("own HIT: {:?}", self.hit_as_bytes);
                                    if !Utils::hits_equal(&ihit, &responders_hit) {
                                        hip_trace!("Invalid HIT");
                                        panic!(
                                            "Invalid HIT {:?}, responder_hit: {:?}",
                                            &ihit, &responders_hit
                                        );
                                    }
                                }
                                [0, 2] => {
                                    let responders_hit = HIT::compute_hit::<114>(hi, oga);
                                    hip_debug!("Responder's computed HIT: {:?}", responders_hit);
                                    hip_debug!("Responder's actual HIT: {:?}", &ihit);
                                    hip_debug!("own HIT: {:?}", self.hit_as_bytes);
                                    if !Utils::hits_equal(&ihit, &responders_hit) {
                                        hip_trace!("Invalid HIT");
                                        panic!(
                                            "Invalid HIT {:?}, responder_hit: {:?}",
                                            &ihit, &responders_hit
                                        );
                                    }
                                }
                                _ => unimplemented!(),
                            }

                            // Extract publickey from HostId
                            match hi[0..2] {
                                [0, 1] => {
                                    responder_pubkey256 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
                                    responder_pubkey384 = None;
                                }
                                [0, 2] => {
                                    responder_pubkey384 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
                                    responder_pubkey256 = None;
                                }
                                _ => unimplemented!(),
                            }

                            // Save responder pubkey to the pubkey_map
                            match (responder_pubkey256, responder_pubkey384) {
                                (Some(val), None) => {
                                    if let Ok(val) = val {
                                        self.pubkey_map.save(
                                            &ihit,
                                            &rhit,
                                            ResponderPubKey::Pk256(val),
                                        );
                                    }
                                }
                                (None, Some(val)) => {
                                    if let Ok(val) = val {
                                        self.pubkey_map.save(
                                            &ihit,
                                            &rhit,
                                            ResponderPubKey::Pk384(val),
                                        );
                                    }
                                }
                                (_, _) => unimplemented!(),
                            };
                        }
                    }
                    HIPParamsTypes::HITSuitListParam(val) => {
                        hip_debug!("HIT Suit list parameter");
                        hit_suit_param = Some(val);
                    }
                    HIPParamsTypes::TransportListParam(val) => {
                        hip_debug!("Transport parameter");
                        hip_debug!("Transport formats: {:?}", val.get_transport_formats());
                        transport_param = Some(val);
                    }
                    HIPParamsTypes::Signature2Param(val) => {
                        hip_debug!("Signature parameter");
                        signature_param = Some(val);
                    }
                    HIPParamsTypes::EchoRequestSignedParam(val) => {
                        hip_debug!("Echo request signed parameter");
                        // let mut echo_signed = EchoResponseSignedParameter::new_checked([0; 100]);
                        echo_request_signed_opaque_data = Some(val.get_opaque_data());
                    }
                    HIPParamsTypes::EchoRequestUnsignedParam(val) => {
                        hip_debug!("Echo request unsigned parameter");
                        echo_request_unisgned_opaque_data = Some(val.get_opaque_data());
                    }
                    HIPParamsTypes::CipherParam(val) => {
                        hip_debug!("Cipher Parameter");
                        cipher_param = Some(val);
                    }
                    HIPParamsTypes::ESPTransformParam(val) => {
                        hip_debug!("ESP Transform Parameter");
                        esp_transform_param = Some(val);
                    }
                    _ => (),
                });

                // Check if any of the mandatory parameters are missing.
                if puzzle_param.is_none() {
                    hip_trace!("Puzzle Parameter not sent");
                } else if dh_param.is_none() {
                    hip_trace!("DH Parameter not sent");
                } else if cipher_param.is_none() {
                    hip_trace!("Cipher Parameter not sent");
                } else if esp_transform_param.is_none() {
                    hip_trace!("ESP Transform Parameter not sent");
                } else if hi_param.is_none() {
                    hip_trace!("Host ID Parameter not sent");
                } else if hit_suit_param.is_none() {
                    hip_trace!("HIT Suit List Parameter not sent");
                } else if dh_groups_param.is_none() {
                    hip_trace!("DH Groups Parameter not sent");
                } else if transport_param.is_none() {
                    hip_trace!("Trandport Parameter not sent");
                } else if signature_param.is_none() {
                    hip_trace!("Signature Parameter not sent");
                }

                if let (Some(p1), Some(p2)) = (dh_groups_param, dh_param) {
                    let list = p1.get_groups()?;
                    if list.contains(&p2.get_group_id()?) {
                    } else {
                        hip_trace!("Manipulation of DH group");
                    }
                }

                // Start a timer
                let mut timer = Timer::new(Duration {
                    millis: (2
                        << (puzzle_param
                            .ok_or_else(|| HIPError::FieldNotSet)?
                            .get_lifetime()?
                            - 32))
                        * 1000,
                });
                // Solve and Verify the puzzle
                let mut jrandom = [0; 32];
                let mut i = [0u8; 32];
                let mut j = [0u8; 32];
                let mut solver = PuzzleSolver(&mut i, &mut j);
                if let (Some(irandom), Some(difficulty)) = (irandom, puzzle_param) {
                    let jrand = solver.solve_puzzle(
                        &irandom?,
                        &hip_packet.get_receivers_hit(),
                        &hip_packet.get_senders_hit(),
                        difficulty.get_k_value()? as usize,
                        &rhash,
                    );
                    jrandom = jrand.try_into().map_err(|_| HIPError::__Nonexhaustive)?;
                    hip_debug!("Puzzle was solved");
                }
                // Check if the time taken to solve the puzzle is greater than the `timer duration`.
                // If yes, drop the packet and set state to unassociated.
                let elapsed_time = timer.get_elapsed_time().ok_or_else(|| HIPError::TimeOut)?;
                if elapsed_time > timer.duration {
                    hip_debug!("Maximum time to solve the puzzle exceeded. Dropping the packet...");
                    hip_state = hip_state.map(|state| state.unassociated());
                }

                // Echo Response Signed Paraemeter - just echo back what the sender sent, unmodified. Assuming a 36 byte opaque payload.
                let mut echo_signed = EchoResponseSignedParameter::new_checked([0; 36])?;
                echo_signed.init_echoresponse_signed_param();
                if echo_request_signed_opaque_data.is_some() {
                    echo_signed.set_opaque_data(
                        echo_request_signed_opaque_data.ok_or_else(|| HIPError::FieldNotSet)??,
                    );
                }
                // Echo Response Unsigned Paraemeter - just echo back what the sender sent, unmodified. Assuming a 36 byte opaque payload.
                let mut echo_unsigned = EchoResponseUnsignedParameter::new_checked([0; 36])?;
                echo_unsigned.init_echoresponse_unsigned_param();
                if echo_request_unisgned_opaque_data.is_some() {
                    echo_unsigned.set_opaque_data(
                        echo_request_unisgned_opaque_data
                            .ok_or_else(|| HIPError::FieldNotSet)??,
                    );
                }

                // Reset puzzle_param fields before verifying the signature. We create a copy as
                // the original value is a `PuzzleParameter<&[u8]>` and not a `PuzzleParameter<&mut [u8]>`
                // We cannot be mutate a buffer behind a reference. Note this is a design contract of this library.
                // (not a limitation)
                let mut temp = &mut copy_of_puzzle_param.ok_or_else(|| HIPError::Exhausted)?[..];
                let mut reset_puzzle_param = PuzzleParameter::new_checked(temp)?;
                match rhash_len {
                    0x20 => {
                        reset_puzzle_param.set_random(&[0; 0x20], rhash_len);
                        reset_puzzle_param.set_opaque(0u16);
                        reset_puzzle_param.set_length(0u16);
                    }
                    0x30 => {
                        reset_puzzle_param.set_random(&[0; 0x30], rhash_len);
                        reset_puzzle_param.set_opaque(0u8 as u16);
                        reset_puzzle_param.set_length(0u16);
                    }
                    _ => unimplemented!(),
                };
                let new_puzzle_param = Some(&reset_puzzle_param);

                let mut param_buf: Vec<u8, U512> = Vec::new();
                #[rustfmt::skip]
                match (r1_counter_param, echo_request_signed_opaque_data) {
                    (Some(r1), Some(echo_req)) => {  //                      
                        for byte in r1.inner_ref().as_ref().iter()
                            .chain(option_as_ref(new_puzzle_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(hit_suit_param)?.iter())
                            .chain(option_as_ref(dh_groups_param)?.iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(option_as_ref(transport_param)?.iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
                        }
                    },
                    (Some(r1), None) => {
                        for byte in r1.inner_ref().as_ref().iter()
                            .chain(option_as_ref(new_puzzle_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(hit_suit_param)?.iter())
                            .chain(option_as_ref(dh_groups_param)?.iter())
                            .chain(option_as_ref(transport_param)?.iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                    (None, Some(echo_req)) => { //
                        for byte in option_as_ref(new_puzzle_param)?.iter()
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(hit_suit_param)?.iter())
                            .chain(option_as_ref(dh_groups_param)?.iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(option_as_ref(transport_param)?.iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                    (None, None) => {
                        for byte in option_as_ref(new_puzzle_param)?.iter()
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(hit_suit_param)?.iter())
                            .chain(option_as_ref(dh_groups_param)?.iter())
                            .chain(option_as_ref(transport_param)?.iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                }

                {
                    let current_r1pkt_len = hip_r1_packet.packet.get_header_length();
                    let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &param_buf.len();
                    hip_r1_packet.packet.set_header_length((pkt_len / 8) as u8);
                    let mut bytes_to_verify: Vec<u8, U512> = Vec::new();
                    for byte in hip_r1_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                        .iter()
                        .chain(param_buf[..].iter())
                    {
                        bytes_to_verify
                            .push(*byte)
                            .map_err(|_| HIPError::Bufferistooshort)?;
                    }

                    hip_debug!("bytes_to_verify {:?}", bytes_to_verify);

                    match (responder_pubkey256, responder_pubkey384) {
                        (Some(val), None) => {
                            if let Ok(pubkey_256) = val {
                                let verifier = ECDSASHA256Signature([0; 32], pubkey_256);
                                let verified = verifier.verify(
                                    &bytes_to_verify[..],
                                    signature_param
                                        .ok_or_else(|| HIPError::SignatureError)?
                                        .get_signature_2()?,
                                );
                                if !verified? {
                                    hip_trace!(
                                        "Invalid signature in R1 packet. Dropping the packet"
                                    );
                                }
                            }
                        }
                        (None, Some(val)) => {
                            if let Ok(pubkey_384) = val {
                                let verifier = ECDSASHA384Signature(
                                    [0; 48],
                                    EncodedPointP384::from_bytes(pubkey_384)
                                        .map_err(|_| HIPError::InvalidEncoding)?,
                                );
                                let verified = verifier.verify(
                                    &bytes_to_verify[..],
                                    signature_param
                                        .ok_or_else(|| HIPError::SignatureError)?
                                        .get_signature_2()?,
                                );
                                if !verified? {
                                    hip_trace!(
                                        "Invalid signature in R1 packet. Dropping the packet"
                                    );
                                }
                            }
                        }
                        (_, _) => unimplemented!(),
                    }
                }

                // Get the DH group and look it up in our list of supported groups.
                // If we get a match, move to key-generation
                let dhlist_param = dh_groups_param.ok_or_else(|| HIPError::FieldNotSet)?;
                let advertised_dh_groups = dhlist_param.get_groups()?; // supposed to be ordered by initiator's preference
                let supported_dh_groups = [0x7, 0x9, 0x8, 0x3, 0x4, 0xa];
                let mut selected_dh_group = None;
                for (idx, group_id) in advertised_dh_groups.iter().enumerate() {
                    if supported_dh_groups.contains(group_id) {
                        // let group = [*group_id; 1];
                        // dhgroups_param.set_groups(&group);
                        selected_dh_group = Some(advertised_dh_groups[idx]);
                        break;
                    }
                }
                if selected_dh_group == None {
                    hip_debug!("Unsupported DH groups");
                }

                // Generate DH private and public keys for the selected DH group.
                let mut dh_alg_id = 0;
                let dhtypes =
                    DHFactory::get(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                let (sk256, pk256_i, sk384, pk384_i) = match dhtypes {
                    DHTypes::ECDH256(val) => {
                        dh_alg_id = 0x7;
                        let sk = ECDHNISTP256::generate_private_key([12; 32]);
                        (
                            Some(sk.clone()),
                            Some(ECDHNISTP256::generate_public_key(&sk)),
                            None,
                            None,
                        )
                    }
                    DHTypes::ECDH384(val) => {
                        dh_alg_id = 0x8;
                        let sk = ECDHNISTP384::<48>::generate_private_key([12; 32]);
                        (
                            None,
                            None,
                            Some(sk.clone()),
                            Some(ECDHNISTP384::<48>::generate_public_key(&sk)),
                        )
                    }
                    _ => unimplemented!(),
                };

                // Get the responder's DH PubKey.
                let (pk256_r, pk384_r) = match dh_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_public_value()
                {
                    Ok(pk) if pk.len() == 65 => (Some(pk), None),
                    Ok(pk) if pk.len() == 97 => (None, Some(pk)),
                    Ok(_) => {
                        hip_debug!("Invalid Public Key value");
                        (None, None)
                    }
                    Err(_) => unimplemented!(),
                };

                // Compute the shared secret using the responder's pubkey and our DH keys
                let (ss256, ss384) = match (pk256_r, pk384_r) {
                    (Some(pk), None) => {
                        let temp = pk256_r.ok_or_else(|| HIPError::FieldNotSet)?;
                        let pk256_r = PkP256::from_bytes(temp)?;
                        let ss = ECDHNISTP256::generate_shared_secret(
                            &sk256.clone().ok_or_else(|| HIPError::ECCError)?,
                            &pk256_r,
                        )?;
                        (Some(ss), None)
                    }
                    (None, Some(pk)) => {
                        let temp = pk384_r.ok_or_else(|| HIPError::FieldNotSet)?;
                        let pk384_r = PkP384::from_bytes(temp)?;
                        let ss = ECDHNISTP384::<48>::generate_shared_secret(
                            &sk384.clone().ok_or_else(|| HIPError::ECCError)?,
                            &pk384_r,
                        )?;
                        (None, Some(ss))
                    }
                    (_, _) => unimplemented!(),
                };

                // Save our DH keys to the DH map.
                let dh_is_ecdh256 = sk256.is_some() && pk256_i.is_some();
                let dh_is_ecdh384 = sk384.is_some() && pk384_i.is_some();
                let is_hit_smaller = Utils::is_hit_smaller(&rhit, &ihit);

                if is_hit_smaller && dh_is_ecdh256 {
                    // 7 is the `dh identifier` for ECDHNISTP256
                    self.dh_map.save(
                        &rhit,
                        &ihit,
                        InitiatorDHKeys::EcdhP256(sk256.unwrap(), pk256_i.unwrap()),
                    );
                } else if dh_is_ecdh256 {
                    self.dh_map.save(
                        &ihit,
                        &rhit,
                        InitiatorDHKeys::EcdhP256(sk256.unwrap(), pk256_i.unwrap()),
                    );
                } else if is_hit_smaller && dh_is_ecdh384 {
                    // 8 is the `dh identifier` for ECDHNISTP384
                    self.dh_map.save(
                        &rhit,
                        &ihit,
                        InitiatorDHKeys::EcdhP384(sk384.unwrap(), pk384_i.unwrap()),
                    );
                } else if dh_is_ecdh384 {
                    self.dh_map.save(
                        &ihit,
                        &rhit,
                        InitiatorDHKeys::EcdhP384(sk384.unwrap(), pk384_i.unwrap()),
                    );
                }

                // A 64 byte salt for the HBKDF from the concatenated irandom + jrandom values
                let info = Utils::sort_hits(&ihit, &rhit);
                let mut salt_buffer = [0; 64];
                let salt = irandom.map(|res| {
                    res.and_then(|slice| {
                        slice
                            .iter()
                            .chain(jrandom.iter())
                            .enumerate()
                            .for_each(|(i, x)| salt_buffer[i] = *x);
                        Ok(())
                    })
                });
                let hmac_alg = HIT::get_responders_oga_id(&ihit);

                // Construct a keyinfo value
                let key_info = KeyInfo {
                    info,
                    salt: salt_buffer,
                    alg_id: dh_alg_id,
                };

                // Save to key_info map.
                if is_hit_smaller {
                    self.key_info_map.save(&rhit, &ihit, key_info);
                } else {
                    self.key_info_map.save(&ihit, &rhit, key_info);
                }

                // Select a cipher from the list of advertised/offered ciphers
                let offered_ciphers = cipher_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_ciphers()?;
                let supported_ciphers = [0x4, 0x2, 0x1]; // NULL (0x1), AES128CBC (0x2), AES256CBC (0x4)
                let mut selected_cipher = None;

                for (idx, group_id) in offered_ciphers.iter().enumerate() {
                    if supported_ciphers.contains(group_id) {
                        selected_cipher = Some(offered_ciphers[idx]);
                        break;
                    }
                }
                if selected_cipher.is_none() {
                    hip_trace!("Unsupported cipher");
                    return Err(HIPError::Unrecognized);
                }

                // Save to the cipher map.
                if is_hit_smaller {
                    self.cipher_map.save(&rhit, &ihit, selected_cipher);
                } else {
                    self.cipher_map.save(&ihit, &rhit, selected_cipher);
                }

                // Select an esp_transform from the list of advertised/offered esp transforms
                let offered_esp_transforms = esp_transform_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_esp_suits()?;
                // NULL with HMAC-SHA-256 (0x7), AES-128-CBC with HMAC-SHA-256 (0x8), AES-256-CBC with HMAC-SHA-256 (0x9)
                let supported_esp_transform_suits = [0x9, 0x8, 0x7];
                let mut selected_esp_transform = None;

                for (idx, group_id) in offered_esp_transforms.iter().enumerate() {
                    if supported_esp_transform_suits.contains(group_id) {
                        selected_esp_transform = Some(offered_esp_transforms[idx]);
                        self.selected_esp_transform = selected_esp_transform;
                        break;
                    }
                }
                if selected_esp_transform.is_none() {
                    hip_trace!("Unsupported ESP transform suit");
                    return Err(HIPError::Unrecognized);
                }

                // Output from kdf function i.e. key-material
                // Note - you only need the first `keymat_len_octet bytes` from the output
                let mut keymat = [0; 800];
                let keymat_len_octets = Utils::compute_keymat_len(
                    hmac_alg,
                    selected_cipher.ok_or_else(|| HIPError::FieldNotSet)?,
                );

                if ss256.is_some() {
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss256.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss384.is_some() {
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss384.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss256.is_none() && ss384.is_none() {
                    return Err(HIPError::FieldNotSet);
                }

                // Save to keymat map.
                if is_hit_smaller {
                    self.keymat_map.save(&rhit, &ihit, keymat);
                } else {
                    self.keymat_map.save(&ihit, &rhit, keymat);
                }

                hip_debug!("Processing R1 packet");

                // Construct I2 packet
                let mut hip_i2_packet = I2Packet::<[u8; 1024]>::new_i2packet().unwrap();
                hip_i2_packet.packet.set_senders_hit(&rhit);
                hip_i2_packet.packet.set_receivers_hit(&ihit);
                hip_i2_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_i2_packet.packet.set_version(HIP_VERSION as u8);

                // HIP Solution Parameter
                let mut solution_param =
                    SolutionParameter::new_checked([0; HIP_SOLUTION_J_OFFSET.end])?;
                solution_param.init_solution_param();
                solution_param.set_k_value(
                    puzzle_param
                        .ok_or_else(|| HIPError::FieldNotSet)?
                        .get_k_value()?,
                );
                solution_param.set_opaque(opaque.ok_or_else(|| HIPError::FieldNotSet)??);
                solution_param.set_random(irandom.ok_or_else(|| HIPError::FieldNotSet)??);
                solution_param.set_solution(&jrandom);

                // HIP DH Parameter
                let dh_param = match (dh_is_ecdh256, dh_is_ecdh384) {
                    (true, _) => {
                        let dh_param_buffer = [0; 80];
                        let mut dh_param256 = DHParameter::new_checked(dh_param_buffer)?;
                        dh_param256.init_dhparameter_param();
                        dh_param256
                            .set_group_id(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                        dh_param256.set_public_value_length(0x40 + 1); // uncompressed pubkey len for ECDH256
                        dh_param256.set_public_value(&pk256_i.unwrap().to_bytes());
                        (
                            HIPParamsTypes::DHParam(dh_param256),
                            HIPParamsTypes::Default,
                        )
                    }

                    (_, true) => {
                        let dh_param_buffer = [0; 112];
                        let mut dh_param384 = DHParameter::new_checked(dh_param_buffer)?;
                        dh_param384.init_dhparameter_param();
                        dh_param384
                            .set_group_id(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                        dh_param384.set_public_value_length(0x60 + 1); // uncompressed pubkey len for ECDH384
                        dh_param384.set_public_value(&pk384_i.unwrap().to_bytes());
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::DHParam(dh_param384),
                        )
                    }
                    (_, _) => unimplemented!(),
                };

                // HIP Cipher Parameter. Set selected cipher
                let mut cipher_param = CipherParameter::new_checked([0; 16])?;
                let chosen_cipher = selected_cipher.ok_or_else(|| HIPError::Unrecognized)?;
                cipher_param.init_cipherparameter_param();
                cipher_param.set_ciphers(&[0x00, chosen_cipher]); // aes256 -0x4, aes128 - 0x2, null -0x1

                // HIP ESP Transform Parameter. Set selected esp transform suit
                let mut esp_transform_param = ESPTransformParameter::new_checked([0; 16])?;
                let chosen_esp_transform =
                    selected_esp_transform.ok_or_else(|| HIPError::Unrecognized)?;
                esp_transform_param.init_esptransformparameter_param();
                // AES-128-CBC with HMAC-SHA-256 (0x8), AES-256-CBC with HMAC-SHA-256 (0x9) NULL with HMAC-SHA-256 (0x7),
                esp_transform_param.set_esp_suits(&[0x00, chosen_esp_transform]);

                // HIP ESP Info Parameter
                let keymat_index =
                    Utils::compute_hip_keymat_len(hmac_alg, selected_cipher.unwrap());
                let mut esp_info_param = ESPInfoParameter::new_checked([0; 16])?;
                esp_info_param.init_espinfoparameter_param();
                esp_info_param.set_keymat_index(keymat_index as u16);
                let random_spi = u32::from_be_bytes(getrandom::<4>([12; 32]));
                esp_info_param.set_new_spi(random_spi);

                // Host Identity Parameter.
                let mut hi_param = match self.hi {
                    HostIdTypes::ECDSAId256(hi) => {
                        let mut hi_256 = HostIdParameter::new_checked([0; 104])?;
                        hi_256.init_hostidparameter_param();
                        hi_256.set_host_id(&hi, &self.hi);
                        hi_256.set_domain_id(&DOMAIN_ID().into_bytes()[..]);
                        (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default)
                    }
                    HostIdTypes::ECDSAId384(hi) => {
                        let mut hi_384 = HostIdParameter::new_checked([0; 136])?;
                        hi_384.init_hostidparameter_param();
                        hi_384.set_host_id(&hi, &self.hi);
                        hi_384.set_domain_id(&DOMAIN_ID().into_bytes()[..]);
                        (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384))
                    }
                    _ => unimplemented!(),
                };

                // Transport List Parameter
                let mut transfmt_param = TransportListParameter::new_checked([0; 8])?;
                transfmt_param.init_transportlistparameter_param();
                transfmt_param.set_transport_formats(&[0x0F, 0xFF]);

                // HIP Mac Parameter
                let (mut mac256_param, mut mac384_param) = match hmac_alg {
                    0x1 => {
                        let mut mac_param = MACParameter::new_checked([0; 32 + 8])?;
                        mac_param.init_macparamter_param();
                        (Some(mac_param), None)
                    }
                    0x2 => {
                        let mut mac_param = MACParameter::new_checked([0; 48 + 8])?;
                        mac_param.init_macparamter_param();
                        (None, Some(mac_param))
                    }
                    _ => unimplemented!(),
                };

                // Compute HMAC
                let mut param_buf: Vec<u8, U512> = Vec::new();
                match (r1_counter_param, echo_request_signed_opaque_data) {
                    (Some(r1), Some(echo_req)) => match (dh_param, hi_param) {
                        (
                            (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                            (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(r1.as_bytes().iter())
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh256.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi256.as_bytes().iter())
                                .chain(echo_signed.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (
                            (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh384)),
                            (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi384)),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(r1.as_bytes().iter())
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh384.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi384.as_bytes().iter())
                                .chain(echo_signed.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (_, _) => unimplemented!(),
                    },
                    (Some(r1), None) => match (dh_param, hi_param) {
                        (
                            (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                            (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(r1.as_bytes().iter())
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh256.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi256.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (
                            (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh384)),
                            (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi384)),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(r1.as_bytes().iter())
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh384.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi384.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (_, _) => unimplemented!(),
                    },
                    (None, Some(echo_req)) => match (dh_param, hi_param) {
                        (
                            (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                            (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh256.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi256.as_bytes().iter())
                                .chain(echo_signed.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (
                            (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh384)),
                            (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi384)),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh384.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi384.as_bytes().iter())
                                .chain(echo_signed.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (_, _) => unimplemented!(),
                    },
                    (None, None) => match (dh_param, hi_param) {
                        (
                            (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                            (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh256.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi256.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (
                            (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh384)),
                            (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi384)),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(solution_param.as_bytes().iter())
                                .chain(dh384.as_bytes().iter())
                                .chain(cipher_param.as_bytes().iter())
                                .chain(esp_transform_param.as_bytes().iter())
                                .chain(hi384.as_bytes().iter())
                                .chain(transfmt_param.as_bytes().iter())
                            {
                                param_buf
                                    .push(*byte)
                                    .map_err(|_| HIPError::Bufferistooshort);
                            }
                        }
                        (_, _) => unimplemented!(),
                    },
                }

                let current_r1pkt_len = hip_i2_packet.packet.get_header_length();
                let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &param_buf.len();
                hip_i2_packet.packet.set_header_length((pkt_len / 8) as u8);
                let mut hmac_bytes: Vec<u8, U512> = Vec::new();
                for byte in hip_i2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                    .iter()
                    .chain(param_buf[..].iter())
                {
                    hmac_bytes
                        .push(*byte)
                        .map_err(|_| HIPError::Bufferistooshort)?;
                }

                let (aes_key, hmac_key) = Utils::get_keys(
                    &keymat[..keymat_len_octets as usize],
                    hmac_alg,
                    selected_cipher.unwrap(),
                    &ihit,
                    &rhit,
                )?;
                let hmac = HMACFactory::get(hmac_alg);

                // Cant mutate enum in place.
                let (mac256_param, mac384_param) = match (mac256_param, mac384_param) {
                    (Some(mut val), None) => {
                        val.set_hmac(&SHA256HMAC::hmac_256(&hmac_bytes[..], hmac_key));
                        (Some(val), None)
                    }
                    (None, Some(mut val)) => {
                        val.set_hmac(&SHA384HMAC::hmac_384(&hmac_bytes[..], hmac_key));
                        (None, Some(val))
                    }
                    (_, _) => unimplemented!(),
                };

                // Compute Signature
                //
                // Construct Signature Parameter
                let signer_tuple = match self.privkey {
                    Some(val) if val.len() == 0x20 => {
                        let mut signature_param = SignatureParameter::new_checked([0; 72])?;
                        let signer = ECDSASHA256Signature(val.try_into().unwrap(), [0; 64]);
                        (Some((signature_param, signer)), None)
                    }
                    Some(val) if val.len() == 0x30 => {
                        let mut signature_param = SignatureParameter::new_checked([0; 104])?;
                        let signer = ECDSASHA384Signature(
                            val.try_into().unwrap(),
                            EncodedPointP384::identity(),
                        );
                        (None, Some((signature_param, signer)))
                    }
                    Some(_) => unimplemented!(),
                    None => unreachable!(),
                };

                let data_tobe_signed: Result<Vec<u8, _>> = match (mac256_param, mac384_param) {
                    (Some(mac256_param), None) => {
                        for byte in mac256_param.inner_ref().as_ref().iter() {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        let current_r1pkt_len = hip_r1_packet.packet.get_header_length();
                        let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &param_buf.len();
                        hip_r1_packet.packet.set_header_length((pkt_len / 8) as u8);
                        let mut s: Vec<u8, U512> = Vec::new();
                        for byte in hip_i2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                            .iter()
                            .chain(param_buf[..].iter())
                        {
                            s.push(*byte).map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        Ok(s)
                    }
                    (None, Some(mac384_param)) => {
                        for byte in mac384_param.inner_ref().as_ref().iter() {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        let current_r1pkt_len = hip_r1_packet.packet.get_header_length();
                        let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &param_buf.len();
                        hip_r1_packet.packet.set_header_length((pkt_len / 8) as u8);
                        let mut s: Vec<u8, U512> = Vec::new();
                        for byte in hip_i2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                            .iter()
                            .chain(param_buf[..].iter())
                        {
                            s.push(*byte).map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        Ok(s)
                    }
                    (_, _) => unimplemented!(),
                };

                let signature_param = match signer_tuple {
                    (Some((mut signature_param, signer)), None) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        signature_param.set_signature_algorithm(0x7);
                        signature_param.set_signature(&signature?[..]);
                        (
                            HIPParamsTypes::SignatureParam(signature_param),
                            HIPParamsTypes::Default,
                        )
                    }
                    (None, Some((mut signature_param, signer))) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        signature_param.set_signature_algorithm(0x7);
                        signature_param.set_signature(&signature?[..]);
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::SignatureParam(signature_param),
                        )
                    }
                    (_, _) => unimplemented!(),
                };

                // Reset I2 packet length. We'll progressively `set header_len` when adding each
                // parameter.
                hip_i2_packet
                    .packet
                    .set_header_length(HIP_DEFAULT_PACKET_LENGTH as u8);

                #[rustfmt::skip]
                // Add I2 parameters. List of mandatory parameters in an I2 packet
                 match (r1_counter_param, echo_request_signed_opaque_data) {
                       (Some(r1), Some(echo_req)) => {
                           match (dh_param, hi_param, signature_param) {
                                (
                                    (HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::SignatureParam(sign_param_256), HIPParamsTypes::Default),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::R1Counter(R1CounterParam::fromtype(&r1)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::EchoResponseSignedParam(EchoResponseSignedParameter::fromtype(&echo_signed)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac256_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_256)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                (
                                    (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::SignatureParam(sign_param_384)),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::R1Counter(R1CounterParam::fromtype(&r1)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::EchoResponseSignedParam(EchoResponseSignedParameter::fromtype(&echo_signed)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac384_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_384)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                _ => unimplemented!(),
                            }
                        },
                        (Some(r1), None) => {
                            match (dh_param, hi_param, signature_param) {
                                (
                                    (HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::SignatureParam(sign_param_256), HIPParamsTypes::Default),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::R1Counter(R1CounterParam::fromtype(&r1)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac256_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_256)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                (
                                    (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::SignatureParam(sign_param_384)),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::R1Counter(R1CounterParam::fromtype(&r1)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac384_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_384)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                _ => unimplemented!(),
                            }
                        },
                        (None, Some(echo_req)) => {
                            match (dh_param, hi_param, signature_param) {
                                (
                                    (HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::SignatureParam(sign_param_256), HIPParamsTypes::Default),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::EchoResponseSignedParam(EchoResponseSignedParameter::fromtype(&echo_signed)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac256_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_256)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                (
                                    (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::SignatureParam(sign_param_384)),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::EchoResponseSignedParam(EchoResponseSignedParameter::fromtype(&echo_signed)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac384_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_384)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                _ => unimplemented!(),
                            }
                        },
                        (None, None) => {
                            match (dh_param, hi_param, signature_param) {
                                (
                                    (HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
                                    (HIPParamsTypes::SignatureParam(sign_param_256), HIPParamsTypes::Default),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac256_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_256)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                (
                                    (HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
                                    (HIPParamsTypes::Default, HIPParamsTypes::SignatureParam(sign_param_384)),
                                ) => {
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SolutionParam(SolutionParameter::fromtype(&solution_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
                                    hip_i2_packet.add_param(HIPParamsTypes::MACParam(MACParameter::fromtype(&mac384_param.unwrap())?));
                                    hip_i2_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_384)?));
                                    if echo_request_unisgned_opaque_data.is_some() {
                                        hip_i2_packet.add_param(HIPParamsTypes::EchoResponseUnsignedParam(
                                            EchoResponseUnsignedParameter::fromtype(&echo_unsigned)?));
                                    }
                                }
                                _ => unimplemented!(),
                            }
                        }
                    }

                // Swap src & dst IPv6 addresses
                core::mem::swap(&mut src, &mut dst);

                // Construct IPv4 packet
                let ipv4_payload_len = (1 + hip_i2_packet.packet.get_header_length() as u16) * 8;
                let ipv4_fixed_header_len = 0x14u8;
                let mut ipv4_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                let mut ipv4_packet = Ipv4Packet::new_checked(
                    &mut ipv4_buffer[..ipv4_fixed_header_len as usize + ipv4_payload_len as usize],
                )
                .map_err(|_| HIPError::Bufferistooshort)?;
                ipv4_packet.set_version(IPV4_VERSION as u8);
                ipv4_packet.set_dst_addr(dst);
                ipv4_packet.set_src_addr(src);
                ipv4_packet.set_hop_limit(IPV4_DEFAULT_TTL as u8);
                ipv4_packet.set_protocol(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                ipv4_packet.set_header_len((IPV4_IHL_NO_OPTIONS * 4) as u8);
                ipv4_packet.set_total_len(ipv4_fixed_header_len as u16 + ipv4_payload_len);

                // // Construct IPv6 packet
                // let ipv6_payload_len = (hip_i2_packet.packet.get_header_length() * 8 + 8) as u16;
                // let ipv6_fixed_header_len = 0x28u8;
                // let mut ipv6_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                // let mut ipv6_packet = Ipv6Packet::new_checked(
                //     &mut ipv6_buffer[..ipv6_fixed_header_len as usize + ipv6_payload_len as usize],
                // )
                // .map_err(|_| HIPError::Bufferistooshort)?;
                // ipv6_packet.set_version(IPV6_VERSION as u8);
                // ipv6_packet.set_dst_addr(dst);
                // ipv6_packet.set_src_addr(src);
                // ipv6_packet.set_next_header(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                // ipv6_packet.set_hop_limit(1);
                // ipv6_packet.set_payload_len(ipv6_payload_len);

                // Compute and set HIP checksum
                let checksum = Utils::hip_ipv4_checksum(
                    &src.0,
                    &dst.0,
                    protocol,
                    ipv4_payload_len,
                    &hip_i2_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );
                hip_i2_packet.packet.set_checksum(checksum);
                ipv4_packet.payload_mut().copy_from_slice(
                    &hip_i2_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );

                // hex formatted string of dst IPv6 address
                let dst_str = Utils::hex_formatted_hit_bytes(Some(&dst.0), None)?;
                if let HeaplessStringTypes::U32(val) = dst_str {
                    hip_debug!(
                        "Sending I2 packet to {:?}, bytes sent {:?}",
                        val,
                        &ipv4_packet.total_len()
                    );
                }

                if hip_socket.can_send() {
                    hip_socket.send_slice(ipv4_packet.as_ref());
                } else {
                    hip_trace!("failed to send I2 packet");
                }

                if is_hit_smaller {
                    let sv = self.state_vars_map.get_mut(&rhit, &ihit)?;
                    sv.map(|s| match s.i2_packet {
                        None => {
                            s.i2_packet = Some(I2Pkt {
                                buffer: ipv4_buffer,
                                len: ipv4_payload_len,
                            });
                        }
                        Some(val) => todo!(),
                    });
                } else {
                    let sv = self.state_vars_map.get_mut(&ihit, &rhit)?;
                    sv.map(|s| match s.i2_packet {
                        None => {
                            s.i2_packet = Some(I2Pkt {
                                buffer: ipv4_buffer,
                                len: ipv4_payload_len,
                            });
                        }
                        Some(val) => todo!(),
                    });
                }

                if hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_i1_sent()
                    || hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_closing()
                    || hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_closed()
                {
                    hip_state = hip_state.map(|s| s.i2_sent());
                    // Update HIP StateMachine
                    let mut old_hip_state = self.hip_state_machine.get_mut(&rhit, &ihit)?;
                    match (&mut old_hip_state, hip_state) {
                        (Some(old_state), Some(new_state)) => **old_state = new_state,
                        (_, _) => {
                            hip_debug!(
                                "Invalid states reached, prev: {:?}, new: {:?}",
                                old_hip_state,
                                hip_state
                            );
                            return Err(HIPError::InvalidState);
                        }
                    }
                }
            }

            HIP_I2_PACKET => {
                hip_debug!("Received I2 packet");

                let mut solution_param = None;
                let mut r1_counter_param = None;
                let mut esp_transform_param = None;
                let mut esp_info_param = None;
                let mut dh_param = None;
                let mut cipher_param = None;
                let mut hi_param = None;
                let mut transport_param = None;
                let mut echo_signed = None;
                let mut mac_param = None;
                let mut signature_param = None;
                let mut responder_pubkey256 = Some(Ok([0; 64]));
                let mut responder_pubkey384 = Some(Ok([0; 96]));
                // let mut echo_request_unisgned_opaque_data = None;
                let mut iv_length = 0;
                let mut encrypted_param = None;
                let mut initiators_spi = None;
                let mut initiators_keymat_index = None;

                let mut parameters = hip_packet.get_parameters();

                // Construct R1 packet
                let mut hip_i2_packet = I2Packet::<[u8; 1024]>::new_i2packet().unwrap();
                hip_i2_packet
                    .packet
                    .set_senders_hit(&hip_packet.get_senders_hit());
                hip_i2_packet
                    .packet
                    .set_receivers_hit(&hip_packet.get_receivers_hit());                
                hip_i2_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_i2_packet.packet.set_version(HIP_VERSION as u8);

                let rhash = HIT::get_responders_hash_alg(&ihit);
                let rhash_len = match &rhash {
                    DigestTypes::SHA256(h) => SHA256Digest::get_length(),
                    DigestTypes::SHA384(h) => SHA384Digest::get_length(),
                    _ => return Err(HIPError::__Nonexhaustive),
                };

                let param_list = parameters.ok_or_else(|| HIPError::FieldNotSet)?;
                param_list.iter().for_each(|param| match param {
                    HIPParamsTypes::ESPInfoParam(val) => {
                        hip_debug!("ESP Info parameter");
                        esp_info_param = Some(val);
                    }
                    HIPParamsTypes::R1Counter(val) => {
                        hip_debug!("R1 Counter parameter");
                        r1_counter_param = Some(val);
                    }
                    HIPParamsTypes::SolutionParam(val) => {
                        hip_debug!("Solution parameter");
                        solution_param = Some(val);
                    }
                    HIPParamsTypes::DHParam(val) => {
                        hip_debug!("DH parameter");
                        dh_param = Some(val);
                    }
                    HIPParamsTypes::EncryptedParam(val) => {
                        hip_debug!("Encrypyted parameter");
                        encrypted_param = Some(val);
                    }
                    HIPParamsTypes::HostIdParam(val) => {
                        hip_debug!("Host ID");
                        hi_param = Some(val);
                        if Some(hi_param.map(|param| param.get_algorithm()))
                            == Some(Some(Ok(0x7 as u16)))
                        {
                            let responder_hi = hi_param.map(|param| param.get_host_id());
                            let oga = HIT::get_responders_oga_id(&ihit);
                            hip_debug!("Responder's OGA ID {:?}", oga);
                            hip_debug!("Responder HI: {:?}", responder_hi);
                            let hi = match responder_hi {
                                Some(Ok(val)) => val,
                                _ => {
                                    hip_debug!("HostID missing");
                                    &[]
                                }
                            };
                            match hi[0..2] {
                                [0, 1] => {
                                    let responders_hit = HIT::compute_hit::<82>(hi, oga);
                                    hip_debug!("Responder's computed HIT: {:?}", responders_hit);
                                    hip_debug!("Initiator's actual HIT: {:?}", &ihit);
                                    hip_debug!("own HIT: {:?}", self.hit_as_bytes);
                                    if !Utils::hits_equal(&ihit, &responders_hit) {
                                        hip_trace!("Invalid HIT");
                                        panic!(
                                            "Invalid HIT {:?}, responder_hit: {:?}",
                                            &ihit, &responders_hit
                                        );
                                    }
                                }
                                [0, 2] => {
                                    let responders_hit = HIT::compute_hit::<114>(hi, oga);
                                    hip_debug!("Responder's computed HIT: {:?}", responders_hit);
                                    hip_debug!("Initiator's actual HIT: {:?}", &ihit);
                                    hip_debug!("own HIT: {:?}", self.hit_as_bytes);
                                    if !Utils::hits_equal(&ihit, &responders_hit) {
                                        hip_trace!("Invalid HIT");
                                        panic!(
                                            "Invalid HIT {:?}, responder_hit: {:?}",
                                            &ihit, &responders_hit
                                        );
                                    }
                                }
                                _ => unimplemented!(),
                            }
                            // Extract publickey from HostId
                            match hi[0..2] {
                                [0, 1] => {
                                    responder_pubkey256 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
                                    responder_pubkey384 = None;
                                }
                                [0, 2] => {
                                    responder_pubkey384 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
                                    responder_pubkey256 = None;
                                }
                                _ => unimplemented!(),
                            }
                            // Save responder pubkey to the pubkey_map
                            match (responder_pubkey256, responder_pubkey384) {
                                (Some(val), None) => {
                                    if let Ok(val) = val {
                                        self.pubkey_map.save(
                                            &ihit,
                                            &rhit,
                                            ResponderPubKey::Pk256(val),
                                        );
                                    }
                                }
                                (None, Some(val)) => {
                                    if let Ok(val) = val {
                                        self.pubkey_map.save(
                                            &ihit,
                                            &rhit,
                                            ResponderPubKey::Pk384(val),
                                        );
                                    }
                                }
                                (_, _) => unimplemented!(),
                            };
                        }
                    }
                    HIPParamsTypes::TransportListParam(val) => {
                        hip_debug!("Transport parameter");
                        hip_debug!("Transport formats: {:?}", val.get_transport_formats());
                        transport_param = Some(val);
                    }
                    HIPParamsTypes::SignatureParam(val) => {
                        hip_debug!("Signature parameter");
                        signature_param = Some(val);
                    }
                    HIPParamsTypes::CipherParam(val) => {
                        hip_debug!("Cipher parameter");
                        cipher_param = Some(val);
                    }
                    HIPParamsTypes::ESPTransformParam(val) => {
                        hip_debug!("ESP Transform parameter");
                        esp_transform_param = Some(val);
                    }
                    HIPParamsTypes::MACParam(val) => {
                        hip_debug!("Cipher Parameter");
                        mac_param = Some(val);
                    }
                    HIPParamsTypes::EchoResponseSignedParam(val) => {
                        hip_debug!("ESP Transform Parameter");
                        echo_signed = Some(val);
                    }
                    _ => (),
                });

                // Check if any of the mandatory parameters are missing.
                if solution_param.is_none() {
                    hip_trace!("Solution Parameter not sent");
                } else if dh_param.is_none() {
                    hip_trace!("DH Parameter not sent");
                } else if cipher_param.is_none() {
                    hip_trace!("Cipher Parameter not sent");
                } else if hi_param.is_none() {
                    hip_trace!("Host ID Parameter not sent");
                } else if mac_param.is_none() {
                    hip_trace!("MAC Parameter not sent");
                } else if esp_info_param.is_none() {
                    hip_trace!("ESP Info Parameter not sent");
                } else if transport_param.is_none() {
                    hip_trace!("Transport Parameter not sent");
                } else if signature_param.is_none() {
                    hip_trace!("Signature Parameter not sent");
                }

                let oga_id = HIT::get_responders_oga_id(&rhit);
                let oga = oga_id << 4;
                match oga_id {
                    0x10 | 0x20 | 0x30 => {}
                    _ => {
                        hip_debug!("Unsupported HIT suit");
                        hip_debug!("OGA {:?}", oga_id);
                        hip_debug!("supported_hit_suits: {:?}", [0x10, 0x20, 0x30]);
                    }
                }

                let is_hit_smaller = Utils::is_hit_smaller(&rhit, &ihit);
                if hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_i2_sent() {
                    if is_hit_smaller {
                        hip_debug!("Dropping I2 packet");
                    }
                }

                let jrandom = solution_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_solution()?;
                let irandom = solution_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_random()?;

                let mut i = [0u8; 32];
                let mut j = [0u8; 32];
                let mut solver = PuzzleSolver(&mut i, &mut j);
                if !solver.verify_puzzle(
                    irandom,
                    jrandom,
                    &hip_packet.get_senders_hit(),
                    &hip_packet.get_receivers_hit(),
                    solution_param.unwrap().get_k_value()? as usize,
                    &rhash,
                ) {
                    hip_debug!("Puzzle was not verified");
                }

                hip_debug!("Puzzle was verified");

                // Get DH secret keys from dh_map
                let mut dh_alg_id = 0;
                let mut sk_i256 = None;
                let mut sk_i384 = None;

                if is_hit_smaller {
                    let temp = self.dh_map.get(&rhit, &ihit)?;
                    match temp {
                        Some(val) => match val {
                            InitiatorDHKeys::EcdhP256(sk256, pk256) => {
                                dh_alg_id = 0x7;
                                sk_i256 = Some(sk256)
                            }
                            InitiatorDHKeys::EcdhP384(sk384, pk384) => {
                                dh_alg_id = 0x8;
                                sk_i384 = Some(sk384)
                            }
                            _ => unimplemented!(),
                        },
                        None => todo!(),
                    }
                } else {
                    let temp = self.dh_map.get(&ihit, &rhit)?;
                    match temp {
                        Some(val) => match val {
                            InitiatorDHKeys::EcdhP256(sk256, pk256) => {
                                dh_alg_id = 0x7;
                                sk_i256 = Some(sk256)
                            }
                            InitiatorDHKeys::EcdhP384(sk384, pk384) => {
                                dh_alg_id = 0x8;
                                sk_i384 = Some(sk384)
                            }
                            _ => unimplemented!(),
                        },
                        None => todo!(),
                    }
                }

                // Get responder public key and compute shared_secret
                let pubkey_r = dh_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_public_value()?;
                let (ss256, ss384) = match (sk_i256, sk_i384) {
                    (Some(sk), None) => {
                        let ss256 = ECDHNISTP256::generate_shared_secret(
                            &sk,
                            &PkP256::from_bytes(pubkey_r)?,
                        )?;
                        (Some(ss256), None)
                    }
                    (None, Some(sk)) => {
                        let ss384 = ECDHNISTP384::<48>::generate_shared_secret(
                            &sk,
                            &PkP384::from_bytes(pubkey_r)?,
                        )?;
                        (None, Some(ss384))
                    }
                    _ => unimplemented!(),
                };
                if ss256.is_some() {
                    hip_debug!("Secret key {:?}", ss256);
                } else if ss384.is_some() {
                    hip_debug!("Secret key {:?}", ss384);
                }

                // A 64 byte salt for the HBKDF from the concatenated irandom + jrandom values
                let info = Utils::sort_hits(&ihit, &rhit);
                let mut salt_buffer = [0; 64];
                let salt = irandom
                    .iter()
                    .chain(jrandom.iter())
                    .enumerate()
                    .for_each(|(i, x)| salt_buffer[i] = *x);

                let hmac_alg = HIT::get_responders_oga_id(&ihit);

                // Construct a keyinfo value
                let key_info = KeyInfo {
                    info,
                    salt: salt_buffer,
                    alg_id: dh_alg_id,
                };

                // Save to key_info map.
                if is_hit_smaller {
                    self.key_info_map.save(&rhit, &ihit, key_info);
                } else {
                    self.key_info_map.save(&ihit, &rhit, key_info);
                }

                // Select a cipher from the list of advertised/offered ciphers
                let offered_ciphers = cipher_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_ciphers()?;
                let supported_ciphers = [0x4, 0x2, 0x1]; // NULL (0x1), AES128CBC (0x2), AES256CBC (0x4)
                let mut selected_cipher = None;

                for (idx, group_id) in offered_ciphers.iter().enumerate() {
                    if supported_ciphers.contains(group_id) {
                        selected_cipher = Some(offered_ciphers[idx]);
                        break;
                    }
                }
                if selected_cipher.is_none() {
                    hip_trace!("Unsupported cipher");
                    return Err(HIPError::Unrecognized);
                }

                // Save to the cipher map.
                if is_hit_smaller {
                    self.cipher_map.save(&rhit, &ihit, selected_cipher);
                } else {
                    self.cipher_map.save(&ihit, &rhit, selected_cipher);
                }

                // HIP ESP Transform Parameter
                if esp_transform_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .get_esp_suits()?
                    .is_empty()
                {
                    hip_debug!("ESP transform suit was not negotiated.");
                    return Err(HIPError::FieldNotSet);
                }

                let selected_esp_transform = esp_transform_param.unwrap().get_esp_suits()?[0];

                initiators_spi = Some(
                    esp_info_param
                        .ok_or_else(|| HIPError::FieldNotSet)?
                        .get_new_spi()?,
                );
                initiators_keymat_index = Some(
                    esp_info_param
                        .ok_or_else(|| HIPError::FieldNotSet)?
                        .get_keymat_index()?,
                );

                // Output from kdf function i.e. key-material
                // Note - you only need the first keymat_len_octet bytes from the output
                let mut keymat = [0; 800];
                let keymat_len_octets = Utils::compute_keymat_len(
                    hmac_alg,
                    selected_cipher.ok_or_else(|| HIPError::FieldNotSet)?,
                );

                if ss256.is_some() {
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss256.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss384.is_some() {
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss384.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss256.is_none() && ss384.is_none() {
                    return Err(HIPError::FieldNotSet);
                }

                // Save to keymat map.
                if is_hit_smaller {
                    self.keymat_map.save(&rhit, &ihit, keymat);
                } else {
                    self.keymat_map.save(&ihit, &rhit, keymat);
                }

                // Encrypted Parameter processing
                if encrypted_param.is_some() {
                    let (aes_key, hmac_key) =
                        Utils::get_keys(&keymat, hmac_alg, selected_cipher.unwrap(), &ihit, &rhit)?;
                    let cipher = SymmetricCiphersFactory::get(
                        selected_cipher.ok_or_else(|| HIPError::FieldNotSet)?,
                    );
                    let (aes128, aes256) = match cipher {
                        CipherTypes::AES128(val) => {
                            iv_length = 0x10;
                            (Some(val), None)
                        } // AES-128 and AES-256 have a block-size of 16 bytes
                        CipherTypes::AES256(val) => {
                            iv_length = 0x10;
                            (None, Some(val))
                        } // iv_length in both cases is 16
                        _ => unimplemented!(),
                    };
                    let iv = encrypted_param
                        .ok_or_else(|| HIPError::FieldNotSet)?
                        .get_iv(iv_length)?;
                    let data = encrypted_param
                        .ok_or_else(|| HIPError::FieldNotSet)?
                        .get_encrypted_data(iv_length)?;
                    let data_len = data.len();
                    let host_id_data = match (aes128, aes256) {
                        (Some(aes128), None) => aes128.decrypt(aes_key, iv, data),
                        (None, Some(aes256)) => aes256.decrypt(aes_key, iv, data),
                        _ => unimplemented!(),
                    };

                    // decrypted host_id_param_data
                    let hi_param = HostIdParameter::new_checked(&host_id_data[..data_len])?;

                    if hi_param.get_algorithm()? == 0x7 {
                        let responder_hi = hi_param.get_host_id();
                        let oga = HIT::get_responders_oga_id(&ihit);
                        hip_debug!("Responder's OGA ID {:?}", oga);
                        hip_debug!("Responder HI: {:?}", responder_hi);
                        let hi = match responder_hi {
                            Ok(val) => val,
                            _ => {
                                hip_debug!("HostID missing");
                                &[]
                            }
                        };
                        match hi[0..2] {
                            [0, 1] => {
                                let responders_hit = HIT::compute_hit::<80>(hi, oga);
                                hip_debug!("Responder's HIT: {:?}", responders_hit);
                                hip_debug!("Initiator's HIT: {:?}", &ihit);
                                hip_debug!("HIPDaemon's HIT: {:?}", self.hit_as_bytes);
                                if !Utils::hits_equal(&ihit, &responders_hit) {
                                    hip_trace!("Invalid HIT");
                                    panic!(
                                        "Invalid HIT {:?}, responder_hit: {:?}",
                                        &ihit, &responders_hit
                                    );
                                }
                            }
                            [0, 2] => {
                                let responders_hit = HIT::compute_hit::<112>(hi, oga);
                                hip_debug!("Responder's HIT: {:?}", responders_hit);
                                hip_debug!("Initiator's HIT: {:?}", &ihit);
                                hip_debug!("HIPDaemon's HIT: {:?}", self.hit_as_bytes);
                                if !Utils::hits_equal(&ihit, &responders_hit) {
                                    hip_trace!("Invalid HIT");
                                    panic!(
                                        "Invalid HIT {:?}, responder_hit: {:?}",
                                        &ihit, &responders_hit
                                    );
                                }
                            }
                            _ => {
                                hip_debug!("Invalid remote Host Identity");
                                unimplemented!()
                            }
                        }

                        // Extract publickey from HostId
                        match hi[0..2] {
                            [0, 1] => {
                                responder_pubkey256 =
                                    Some(hi[2..].try_into().map_err(|_| HIPError::IncorrectLength));
                                // responder_pubkey256 = Err(HIP);
                            }
                            [0, 2] => {
                                responder_pubkey384 =
                                    Some(hi[2..].try_into().map_err(|_| HIPError::IncorrectLength));
                            }
                            _ => {
                                hip_debug!("Invalid remote Host Identity");
                                unimplemented!()
                            }
                        }
                    }
                }

                // Fill out an I2 packet
                let mut hip_i2_packet = I2Packet::<[u8; 1024]>::new_i2packet()?;
                hip_i2_packet.packet.set_senders_hit(&rhit);
                hip_i2_packet.packet.set_receivers_hit(&ihit);
                hip_i2_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_i2_packet.packet.set_version(HIP_VERSION as u8);

                // Compute HMAC
                let mut param_buf: Vec<u8, U512> = Vec::new();
                match (r1_counter_param, echo_signed) {
                    (Some(r1), Some(echo_signed)) => {
                        for byte in option_as_ref(esp_info_param)?
                            .iter()
                            .chain(r1.inner_ref().as_ref().iter())
                            .chain(option_as_ref(solution_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(option_as_ref(transport_param)?.iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort);
                        }
                    }
                    (Some(r1), None) => {
                        for byte in option_as_ref(esp_info_param)?
                            .iter()
                            .chain(r1.inner_ref().as_ref().iter())
                            .chain(option_as_ref(solution_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(transport_param)?.iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort);
                        }
                    }
                    (None, Some(echo_signed)) => {
                        for byte in option_as_ref(esp_info_param)?
                            .iter()
                            .chain(option_as_ref(solution_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(option_as_ref(transport_param)?.iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort);
                        }
                    }
                    (None, None) => {
                        for byte in option_as_ref(esp_info_param)?
                            .iter()
                            .chain(option_as_ref(solution_param)?.iter())
                            .chain(option_as_ref(dh_param)?.iter())
                            .chain(option_as_ref(cipher_param)?.iter())
                            .chain(option_as_ref(esp_transform_param)?.iter())
                            .chain(option_as_ref(hi_param)?.iter())
                            .chain(option_as_ref(transport_param)?.iter())
                        {
                            param_buf
                                .push(*byte)
                                .map_err(|_| HIPError::Bufferistooshort);
                        }
                    }
                }

                let current_r1pkt_len = hip_i2_packet.packet.get_header_length();
                let pkt_len = 8 * (1 + current_r1pkt_len as usize) + &param_buf.len();
                hip_i2_packet.packet.set_header_length((pkt_len / 8) as u8);
                let mut hmac_bytes: Vec<u8, U512> = Vec::new();
                for byte in hip_i2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                    .iter()
                    .chain(param_buf[..].iter())
                {
                    hmac_bytes
                        .push(*byte)
                        .map_err(|_| HIPError::Bufferistooshort)?;
                }

                let (aes_key, hmac_key) = Utils::get_keys(
                    &keymat[..keymat_len_octets as usize],
                    hmac_alg,
                    selected_cipher.unwrap(),
                    &rhit,
                    &ihit,
                )?;
                let hmac = HMACFactory::get(hmac_alg);

                match hmac {
                    HMACTypes::HMAC256(mac) => {
                        if SHA256HMAC::hmac_256(&hmac_bytes[..], hmac_key)
                            != mac_param.ok_or_else(|| HIPError::FieldNotSet)?.get_hmac()?
                        {
                            hip_debug!("Invalid HMAC. Dropping the packet");
                        }
                    }
                    HMACTypes::HMAC384(mac) => {
                        if SHA384HMAC::hmac_384(&hmac_bytes[..], hmac_key)
                            != mac_param.ok_or_else(|| HIPError::FieldNotSet)?.get_hmac()?
                        {
                            hip_debug!("Invalid HMAC. Dropping the packet");
                        }
                    }
                    _ => unimplemented!(),
                }

                // Verify signature of I2 Packet
                let current_r1pkt_len = hip_i2_packet.packet.get_header_length();
                let pkt_len = current_r1pkt_len as usize * 8 + &param_buf.len();
                hip_i2_packet.packet.set_header_length((pkt_len / 8) as u8);
                let mut bytes_to_verify: Vec<u8, U512> = Vec::new();
                for byte in hip_i2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                    .iter()
                    .chain(param_buf[..].iter())
                {
                    bytes_to_verify
                        .push(*byte)
                        .map_err(|_| HIPError::Bufferistooshort)?;
                }

                match (responder_pubkey256, responder_pubkey384) {
                    (Some(val), None) => {
                        if let Ok(pubkey_256) = val {
                            let verifier = ECDSASHA256Signature([0; 32], pubkey_256);
                            let verified = verifier.verify(
                                &bytes_to_verify[..],
                                signature_param
                                    .ok_or_else(|| HIPError::SignatureError)?
                                    .inner_ref()
                                    .as_ref(),
                            );
                            if !verified? {
                                hip_trace!("Invalid signature in R1 packet. Dropping the packet");
                            } else {
                                hip_debug!("Signature is correct");
                            }
                        }
                    }
                    (None, Some(val)) => {
                        if let Ok(pubkey_384) = val {
                            let verifier = ECDSASHA384Signature(
                                [0; 48],
                                EncodedPointP384::from_bytes(pubkey_384)
                                    .map_err(|_| HIPError::InvalidEncoding)?,
                            );
                            let verified = verifier.verify(
                                &bytes_to_verify[..],
                                signature_param
                                    .ok_or_else(|| HIPError::SignatureError)?
                                    .inner_ref()
                                    .as_ref(),
                            );
                            if !verified? {
                                hip_trace!("Invalid signature in R1 packet. Dropping the packet");
                            } else {
                                hip_debug!("Signature is correct");
                            }
                        }
                    }
                    (_, _) => unimplemented!(),
                }

                hip_debug!("Processing I2 packet");

                // Construct a new R2 Packet
                let mut hip_r2_packet = R2Packet::<[u8; 512]>::new_r2packet()?;
                hip_r2_packet.packet.set_senders_hit(&rhit);
                hip_r2_packet.packet.set_receivers_hit(&ihit);
                hip_r2_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_r2_packet.packet.set_version(HIP_VERSION as u8);

                let keymat_index = Utils::compute_hip_keymat_len(
                    hmac_alg,
                    selected_cipher.ok_or_else(|| HIPError::FieldNotSet)?,
                );
                let responder_spi = getrandom::<4>([12; 32]);

                if initiators_keymat_index != Some(keymat_index as u16) {
                    hip_trace!("Keymat index should match....");
                    return Err(HIPError::IncorrectLength);
                }

                let mut esp_info_param = ESPInfoParameter::new_checked([0; 16])?;
                esp_info_param.init_espinfoparameter_param();
                esp_info_param.set_keymat_index(keymat_index as u16);
                esp_info_param.set_new_spi(u32::from_be_bytes(responder_spi));

                hip_r2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(
                    &esp_info_param,
                )?));
                let (aes_key, hmac_key) = Utils::get_keys(
                    &keymat[..keymat_len_octets as usize],
                    hmac_alg,
                    selected_cipher.unwrap(),
                    &ihit,
                    &rhit,
                )?;
                let hmac = HMACFactory::get(hmac_alg);

                // HIP Mac2 Parameter
                let (mut mac2_256_param, mut mac2_384_param) = match hmac_alg {
                    0x1 => {
                        let mut mac2_param = MAC2Parameter::new_checked([0; 32 + 4])?;
                        mac2_param.init_mac2paramter_param();
                        (Some(mac2_param), None)
                    }
                    0x2 => {
                        let mut mac2_param = MAC2Parameter::new_checked([0; 48 + 4])?;
                        mac2_param.init_mac2paramter_param();
                        (None, Some(mac2_param))
                    }
                    _ => unimplemented!(),
                };

                let byte_len = hip_r2_packet.packet.get_header_length() * 8 + 8;
                if mac2_256_param.is_some() {
                    mac2_256_param.unwrap().set_hmac2(&SHA256HMAC::hmac_256(
                        &hip_r2_packet.inner_ref().as_ref()[..byte_len as usize],
                        hmac_key,
                    ));
                } else if mac2_384_param.is_some() {
                    mac2_384_param.unwrap().set_hmac2(&SHA384HMAC::hmac_384(
                        &hip_r2_packet.inner_ref().as_ref()[..byte_len as usize],
                        hmac_key,
                    ));
                }

                // Compute Signature
                // Get signer_tuple - i.e. Signature2 Parameter AND ECDSA Signature type
                let signer_tuple = match self.privkey {
                    Some(val) if val.len() == 0x20 => {
                        let mut signature_param = Signature2Parameter::new_checked([0; 72])?;
                        signature_param.init_signature2parameter_param();
                        let signer = ECDSASHA256Signature([0; 32], [0; 64]);
                        (Some((signature_param, signer)), None)
                    }
                    Some(val) if val.len() == 0x30 => {
                        let mut signature_param = Signature2Parameter::new_checked([0; 104])?;
                        signature_param.init_signature2parameter_param();
                        let signer = ECDSASHA384Signature([0; 48], EncodedPointP384::identity());
                        (None, Some((signature_param, signer)))
                    }
                    Some(_) => unimplemented!(),
                    None => unreachable!(),
                };

                // Get data to be signed
                let data_tobe_signed: Result<Vec<u8, _>> = match (mac2_256_param, mac2_384_param) {
                    (Some(mac2_256_param), None) => {
                        let mut s: Vec<u8, U512> = Vec::new();
                        for byte in hip_r2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                            .iter()
                            .chain(mac2_256_param.inner_ref().as_ref().iter())
                        {
                            s.push(*byte).map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        let current_r2pkt_len = hip_r2_packet.packet.get_header_length();
                        let pkt_len = current_r1pkt_len as usize * 8
                            + mac2_256_param.inner_ref().as_ref().len();
                        hip_r2_packet.packet.set_header_length((pkt_len / 8) as u8);
                        Ok(s)
                    }
                    (None, Some(mac2_384_param)) => {
                        let mut s: Vec<u8, U512> = Vec::new();
                        for byte in hip_r2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                            .iter()
                            .chain(mac2_384_param.inner_ref().as_ref().iter())
                        {
                            s.push(*byte).map_err(|_| HIPError::Bufferistooshort)?;
                        }
                        let current_r2pkt_len = hip_r2_packet.packet.get_header_length();
                        let pkt_len = current_r1pkt_len as usize * 8
                            + mac2_384_param.inner_ref().as_ref().len();
                        hip_r2_packet.packet.set_header_length((pkt_len / 8) as u8);
                        Ok(s)
                    }
                    (_, _) => unimplemented!(),
                };

                let signature_param = match signer_tuple {
                    (Some((mut signature_param, signer)), None) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        signature_param.set_signature_algorithm_2(0x7);
                        signature_param.set_signature_2(&signature?[..]);
                        (
                            HIPParamsTypes::Signature2Param(signature_param),
                            HIPParamsTypes::Default,
                        )
                    }
                    (None, Some((mut signature_param, signer))) => {
                        let signature = signer.sign(&data_tobe_signed?[..]);
                        signature_param.set_signature_algorithm_2(0x7);
                        signature_param.set_signature_2(&signature?[..]);
                        (
                            HIPParamsTypes::Default,
                            HIPParamsTypes::Signature2Param(signature_param),
                        )
                    }
                    (_, _) => unimplemented!(),
                };

                #[rustfmt::skip]
                match (signature_param, mac2_256_param) {
                    ((HIPParamsTypes::Signature2Param(s256), HIPParamsTypes::Default),// 
                        Some(mac2_256_param))  => {
                        hip_r2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                        hip_r2_packet.add_param(HIPParamsTypes::MAC2Param(MAC2Parameter::fromtype(&mac2_256_param)?));
                        hip_r2_packet.add_param(HIPParamsTypes::Signature2Param(Signature2Parameter::fromtype(&s256)?));
                    },
                    ((HIPParamsTypes::Signature2Param(s384), HIPParamsTypes::Default),// 
                        Some(mac2_384_param))  => {
                        hip_r2_packet.add_param(HIPParamsTypes::ESPInfoParam(ESPInfoParameter::fromtype(&esp_info_param)?));
                        hip_r2_packet.add_param(HIPParamsTypes::MAC2Param(MAC2Parameter::fromtype(&mac2_384_param)?));
                        hip_r2_packet.add_param(HIPParamsTypes::Signature2Param(Signature2Parameter::fromtype(&s384)?));
                    }
                    _ => unimplemented!(),
                }

                // Swap src & dst IPv6 addresses
                core::mem::swap(&mut src, &mut dst);

                // Construct IPv4 packet
                let ipv4_payload_len = (1 + hip_r2_packet.packet.get_header_length() as u16) * 8;
                let ipv4_fixed_header_len = 0x14u8;
                let mut ipv4_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                let mut ipv4_packet = Ipv4Packet::new_checked(
                    &mut ipv4_buffer[..ipv4_fixed_header_len as usize + ipv4_payload_len as usize],
                )
                .map_err(|_| HIPError::Bufferistooshort)?;
                ipv4_packet.set_version(IPV4_VERSION as u8);
                ipv4_packet.set_dst_addr(dst);
                ipv4_packet.set_src_addr(src);
                ipv4_packet.set_hop_limit(IPV4_DEFAULT_TTL as u8);
                ipv4_packet.set_protocol(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                ipv4_packet.set_header_len((IPV4_IHL_NO_OPTIONS * 4) as u8);
                ipv4_packet.set_total_len(ipv4_fixed_header_len as u16 + ipv4_payload_len);

                // // Construct IPv6 packet
                // let ipv6_payload_len = (hip_r2_packet.packet.get_header_length() * 8 + 8) as u16;
                // let ipv6_fixed_header_len = 0x28u8;
                // let mut ipv6_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                // let mut ipv6_packet = Ipv6Packet::new_checked(
                //     &mut ipv6_buffer[..ipv6_fixed_header_len as usize + ipv6_payload_len as usize],
                // )
                // .map_err(|_| HIPError::Bufferistooshort)?;
                // ipv6_packet.set_version(IPV6_VERSION as u8);
                // ipv6_packet.set_dst_addr(dst);
                // ipv6_packet.set_src_addr(src);
                // ipv6_packet.set_next_header(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                // ipv6_packet.set_hop_limit(1);
                // ipv6_packet.set_payload_len(ipv6_payload_len);

                // Compute and set HIP checksum
                let checksum = Utils::hip_ipv4_checksum(
                    &src.0,
                    &dst.0,
                    protocol,
                    ipv4_payload_len,
                    &hip_r2_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );
                hip_r2_packet.packet.set_checksum(checksum);
                ipv4_packet.payload_mut().copy_from_slice(
                    &hip_r2_packet.inner_ref().as_ref()[..ipv4_payload_len as usize],
                );

                // hex formatted string of dst IPv6 address
                let dst_str = Utils::hex_formatted_hit_bytes(Some(&dst.0), None)?;
                let src_str = Utils::hex_formatted_hit_bytes(Some(&src.0), None)?;

                hip_debug!("Current System state is {:?}", hip_state);
                if hip_state
                    .ok_or_else(|| HIPError::__Nonexhaustive)?
                    .is_established()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_unassociated()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_i1_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_i2_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_r2_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_closing()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_closed()
                {
                    hip_state = hip_state.map(|s| s.r2_sent());
                    if let HeaplessStringTypes::U32(val) = dst_str {
                        hip_debug!(
                            "Sending R2 packet to {:?}, bytes sent {:?}",
                            val,
                            &ipv4_packet.total_len()
                        );
                    }

                    if hip_socket.can_send() {
                        hip_socket.send_slice(ipv4_packet.as_ref());
                    } else {
                        hip_trace!("failed to send R2 packet");
                    }
                }

                hip_debug!("Setting SA records...");

                let (cipher, hmac) = ESPTransformFactory::get(selected_esp_transform);

                // Create a new SA record and save it to out sa_map
                match cipher {
                    CipherTypes::AES128(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index,
                            0x1, // hmac256 id
                            0x2, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev4(src.0),
                            SAData::Typev4(dst.0),
                        );
                        sa_record.set_spi(initiators_spi.ok_or_else(|| HIPError::__Nonexhaustive)?);
                        let key = Utils::hex_formatted_hit_bytes(Some(&rhit), Some(&ihit))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    CipherTypes::AES256(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index,
                            0x1, // hmac256 id
                            0x4, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev4(src.0),
                            SAData::Typev4(dst.0),
                        );
                        sa_record.set_spi(initiators_spi.ok_or_else(|| HIPError::__Nonexhaustive)?);
                        let key = Utils::hex_formatted_hit_bytes(Some(&rhit), Some(&ihit))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    _ => unimplemented!(),
                }

                // Save this extra record to the sa_map for debugging purposes
                match cipher {
                    CipherTypes::AES128(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index,
                            0x1, // hmac256 id
                            0x2, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev6(rhit),
                            SAData::Typev6(ihit),
                        );
                        sa_record.set_spi(initiators_spi.ok_or_else(|| HIPError::__Nonexhaustive)?);
                        let key = Utils::hex_formatted_hit_bytes(Some(&dst.0), Some(&src.0))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    CipherTypes::AES256(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index,
                            0x1, // hmac256 id
                            0x4, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev6(rhit),
                            SAData::Typev6(ihit),
                        );
                        sa_record.set_spi(initiators_spi.ok_or_else(|| HIPError::__Nonexhaustive)?);
                        let key = Utils::hex_formatted_hit_bytes(Some(&dst.0), Some(&src.0))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    _ => unimplemented!(),
                }

                if is_hit_smaller {
                    let sv = self.state_vars_map.get_mut(&rhit, &ihit)?;
                    sv.map(|s| {
                        s.ec_complete_timeout = Instant::now()
                            + Duration {
                                millis: (120 * 1000) as u64,
                            }
                    });
                } else {
                    let sv = self.state_vars_map.get_mut(&ihit, &rhit)?;
                    sv.map(|s| {
                        s.ec_complete_timeout = Instant::now()
                            + Duration {
                                millis: (120 * 1000) as u64,
                            }
                    });
                }
            }

            HIP_R2_PACKET => {
                if hip_state
                    .ok_or_else(|| HIPError::__Nonexhaustive)?
                    .is_unassociated()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_i1_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_r2_sent()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_established()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_closing()
                    || hip_state
                        .ok_or_else(|| HIPError::__Nonexhaustive)?
                        .is_closed()
                {
                    hip_debug!("Dropping the packet ");
                }

                hip_debug!("Got R2 Packet");

                let mut cipher_alg = 0;
                let mut keymat = [0u8; 800];
                let hmac_alg = HIT::get_responders_oga_id(&ihit);
                let is_hit_smaller = Utils::is_hit_smaller(&rhit, &ihit);

                if is_hit_smaller {
                    match self.cipher_map.get(&rhit, &ihit)? {
                        Some(val) => match val {
                            Some(val) => cipher_alg = *val,
                            None => {}
                        },
                        None => {}
                    }
                } else {
                    match self.cipher_map.get(&ihit, &rhit)? {
                        Some(val) => match val {
                            Some(val) => cipher_alg = *val,
                            None => {}
                        },
                        None => {}
                    }
                }

                if is_hit_smaller {
                    match self.keymat_map.get(&rhit, &ihit)? {
                        Some(val) => keymat = *val,
                        None => {}
                    }
                } else {
                    match self.keymat_map.get(&rhit, &ihit)? {
                        Some(val) => keymat = *val,
                        None => {}
                    }
                }

                let keymat_len_octets = Utils::compute_keymat_len(hmac_alg, cipher_alg);
                let (aes_key, hmac_key) = Utils::get_keys(
                    &keymat[..keymat_len_octets as usize],
                    hmac_alg,
                    cipher_alg,
                    &ihit,
                    &rhit,
                )?;

                let hmac = HMACFactory::get(hmac_alg);
                let param_list = hip_packet
                    .get_parameters()
                    .ok_or_else(|| HIPError::FieldNotSet)?;
                let mut esp_info_param = None;
                let mut hmac_param = None;
                let mut signature_param = None;

                // let initiators_spi = None;
                let mut responders_spi = None;
                let mut keymat_index = None;

                param_list.iter().for_each(|param| match param {
                    HIPParamsTypes::ESPInfoParam(val) => {
                        hip_debug!("ESP Info parameter");
                        esp_info_param = Some(val);
                    }
                    HIPParamsTypes::MAC2Param(val) => {
                        hip_debug!("Mac2 parameter");
                        hmac_param = Some(val);
                    }
                    HIPParamsTypes::Signature2Param(val) => {
                        hip_debug!("Signature2 parameter");
                        signature_param = Some(val);
                    }
                    _ => {}
                });

                // Check if any of the mandatory parameters are missing.
                if esp_info_param.is_none() {
                    hip_trace!("ESP Info Parameter not sent");
                } else if hmac_param.is_none() {
                    hip_trace!("MAC2 Parameter not sent");
                } else if signature_param.is_none() {
                    hip_trace!("Signature2 Parameter not sent");
                }

                // Construct a new R2 Packet
                let mut hip_r2_packet = R2Packet::<[u8; 512]>::new_r2packet()?;
                hip_r2_packet.packet.set_senders_hit(&rhit);
                hip_r2_packet.packet.set_receivers_hit(&ihit);
                hip_r2_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_r2_packet.packet.set_version(HIP_VERSION as u8);

                if let Some(val) = esp_info_param {
                    hip_r2_packet.add_param(HIPParamsTypes::ESPInfoParam(
                        ESPInfoParameter::fromtype(val)?,
                    ));
                }

                let byte_len = hip_r2_packet.packet.get_header_length() * 8 + 8;
                match hmac_alg {
                    0x1 => {
                        if &SHA256HMAC::hmac_256(
                            &hip_r2_packet.inner_ref().as_ref()[..byte_len as usize],
                            hmac_key,
                        ) != hmac_param
                            .ok_or_else(|| HIPError::FieldNotSet)?
                            .get_hmac2()?
                        {
                            hip_debug!("Invalid HMAC256. Dropping the packet");
                        }
                    }
                    0x2 => {
                        if &SHA384HMAC::hmac_384(
                            &hip_r2_packet.inner_ref().as_ref()[..byte_len as usize],
                            hmac_key,
                        ) != hmac_param
                            .ok_or_else(|| HIPError::FieldNotSet)?
                            .get_hmac2()?
                        {
                            hip_debug!("Invalid HMAC384. Dropping the packet");
                        }
                    }
                    _ => unimplemented!(),
                }

                hip_debug!("HMAC is ok. Compute signature");

                let hmac_param_len = hmac_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .inner_ref()
                    .as_ref()
                    .len();
                let hmac_param_bytes = hmac_param
                    .ok_or_else(|| HIPError::FieldNotSet)?
                    .inner_ref()
                    .as_ref();
                let current_r2pkt_len = hip_r2_packet.packet.get_header_length();
                let pkt_len = current_r2pkt_len as usize * 8 + hmac_param_len;
                hip_r2_packet.packet.set_header_length((pkt_len / 8) as u8);
                let mut bytes_to_verify: Vec<u8, U512> = Vec::new();
                for byte in hip_r2_packet.inner_ref().as_ref()[..HIP_HEADER_LENGTH]
                    .iter()
                    .chain(hmac_param_bytes.iter())
                {
                    bytes_to_verify
                        .push(*byte)
                        .map_err(|_| HIPError::Bufferistooshort)?;
                }

                let mut responder_pubkey256 = [0; 64];
                let mut responder_pubkey384 = [0; 96];

                let responder_pubkey = self.pubkey_map.get(&ihit, &rhit)?;
                // Get responder pubkey from our pubkey_map
                let pubkey_len = match responder_pubkey {
                    Some(val) => match val {
                        ResponderPubKey::Pk256(val) => {
                            responder_pubkey256 = *val;
                            0x20
                        }
                        ResponderPubKey::Pk384(val) => {
                            responder_pubkey384 = *val;
                            0x30
                        }
                    },
                    None => 0x0,
                };

                match pubkey_len {
                    0x20 => {
                        let verifier = ECDSASHA256Signature([0; 32], responder_pubkey256);
                        let verified =
                            verifier.verify(&bytes_to_verify[..], option_as_ref(signature_param)?);
                        if !verified? {
                            hip_trace!("Invalid signature in R2 packet. Dropping the packet");
                        } else {
                            hip_debug!("Signature is correct");
                        }
                    }
                    0x30 => {
                        let verifier = ECDSASHA384Signature(
                            [0; 48],
                            EncodedPointP384::from_bytes(responder_pubkey384)
                                .map_err(|_| HIPError::InvalidEncoding)?,
                        );
                        let verified =
                            verifier.verify(&bytes_to_verify[..], option_as_ref(signature_param)?);
                        if !verified? {
                            hip_trace!("Invalid signature in R2 packet. Dropping the packet");
                        } else {
                            hip_debug!("Signature is correct");
                        }
                    }
                    _ => unimplemented!(),
                }

                responders_spi = esp_info_param.map(|esp_info| esp_info.get_new_spi());
                keymat_index = esp_info_param.map(|esp_info| esp_info.get_keymat_index());

                hip_debug!("Processing R2 packet");
                hip_debug!("Ending HIP BEX");

                // hex formatted string of dst IPv6 address
                let dst_str = Utils::hex_formatted_hit_bytes(Some(&dst.0), None)?;
                let src_str = Utils::hex_formatted_hit_bytes(Some(&src.0), None)?;

                hip_debug!("Setting SA records...{:?} - {:?}", src_str, dst_str);

                let (cipher, hmac) = ESPTransformFactory::get(
                    self.selected_esp_transform
                        .ok_or_else(|| HIPError::InvalidState)?,
                );

                // Create a new SA record and save it to out sa_map
                match cipher {
                    CipherTypes::AES128(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index.ok_or_else(|| HIPError::IncorrectLength)?? as u8,
                            0x1, // hmac256 id
                            0x2, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev4(src.0),
                            SAData::Typev4(dst.0),
                        );
                        sa_record
                            .set_spi(responders_spi.ok_or_else(|| HIPError::__Nonexhaustive)??);
                        let key = Utils::hex_formatted_hit_bytes(Some(&rhit), Some(&ihit))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    CipherTypes::AES256(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index.ok_or_else(|| HIPError::IncorrectLength)?? as u8,
                            0x1, // hmac256 id
                            0x4, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev4(src.0),
                            SAData::Typev4(dst.0),
                        );
                        sa_record
                            .set_spi(responders_spi.ok_or_else(|| HIPError::__Nonexhaustive)??);
                        let key = Utils::hex_formatted_hit_bytes(Some(&rhit), Some(&ihit))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    _ => unimplemented!(),
                }

                // Save this extra record to the sa_map for debugging purposes
                match cipher {
                    CipherTypes::AES128(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index.ok_or_else(|| HIPError::IncorrectLength)?? as u8,
                            0x1, // hmac256 id
                            0x2, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev6(rhit),
                            SAData::Typev6(ihit),
                        );
                        sa_record
                            .set_spi(responders_spi.ok_or_else(|| HIPError::__Nonexhaustive)??);
                        let key = Utils::hex_formatted_hit_bytes(Some(&dst.0), Some(&src.0))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    CipherTypes::AES256(cipher) => {
                        let (aes_key, hmac_key) = Utils::get_keys_esp(
                            &keymat[..keymat_len_octets as usize],
                            keymat_index.ok_or_else(|| HIPError::IncorrectLength)?? as u8,
                            0x1, // hmac256 id
                            0x4, // aes128 id
                            &ihit,
                            &rhit,
                        )?;
                        let mut sa_record = SecurityAssociationRecord::new(
                            0x2,
                            0x1,
                            aes_key,
                            hmac_key,
                            SAData::Typev6(rhit),
                            SAData::Typev6(ihit),
                        );
                        sa_record
                            .set_spi(responders_spi.ok_or_else(|| HIPError::__Nonexhaustive)??);
                        let key = Utils::hex_formatted_hit_bytes(Some(&dst.0), Some(&src.0))?;
                        if let HeaplessStringTypes::U64(key) = key {
                            self.sa_map.add_record(key, sa_record);
                        }
                    }
                    _ => unimplemented!(),
                }

                // Transition to an Established state
                hip_state = hip_state.map(|state| state.established());

                if is_hit_smaller {
                    let sv = self.state_vars_map.get_mut(&rhit, &ihit)?;
                    sv.map(|s| {
                        s.data_timeout = Instant::now()
                            + Duration {
                                millis: (120 * 1000) as u64,
                            }
                    });
                } else {
                    let sv = self.state_vars_map.get_mut(&ihit, &rhit)?;
                    sv.map(|s| {
                        s.data_timeout = Instant::now()
                            + Duration {
                                millis: (120 * 1000) as u64,
                            }
                    });
                }
            }
            _ => todo!(),
        }
        Ok(())
    }

    /// A method to initiate an HIP connection. Typically, the use of this method indicates
    /// that this `HIPDaemon instance` is the initiator.
    ///
    /// This method constructs and sends an I1 Packet.
    /// For now, this does not include DNS resolution.
    pub fn initiate_hip_connection(
        &mut self,
        rhit: [u8; 16],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        mut hip_socket: SocketRef<RawSocket>,
    ) -> Result<()> {
        let ihit = self.hit_as_bytes;
        let mut hip_state = None;
        let is_hit_smaller = Utils::is_hit_smaller(&ihit, &rhit);

        // Get the key from the `hip_state_machine` and if it doesn't exist, add one.
        if is_hit_smaller {
            self.hip_state_machine.get(&rhit, &ihit)?.and_then(|state| {
                hip_state = Some(*state);
                hip_state
            });
        } else {
            self.hip_state_machine.get(&ihit, &rhit)?.and_then(|state| {
                hip_state = Some(*state);
                hip_state
            });
        }

        if hip_state
            .ok_or_else(|| HIPError::FieldNotSet)?
            .is_unassociated()
            || hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_closing()
            || hip_state.ok_or_else(|| HIPError::FieldNotSet)?.is_closed()
        {
            hip_debug!("HIP_STATE ==: {:?}", hip_state);
            hip_debug!("Starting HIP BEX");
            // hip_debug!("");

            // HIP DH Groups Parameter. An 11 packet with a 12-byte DH Groups parameter
            // i.e. we're only interested in 3 groups ECDHNIST384 (0x8), ECDHNIST256 (0x7), ECDHSECP160R1 (0xa)
            let mut dhgroups_param = DHGroupListParameter::new_checked([0; 16])?;
            dhgroups_param.init_dhgrouplist_param();
            dhgroups_param.set_groups(&[0x00, 0x7, 0x00, 0x8, 0x00, 0xa]);

            // Construct a new I1 Packet
            let mut hip_i1_packet = I1Packet::<[u8; 80]>::new_i1packet()?;
            hip_i1_packet.packet.set_senders_hit(&ihit);
            hip_i1_packet.packet.set_receivers_hit(&rhit);
            hip_i1_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
            hip_i1_packet.packet.set_version(HIP_VERSION as u8);
            hip_i1_packet.add_param(HIPParamsTypes::DHGroupListParam(
                DHGroupListParameter::fromtype(&dhgroups_param)?,
            ));

            let hip_pkt_size = (1 + hip_i1_packet.packet.get_header_length() as u16) * 8;
            let computed_checksum = Utils::hip_ipv4_checksum(
                &src_ip,
                &dst_ip,
                HIP_PROTOCOL as u8,
                hip_pkt_size,
                &hip_i1_packet.inner_ref().as_ref()[..hip_pkt_size as usize],
            );
            hip_i1_packet.packet.set_checksum(computed_checksum);

            // Construct an IPv4 packet
            let ipv4_fixed_header_len = 0x14u8;
            let mut ipv4_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
            let mut ipv4_packet = Ipv4Packet::new_checked(
                &mut ipv4_buffer[..ipv4_fixed_header_len as usize + hip_pkt_size as usize],
            )
            .map_err(|_| HIPError::Bufferistooshort)?;
            ipv4_packet.set_version(IPV4_VERSION as u8);
            ipv4_packet.set_dst_addr(Ipv4Address::from_bytes(&dst_ip));
            ipv4_packet.set_src_addr(Ipv4Address::from_bytes(&src_ip));
            ipv4_packet.set_hop_limit(IPV4_DEFAULT_TTL as u8);
            ipv4_packet.set_protocol(IpProtocol::Unknown(HIP_PROTOCOL as u8));
            ipv4_packet.set_header_len((IPV4_IHL_NO_OPTIONS * 4) as u8);
            ipv4_packet.set_total_len(ipv4_fixed_header_len as u16 + hip_pkt_size);
            ipv4_packet
                .payload_mut()
                .copy_from_slice(&hip_i1_packet.inner_ref().as_ref()[..hip_pkt_size as usize]);

            // // Construct an IPv6 packet
            // let ipv6_fixed_header_len = 0x28u8;
            // let mut ipv6_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
            // let mut ipv6_packet = Ipv6Packet::new_checked(
            //     &mut ipv6_buffer[..ipv6_fixed_header_len as usize + hip_pkt_size as usize],
            // )
            // .map_err(|_| HIPError::Bufferistooshort)?;
            // ipv6_packet.set_version(IPV6_VERSION as u8);
            // ipv6_packet.set_dst_addr(Ipv6Address::from_bytes(&dst_ip));
            // ipv6_packet.set_src_addr(Ipv6Address::from_bytes(&src_ip));
            // ipv6_packet.set_next_header(IpProtocol::Unknown(HIP_PROTOCOL as u8));
            // ipv6_packet.set_hop_limit(1);
            // ipv6_packet.set_payload_len(hip_pkt_size);
            // ipv6_packet
            //     .payload_mut()
            //     .copy_from_slice(&hip_i1_packet.inner_ref().as_ref()[..hip_pkt_size as usize]);

            hip_debug!("Sending I1 packet");
            if hip_socket.can_send() {
                hip_socket.send_slice(ipv4_packet.as_ref());
            } else {
                hip_trace!("failed to send I1 packet");
            }

            // Transition to an I1-Sent state
            hip_state = hip_state.map(|state| state.i1_sent());

            if is_hit_smaller {
                // Update HIP StateMachine
                let mut old_hip_state = self.hip_state_machine.get_mut(&rhit, &ihit)?;
                match (&mut old_hip_state, hip_state) {
                    (Some(old_state), Some(new_state)) => **old_state = new_state,
                    (_, _) => {
                        hip_debug!(
                            "Invalid states reached, prev: {:?}, new: {:?}",
                            old_hip_state,
                            hip_state
                        );
                        return Err(HIPError::InvalidState);
                    }
                }
                // Update State_Variables
                self.state_vars_map.save(
                    &rhit,
                    &ihit,
                    StateVariables::new(
                        hip_state.ok_or_else(|| HIPError::InvalidState)?,
                        &ihit,
                        &rhit,
                        &src_ip,
                        &dst_ip,
                        None,
                    ),
                );
                let sv = self.state_vars_map.get_mut(&rhit, &ihit)?;
                sv.map(|s| {
                    s.is_responder = false;
                    s.i1_retries += 1;
                    s.i1_timeout = Instant::now()
                        + Duration {
                            millis: (20 * 1000) as u64,
                        }
                });
            } else {
                let mut old_hip_state = self.hip_state_machine.get_mut(&ihit, &rhit)?;
                match (&mut old_hip_state, hip_state) {
                    (Some(old_state), Some(new_state)) => **old_state = new_state,
                    (_, _) => {
                        hip_debug!(
                            "Invalid states reached, prev: {:?}, new: {:?}",
                            old_hip_state,
                            hip_state
                        );
                        return Err(HIPError::InvalidState);
                    }
                }
                self.state_vars_map.save(
                    &ihit,
                    &rhit,
                    StateVariables::new(
                        hip_state.ok_or_else(|| HIPError::InvalidState)?,
                        &ihit,
                        &rhit,
                        &src_ip,
                        &dst_ip,
                        None,
                    ),
                );
                let sv = self.state_vars_map.get_mut(&ihit, &rhit)?;
                sv.map(|s| {
                    s.is_responder = false;
                    s.i1_retries += 1;
                    s.i1_timeout = Instant::now()
                        + Duration {
                            millis: (20 * 1000) as u64,
                        }
                });
            }
        }

        Ok(())
    }
}
