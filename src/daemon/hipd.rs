#![allow(warnings)]

use core::convert::TryInto;

use crate::storage::SecurityAssociations::{
    SARecordStore, SecurityAssociationDatabase, SecurityAssociationRecord,
};
use crate::{storage::HIPState::*, utils::puzzles};

use crate::crypto::{digest::*, ecdh::*, factory::*, signatures::*};
use crate::time::*;
use crate::utils::{hi::*, hit::*, misc::Utils, puzzles::*};
use crate::wire::constants::field::*;
use crate::wire::hip::*;
use crate::{HIPError, Result};

use elliptic_curve::{pkcs8, sec1::EncodedPoint as EncodedPointP384};
use generic_array::GenericArray;
use heapless::{consts::*, Vec};

// use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{IpProtocol, Ipv6Address, Ipv6Packet};

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
}

impl<'a> HIPDaemon<'a> {
    /// Construct a new HIP Daemon.
    pub fn new(
        state_store: &'a mut StateStore,
        keymat_store: &'a mut GenericValueStore<[u8; 800]>,
        dh_map: &'a mut GenericValueStore<InitiatorDHKeys>,
        cipher_map: &'a mut GenericValueStore<Option<u8>>,
        pubkey_map: &'a mut GenericValueStore<ResponderPubKey>,
        state_vars_map: &'a mut GenericValueStore<StateVariables>,
        key_info_map: &'a mut GenericValueStore<KeyInfo>,
        sa_map: &'a mut SARecordStore<'a>,
    ) -> Self {
        HIPDaemon {
            pubkey: None,
            privkey: None,
            hi: HostIdTypes::__Nonexhaustive,
            hit_as_hexstring: None,
            hit_as_bytes: [0; 16],
            hip_state_machine: StateMachine::new(state_store),
            keymat_map: Storage::new(keymat_store),
            dh_map: Storage::new(dh_map),
            cipher_map: Storage::new(cipher_map),
            pubkey_map: Storage::new(pubkey_map),
            state_vars_map: Storage::new(state_vars_map),
            key_info_map: Storage::new(key_info_map),
            sa_map: SecurityAssociationDatabase::new(sa_map),
        }
    }

    /// A method to process individual HIP packets `(I1, R1, I2, R2, UPDATE,
    /// NOTIFY, CLOSE)`
    ///
    /// For now, this method is a pretty huge monolith. Must see if we can split
    /// it into smaller chunks to improve readability.
    pub fn process_hip_packet(&mut self, ipv6_packet: Ipv6Packet<&[u8]>) -> Result<()> {
        let mut src = ipv6_packet.src_addr();
        let mut dst = ipv6_packet.dst_addr();

        // Sequence of checks
        // Check to see if the ipv6 packet's next header is correctly set to HIP
        // protocol identifier.
        let protocol = if let IpProtocol::Unknown(val) = ipv6_packet.next_header() {
            val
        } else {
            return Err(HIPError::Unrecognized);
        };

        if protocol as usize != HIP_PROTOCOL {
            hip_debug!("Invalid protocol type {:?}", protocol);
        }

        // All HIP packets are a multiple of 8 bytes.
        if ipv6_packet.payload().len() % 8 != 0 {
            hip_debug!("Invalid payload. HIP payload (i.e. packet) must be a multiple of 8 bytes");
        }

        let hip_packet = HIPPacket::new_checked(ipv6_packet.payload())?;
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

        // Check if the `responders HIT` equals our (i.e.initiator's) HIT or if its a
        // null HIT.
        if !Utils::hits_equal(&rhit, &self.hit_as_bytes) && !Utils::hits_equal(&rhit, &[0; 16]) {
            hip_trace!("We're good, Not our HIT");
            hip_trace!("{:?}", Utils::hex_formatted_hit_bytes(None, Some(&rhit)));
            hip_trace!(
                "{:?}",
                Utils::hex_formatted_hit_bytes(Some(&self.hit_as_bytes), None)
            );
        }

        let original_checksum = hip_packet.get_checksum();
        // hip_packet.set_checksum(0x0);
        let computed_checksum = Utils::hip_ipv4_checksum(
            &src.0,
            &dst.0,
            protocol,
            (hip_packet.get_header_length() * 8 + 8) as u16,
            ipv6_packet.payload(),
        );
        if original_checksum != computed_checksum {
            hip_trace!("Invalid checksum");
        }

        match hip_packet.get_packet_type() as usize {
            HIP_I1_PACKET => {
                hip_debug!("Received I1 Packet");

                if hip_state.ok_or_else(|| HIPError::Illegal)?.is_i1_sent()
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
                                .ok_or_else(|| HIPError::Illegal)?,
                            &ihit,
                            &rhit,
                            &src.0,
                            &dst.0,
                        ),
                    );
                } else {
                    self.state_vars_map.save(
                        &ihit,
                        &rhit,
                        StateVariables::new(
                            hip_state
                                .map(|state| state.get_state())
                                .ok_or_else(|| HIPError::Illegal)?,
                            &ihit,
                            &rhit,
                            &src.0,
                            &dst.0,
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
                let params = hip_packet
                    .get_parameters()
                    .ok_or_else(|| HIPError::FieldisNOTSet)?;
                let mut rec_dh_grouplist = None;
                params.iter().for_each(|param| {
                    if let HIPParamsTypes::DHGroupListParam(val) = *param {
                        rec_dh_grouplist = Some(val);
                    } else {
                        hip_debug!("DH groups parameter NOT found. Dropping I1 packet");
                        rec_dh_grouplist = None;
                    }
                });

                let dhlist_param = rec_dh_grouplist.ok_or_else(|| HIPError::FieldisNOTSet)?;
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
                        dh_param256.set_public_value_length(0x40); // pubkey len for ECDH256
                        dh_param256.set_public_value(&pk256.unwrap().to_bytes());
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
                        dh_param384.set_public_value_length(0x60); // pubkey len for ECDH384
                        dh_param384.set_public_value(&pk384.unwrap().to_bytes());
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
                        let mut signature_param = SignatureParameter::new_checked([0; 72])?;
                        let signer = ECDSASHA256Signature([0; 32], [0; 64]);
                        (Some((signature_param, signer)), None)
                    }
                    Some(val) if val.len() == 0x30 => {
                        let mut signature_param = SignatureParameter::new_checked([0; 104])?;
                        let signer = ECDSASHA384Signature([0; 48], EncodedPointP384::identity());
                        (None, Some((signature_param, signer)))
                    }
                    Some(_) => unimplemented!(),
                    None => unreachable!(),
                };

                // Concatenate constructed parameter buffers into a heapless Vec
                #[rustfmt::skip]
				let buf: Result<Vec<u8, _>> = match (puzzle_param, dh_param, hi_param) {
					(
						(HIPParamsTypes::PuzzleParam(puzzle_256), HIPParamsTypes::Default),
						(HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
						(HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
					) => {
						let mut param_buf: Vec<u8, U400> = Vec::new();
                        for byte in puzzle_256.inner_ref().as_ref().iter()
                            .chain(dh_256.inner_ref().as_ref().iter())
                            .chain(cipher_param.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.inner_ref().as_ref().iter())
                            .chain(hi_256.inner_ref().as_ref().iter())
                            .chain(hit_suitlist_param.inner_ref().as_ref().iter())
                            .chain(dhgroups_param.inner_ref().as_ref().iter())
                            .chain(transfmt_param.inner_ref().as_ref().iter()) {
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
                        for byte in puzzle_384.inner_ref().as_ref().iter()
                            .chain(dh_384.inner_ref().as_ref().iter())
                            .chain(cipher_param.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.inner_ref().as_ref().iter())
                            .chain(hi_384.inner_ref().as_ref().iter())
                            .chain(hit_suitlist_param.inner_ref().as_ref().iter())
                            .chain(dhgroups_param.inner_ref().as_ref().iter())
                            .chain(transfmt_param.inner_ref().as_ref().iter()) {
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
                        let pkt_len = current_r1pkt_len as usize * 8 + &val.len();
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

                // Reset R1 packet length. We'll progressively `set header_len` when adding each
                // parameter.
                hip_r1_packet
                    .packet
                    .set_header_length(HIP_DEFAULT_PACKET_LENGTH as u8);

                // set puzzle parameter fields irandom and opaque
                match puzzle_param {
                    (HIPParamsTypes::PuzzleParam(mut puzzle_256), HIPParamsTypes::Default) => {
                        let irandom = getrandom::<32>([12; 32]);
                        let opaque = getrandom::<2>([10; 32]);
                        puzzle_256.set_random(&irandom, 0x20);
                        puzzle_256.set_opaque(u16::from_be_bytes(opaque));
                    }
                    (HIPParamsTypes::Default, HIPParamsTypes::PuzzleParam(mut puzzle_384)) => {
                        let irandom = getrandom::<48>([12; 32]);
                        let opaque = getrandom::<2>([10; 32]);
                        puzzle_384.set_random(&irandom, 0x30);
                        puzzle_384.set_opaque(u16::from_be_bytes(opaque));
                    }
                    (_, _) => unreachable!(),
                }

                #[rustfmt::skip]
				// Add R1 parameters. List of mandatory parameters in an R1 packet
				match (puzzle_param, dh_param, hi_param, signature_param) {
					(
						(HIPParamsTypes::PuzzleParam(puzzle_256), HIPParamsTypes::Default),
						(HIPParamsTypes::DHParam(dh_256), HIPParamsTypes::Default),
						(HIPParamsTypes::HostIdParam(hi_256), HIPParamsTypes::Default),
						(HIPParamsTypes::SignatureParam(sign_param_256), HIPParamsTypes::Default),
					) => {
						hip_r1_packet.add_param(HIPParamsTypes::PuzzleParam(PuzzleParameter::fromtype(&puzzle_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_256)?));
						hip_r1_packet.add_param(HIPParamsTypes::HITSuitListParam(HITSuitListParameter::fromtype(&hit_suitlist_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHGroupListParam(DHGroupListParameter::fromtype(&dhgroups_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_256)?));
					}
					(
						(HIPParamsTypes::Default, HIPParamsTypes::PuzzleParam(puzzle_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::DHParam(dh_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::HostIdParam(hi_384)),
						(HIPParamsTypes::Default, HIPParamsTypes::SignatureParam(sign_param_384)),
					) => {
						hip_r1_packet.add_param(HIPParamsTypes::PuzzleParam(PuzzleParameter::fromtype(&puzzle_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHParam(DHParameter::fromtype(&dh_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::CipherParam(CipherParameter::fromtype(&cipher_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::ESPTransformParam(ESPTransformParameter::fromtype(&esp_transform_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::HostIdParam(HostIdParameter::fromtype(&hi_384)?));
						hip_r1_packet.add_param(HIPParamsTypes::HITSuitListParam(HITSuitListParameter::fromtype(&hit_suitlist_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::DHGroupListParam(DHGroupListParameter::fromtype(&dhgroups_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::TransportListParam(TransportListParameter::fromtype(&transfmt_param)?));
						hip_r1_packet.add_param(HIPParamsTypes::SignatureParam(SignatureParameter::fromtype(&sign_param_384)?));
					}
					_ => unimplemented!(),
				}

                // Swap src & dst IPv6 addresses
                core::mem::swap(&mut src, &mut dst);

                // Construct IPv6 packet
                let ipv6_payload_len = (hip_r1_packet.packet.get_header_length() * 8 + 8) as u16;
                let ipv6_fixed_header_len = 0x28u8;
                let mut ipv6_buffer = [0u8; 512]; // max- allocation to accomodate p384 parameter variants
                let mut ipv6_packet = Ipv6Packet::new_checked(&mut ipv6_buffer)
                    .map_err(|_| HIPError::Bufferistooshort)?;
                ipv6_packet.set_version(IPV6_VERSION as u8);
                ipv6_packet.set_dst_addr(dst);
                ipv6_packet.set_src_addr(src);
                ipv6_packet.set_next_header(IpProtocol::Unknown(HIP_PROTOCOL as u8));
                ipv6_packet.set_hop_limit(1);
                ipv6_packet.set_payload_len(ipv6_payload_len);

                // Compute and set HIP checksum
                let checksum = Utils::hip_ipv4_checksum(
                    &src.0,
                    &dst.0,
                    protocol,
                    ipv6_payload_len,
                    &hip_r1_packet.inner_ref().as_ref()[..ipv6_payload_len as usize],
                );
                hip_r1_packet.packet.set_checksum(checksum);
                ipv6_buffer[ipv6_fixed_header_len as usize..].copy_from_slice(
                    &hip_r1_packet.inner_ref().as_ref()[..ipv6_payload_len as usize],
                );
            }

            HIP_R1_PACKET => {
                hip_debug!("Received R1 packet");

                if hip_state
                    .ok_or_else(|| HIPError::Illegal)?
                    .is_unassociated()
                    || hip_state.ok_or_else(|| HIPError::Illegal)?.is_r2_sent()
                    || hip_state.ok_or_else(|| HIPError::Illegal)?.is_established()
                {
                    hip_debug!("Not expecting an R1 packet. Dropping packet...");
                }

                let oga_id = HIT::get_responders_oga_id(&rhit);

                match oga_id {
                    0x10 | 0x20 | 0x30 => {}
                    _ => {
                        hip_debug!("Unsupported HIT suit");
                        hip_debug!("OGA {:?}", oga_id);
                        hip_debug!("supported_hit_suits: {:?}", [0x10, 0x20, 0x30]);
                    }
                }

                let mut puzzle_param = None;
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
                // hip_r1_packet.packet.set_receivers_hit(&ihit);
                hip_r1_packet.packet.set_next_header(HIP_IPPROTO_NONE as u8);
                hip_r1_packet.packet.set_version(HIP_VERSION as u8);

                let rhash = HIT::get_responders_hash_alg(&ihit);
                let rhash_len = match &rhash {
                    DigestTypes::SHA256(h) => SHA256Digest::get_length(),
                    DigestTypes::SHA384(h) => SHA384Digest::get_length(),
                    _ => return Err(HIPError::__Nonexhaustive),
                };

                let param_list = parameters.ok_or_else(|| HIPError::FieldisNOTSet)?;
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
                                    let responders_hit = HIT::compute_hit::<32>(hi, oga_id);
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
                                    let responders_hit = HIT::compute_hit::<48>(hi, oga_id);
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
                                _ => unimplemented!(),
                            }

                            // Extract publickey from HostId
                            match hi[0..2] {
                                [0, 1] => {
                                    responder_pubkey256 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
                                    // responder_pubkey256 = Err(HIP);
                                }
                                [0, 2] => {
                                    responder_pubkey384 = Some(
                                        hi[2..].try_into().map_err(|_| HIPError::IncorrectLength),
                                    );
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
                            .ok_or_else(|| HIPError::FieldisNOTSet)?
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
                    hip_debug!("Puzzle was solved and verified");
                }
                // Check if the time taken to solve the puzzle is greater than the `timer duration`.
                // If yes, drop the packet and set state to unassociated.
                let elapsed_time = timer.get_elapsed_time().ok_or_else(|| HIPError::TimeOut)?;
                if elapsed_time > timer.duration {
                    hip_debug!("Maximum time to solve the puzzle exceeded. Dropping the packet...");
                    hip_state.map(|state| state.unassociated());
                }

                // Echo Response Paraemeter - just echo back what the sender sent, unmodified. Assuming a 36 byte opaque payload.
                let mut echo_signed = EchoResponseSignedParameter::new_checked([0; 36])?;
                echo_signed.init_echoresponse_signed_param();
                echo_signed.set_opaque_data(
                    echo_request_signed_opaque_data.ok_or_else(|| HIPError::FieldisNOTSet)??,
                );
                let mut param_buf: Vec<u8, U512> = Vec::new();
                #[rustfmt::skip]
                match (r1_counter_param, echo_request_signed_opaque_data) {
                    (Some(r1), Some(echo_req)) => {  //                      
                        for byte in r1.inner_ref().as_ref().iter()
                            .chain(puzzle_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(cipher_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hi_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hit_suit_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(dh_groups_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(transport_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
                        }
                    },
                    (Some(r1), None) => {
                        for byte in r1.inner_ref().as_ref().iter()
                            .chain(puzzle_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(cipher_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hi_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hit_suit_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(dh_groups_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(transport_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                    (None, Some(echo_req)) => { //
                        for byte in puzzle_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()
                            .chain(cipher_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hi_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hit_suit_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(dh_groups_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(echo_signed.inner_ref().as_ref().iter())
                            .chain(transport_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                    (None, None) => {
                        for byte in puzzle_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()
                            .chain(cipher_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(esp_transform_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hi_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(hit_suit_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(dh_groups_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter())
                            .chain(transport_param.ok_or_else(|| HIPError::FieldisNOTSet)?.inner_ref().as_ref().iter()) {
						  param_buf
							.push(*byte)
							.map_err(|_| HIPError::Bufferistooshort);
						}
                    },
                }

                let current_r1pkt_len = hip_r1_packet.packet.get_header_length();
                let pkt_len = current_r1pkt_len as usize * 8 + &param_buf.len();
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
                            }
                        }
                    }
                    (_, _) => unimplemented!(),
                }

                // Get the DH group and look it up in our list of supported groups.
                // If we get a match, move to key-generation
                let dhlist_param = dh_groups_param.ok_or_else(|| HIPError::FieldisNOTSet)?;
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
                    .ok_or_else(|| HIPError::FieldisNOTSet)?
                    .get_public_value()
                {
                    Ok(pk) if pk.len() != 64 => (Some(pk), None),
                    Ok(pk) if pk.len() != 96 => (None, Some(pk)),
                    Ok(_) => {
                        hip_debug!("Invalid Public Key value");
                        (None, None)
                    }
                    Err(_) => unimplemented!(),
                };

                // Compute the shared secret using the responder's pubkey and our DH keys
                let (ss256, ss384) = match (pk256_r, pk384_r) {
                    (Some(pk), None) => {
                        let temp = pk256_r.ok_or_else(|| HIPError::FieldisNOTSet)?;
                        let pk256_r = PkP256::from_bytes(temp)?;
                        let ss = ECDHNISTP256::generate_shared_secret(
                            &sk256.clone().ok_or_else(|| HIPError::ECCError)?,
                            &pk256_r,
                        )?;
                        (Some(ss), None)
                    }
                    (None, Some(pk)) => {
                        let temp = pk384_r.ok_or_else(|| HIPError::FieldisNOTSet)?;
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
                    .ok_or_else(|| HIPError::FieldisNOTSet)?
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
                    .ok_or_else(|| HIPError::FieldisNOTSet)?
                    .get_esp_suits()?;
                // NULL with HMAC-SHA-256 (0x7), AES-128-CBC with HMAC-SHA-256 (0x8), AES-256-CBC with HMAC-SHA-256 (0x9)
                let supported_esp_transform_suits = [0x9, 0x8, 0x7];
                let mut selected_esp_transform = None;

                for (idx, group_id) in offered_esp_transforms.iter().enumerate() {
                    if supported_esp_transform_suits.contains(group_id) {
                        selected_esp_transform = Some(offered_esp_transforms[idx]);
                        break;
                    }
                }
                if selected_esp_transform.is_none() {
                    hip_trace!("Unsupported ESP transform suit");
                    return Err(HIPError::Unrecognized);
                }

                // Output from kdf function i.e. key-material
                // Note - you only need the first keymat_len_octet bytes from the output
                let mut keymat = [0; 800];

                if ss256.is_some() {
                    let keymat_len_octets = Utils::compute_keymat_len(
                        hmac_alg,
                        selected_cipher.ok_or_else(|| HIPError::FieldisNOTSet)?,
                    );
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss256.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss384.is_some() {
                    let keymat_len_octets = Utils::compute_keymat_len(
                        hmac_alg,
                        selected_cipher.ok_or_else(|| HIPError::FieldisNOTSet)?,
                    );
                    keymat = Utils::kdf(
                        hmac_alg,
                        &salt_buffer,
                        &ss384.unwrap().to_bytes(),
                        &key_info.as_bytearray(),
                        keymat_len_octets,
                    );
                } else if ss256.is_none() && ss384.is_none() {
                    return Err(HIPError::FieldisNOTSet);
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
                solution_param.set_k_value(
                    puzzle_param
                        .ok_or_else(|| HIPError::FieldisNOTSet)?
                        .get_k_value()?,
                );
                solution_param.set_opaque(opaque.ok_or_else(|| HIPError::FieldisNOTSet)??);
                solution_param.set_random(irandom.ok_or_else(|| HIPError::FieldisNOTSet)??);
                solution_param.set_solution(&jrandom);

                // HIP DH Parameter
                let dh_param = match (dh_is_ecdh256, dh_is_ecdh384) {
                    (true, _) => {
                        let dh_param_buffer = [0; 80];
                        let mut dh_param256 = DHParameter::new_checked(dh_param_buffer)?;
                        dh_param256.init_dhparameter_param();
                        dh_param256
                            .set_group_id(selected_dh_group.ok_or_else(|| HIPError::Unrecognized)?);
                        dh_param256.set_public_value_length(0x40); // pubkey len for ECDH256
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
                        dh_param384.set_public_value_length(0x60); // pubkey len for ECDH384
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
                        let mut mac_param = MACParameter::new_checked([0; 32 + 4])?;
                        (Some(mac_param), None)
                    }
                    0x2 => {
                        let mut mac_param = MACParameter::new_checked([0; 48 + 4])?;
                        (None, Some(mac_param))
                    }
                    _ => unimplemented!(),
                };

                // Compute HMAC
                let mut param_buf: Vec<u8, U512> = Vec::new();
                match (r1_counter_param, echo_request_signed_opaque_data) {
                    (Some(r1), Some(echo_req)) => {
                        //
                        match (dh_param, hi_param) {
                            (
                                (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                                (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                            ) => {
                                for byte in esp_info_param
                                    .inner_ref()
                                    .as_ref()
                                    .iter()
                                    .chain(r1.inner_ref().as_ref().iter())
                                    .chain(solution_param.inner_ref().as_ref().iter())
                                    .chain(dh256.inner_ref().as_ref().iter())
                                    .chain(cipher_param.inner_ref().as_ref().iter())
                                    .chain(esp_transform_param.inner_ref().as_ref().iter())
                                    .chain(hi256.inner_ref().as_ref().iter())
                                    .chain(echo_signed.inner_ref().as_ref().iter())
                                    .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                    .chain(r1.inner_ref().as_ref().iter())
                                    .chain(solution_param.inner_ref().as_ref().iter())
                                    .chain(dh384.inner_ref().as_ref().iter())
                                    .chain(cipher_param.inner_ref().as_ref().iter())
                                    .chain(esp_transform_param.inner_ref().as_ref().iter())
                                    .chain(hi384.inner_ref().as_ref().iter())
                                    .chain(echo_signed.inner_ref().as_ref().iter())
                                    .chain(transfmt_param.inner_ref().as_ref().iter())
                                {
                                    param_buf
                                        .push(*byte)
                                        .map_err(|_| HIPError::Bufferistooshort);
                                }
                            }
                            (_, _) => unimplemented!(),
                        }
                    }
                    (Some(r1), None) => match (dh_param, hi_param) {
                        (
                            (HIPParamsTypes::DHParam(dh256), HIPParamsTypes::Default),
                            (HIPParamsTypes::HostIdParam(hi256), HIPParamsTypes::Default),
                        ) => {
                            for byte in esp_info_param
                                .inner_ref()
                                .as_ref()
                                .iter()
                                .chain(r1.inner_ref().as_ref().iter())
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh256.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi256.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                .chain(r1.inner_ref().as_ref().iter())
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh384.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi384.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh256.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi256.inner_ref().as_ref().iter())
                                .chain(echo_signed.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh384.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi384.inner_ref().as_ref().iter())
                                .chain(echo_signed.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh256.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi256.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                                .chain(solution_param.inner_ref().as_ref().iter())
                                .chain(dh384.inner_ref().as_ref().iter())
                                .chain(cipher_param.inner_ref().as_ref().iter())
                                .chain(esp_transform_param.inner_ref().as_ref().iter())
                                .chain(hi384.inner_ref().as_ref().iter())
                                .chain(transfmt_param.inner_ref().as_ref().iter())
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
                let pkt_len = current_r1pkt_len as usize * 8 + &param_buf.len();
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

                let (aes_key, hmac_key) =
                    Utils::get_keys(&keymat, hmac_alg, selected_cipher.unwrap(), &ihit, &rhit)?;
                let hmac = HMACFactory::get(hmac_alg);

                if mac256_param.is_some() {
                    mac256_param
                        .unwrap()
                        .set_hmac(&SHA256HMAC::hmac_256(&hmac_bytes[..], hmac_key));
                } else if mac384_param.is_some() {
                    mac384_param
                        .unwrap()
                        .set_hmac(&SHA384HMAC::hmac_384(&hmac_bytes[..], hmac_key));
                }

                // Compute Signature
                //
                // Construct Signature Parameter
                let signer_tuple = match self.privkey {
                    Some(val) if val.len() == 0x20 => {
                        let mut signature_param = SignatureParameter::new_checked([0; 72])?;
                        let signer = ECDSASHA256Signature([0; 32], [0; 64]);
                        (Some((signature_param, signer)), None)
                    }
                    Some(val) if val.len() == 0x30 => {
                        let mut signature_param = SignatureParameter::new_checked([0; 104])?;
                        let signer = ECDSASHA384Signature([0; 48], EncodedPointP384::identity());
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
                        let pkt_len = current_r1pkt_len as usize * 8 + &param_buf.len();
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
                        let pkt_len = current_r1pkt_len as usize * 8 + &param_buf.len();
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
            }
            _ => todo!(),
        }
        Ok(())
    }

    pub fn dispatch_hip_packet() {}
}
