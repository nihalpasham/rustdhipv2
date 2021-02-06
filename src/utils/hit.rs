#![allow(warnings)]

use super::constants;
use crate::crypto::dh;
use crate::crypto::digest::{SHA1Digest, SHA256Digest, SHA384Digest};
// use pretty_hex::*;
use crate::Result;

use core::{convert::TryInto, fmt};
use libc_print::libc_println;

use num_bigint_dig::BigUint;

pub enum DigestTypes {
    SHA256(SHA256Digest),
    SHA384(SHA384Digest),
    SHA1(SHA1Digest),
    __Nonexhaustive,
}

pub struct HIT;

impl HIT {
    #[inline]
    pub fn get_responders_hash_alg(rhit: &[u8]) -> DigestTypes {
        let oga_id = rhit[constants::OGA_OFFSET as usize];
        let rhash = if oga_id == 0x1 {
            DigestTypes::SHA256(SHA256Digest)
        } else if oga_id == 0x2 {
            DigestTypes::SHA384(SHA384Digest)
        } else if oga_id == 0x3 {
            DigestTypes::SHA1(SHA1Digest)
        } else {
            panic!()
        };
        rhash
    }

    pub fn get_responders_oga_id(rhit: &[u8]) -> u8 {
        rhit[constants::OGA_OFFSET as usize]
    }

    pub fn encode_96(bytes: &[u8]) -> [u8; constants::TRUNCATED_HASH_LENGTH as usize] {
        let bit_len = (bytes.len() * 8 - (constants::TRUNCATED_HASH_LENGTH * 8) as usize) / 2;
        let start_offset = bit_len / 8;
        let trunc_bytes: [u8; constants::TRUNCATED_HASH_LENGTH as usize] = bytes
            [start_offset..start_offset + constants::TRUNCATED_HASH_LENGTH as usize]
            .try_into()
            .unwrap();
        trunc_bytes
        // let mut trunc_bytes = [0u8; 12];
        // for i in 0..len{
        //     let bw = [0xff;1];
        //     let byte = (v.clone() >> (i*8) as usize) &
        // BigUint::from_bytes_be(&bw);     trunc_bytes[i as usize] =
        // BigUint::to_bytes_be(&byte).as_slice()[0]; }
        // trunc_bytes
    }

    /// Input      :=  any bitstring
    /// OGA ID     :=  4-bit Orchid Generation Algorithm identifier
    /// Hash Input :=  Context ID | Input
    /// Hash       :=  Hash_function( Hash Input )
    /// ORCHID     :=  Prefix | OGA ID | Encode_96( Hash )
    ///
    /// The N represents the `Hash Input` length. For Ex: we'd use an `N value`
    /// of `96 + 16`
    /// - 96 bytes for a P384 public-key and
    /// - 16 bytes for the fixed `Context ID`
    pub fn compute_hit<const N: usize>(hi: &[u8], oga_id: u8) -> [u8; 16] {
        let mut rhash;
        if oga_id == 0x1 {
            rhash = DigestTypes::SHA256(SHA256Digest);
        } else if oga_id == 0x2 {
            rhash = DigestTypes::SHA384(SHA384Digest);
        } else if oga_id == 0x3 {
            rhash = DigestTypes::SHA1(SHA1Digest);
        } else {
            panic!()
        }

        let mut hit = [0; 16];
        let hit_ctx_id = dh::unhexlify_to_bytearray::<16>(&constants::HIP_HIT_CONTEX_ID);
        let mut hash_contents: [u8; N] = [0; N];
        hit_ctx_id
            .iter()
            .chain(hi.iter())
            .enumerate()
            .for_each(|(i, x)| hash_contents[i] = *x);

        let mut hip_hit_prefix = dh::unhexlify_to_bytearray::<4>("20012000");
        hip_hit_prefix[hip_hit_prefix.len() - 1] =
            hip_hit_prefix[hip_hit_prefix.len() - 1] | (oga_id & 0xF);
        match rhash {
            DigestTypes::SHA256(val) => {
                let encoded_hit = HIT::encode_96(&val.digest(&hash_contents));
                hit[0..hip_hit_prefix.len()].copy_from_slice(&hip_hit_prefix[..]);
                hit[hip_hit_prefix.len()..].copy_from_slice(&encoded_hit);
                hit
            }
            DigestTypes::SHA384(val) => {
                let encoded_hit = HIT::encode_96(&val.digest(&hash_contents));
                hit[0..hip_hit_prefix.len()].copy_from_slice(&hip_hit_prefix[..]);
                hit[hip_hit_prefix.len()..].copy_from_slice(&encoded_hit);
                hit
            }
            DigestTypes::SHA1(val) => {
                let encoded_hit = HIT::encode_96(&val.digest(&hash_contents));
                hit[0..hip_hit_prefix.len()].copy_from_slice(&hip_hit_prefix[..]);
                hit[hip_hit_prefix.len()..].copy_from_slice(&encoded_hit);
                hit
            }
            _ => unimplemented!(),
        }
    }

    // pub fn get_hit_in_hex<const N: usize>(hi: &[u8], oga_id: u8) {
    //     let hit_bytes = HIT::compute_hit::<N>(hi, oga_id);
    //     // pretty_hex::simple_hex_write(writer, source)

    // }

    /// Derives OGA ID from the HIT
    pub fn get_oga_id(hit: [u8; 16]) -> u8 {
        hit[constants::OGA_OFFSET as usize] & 0xF
    }

    /// Returns the RHash type
    pub fn get_rhash(hit: [u8; 16]) -> DigestTypes {
        let oga_id = HIT::get_oga_id(hit);
        match oga_id {
            0x1 => DigestTypes::SHA256(SHA256Digest),
            0x2 => DigestTypes::SHA384(SHA384Digest),
            0x3 => DigestTypes::SHA1(SHA1Digest),
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_hit_encode_96() {
        let data = [12; 48];
        let sha256 = SHA256Digest;
        let hash256 = sha256.digest(&data);
        let hit_96 = HIT::encode_96(&hash256);
        assert_eq!(
            [169, 156, 222, 129, 40, 140, 58, 53, 15, 243, 80, 230],
            hit_96
        );
        assert_eq!(12, hit_96.len());
    }

    #[test]
    fn test_compute_hit() {
        let data = [12; 48];
        let sha256 = SHA256Digest;
        let hash256 = sha256.digest(&data);
        let hit = HIT::compute_hit::<48>(&hash256, 0x1);
        assert_eq!(
            [32, 1, 32, 1, 18, 183, 211, 169, 42, 196, 19, 229, 119, 38, 62, 91],
            hit
        );
        assert_eq!(16, hit.len());
    }
}
