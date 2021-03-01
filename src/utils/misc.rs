#![deny(unsafe_code)]
#![allow(warnings)]

use crate::{HIPError, Result};
use core::convert::TryInto;
use core::{cmp::Ordering::Equal, panic};

use crate::crypto::digest::{SHA1HMAC, SHA256HMAC, SHA384HMAC};
use crate::crypto::factory::{CipherTypes, HMACFactory, HMACTypes, SymmetricCiphersFactory};
use hkdf::Hkdf;
use sha1::Sha1;
use sha2::{Sha256, Sha384};

use heapless::consts::*;
use heapless::String;

use libc_print::libc_println;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaplessStringTypes {
    U64(String<U80>),
    U32(String<U40>),
    U16(String<U20>),
    U8(String<U10>),
}

impl HeaplessStringTypes {
    pub fn as_str(&self) -> &str {
        #[rustfmt::skip]
        match self {
            HeaplessStringTypes::U64(str) => str.as_str(),
            HeaplessStringTypes::U32(str) => str.as_str(),
            HeaplessStringTypes::U16(str) => str.as_str(),
            HeaplessStringTypes::U8(str)  => str.as_str(),
        }
    }
}
pub struct Utils;

impl Utils {
    pub fn hits_equal(ihit: &[u8], rhit: &[u8]) -> bool {
        if ihit.len() != rhit.len() {
            return false;
        } else if ihit.partial_cmp(rhit).unwrap() == Equal {
            return true;
        } else {
            false
        }
    }

    pub fn hex_formatted_hit_bytes(
        ihit: Option<&[u8]>,
        rhit: Option<&[u8]>,
    ) -> Result<HeaplessStringTypes> {
        match (ihit, rhit) {
            (Some(ihit), Some(rhit)) => {
                match (ihit.len(), rhit.len()) {
                    (0x10, 0x10) => {
                        let mut key_bytes = [0; 32];
                        let _temp = ihit
                            .iter()
                            .chain(rhit.iter())
                            .enumerate()
                            .for_each(|(i, c)| key_bytes[i] = *c);

                        let mut key_string: String<U80> = String::new();
                        let _temp = key_bytes.iter().enumerate().for_each(|(i, byte)| {
                            key_string
                                .push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char)
                                .and_then(|_| {
                                    key_string.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize] as char)
                                });
                            if i == 1 {
                                key_string.push(':')
                            } else if i > 1 && ((i - 1) % 2) == 0 {
                                key_string.push(':')
                            } else {
                                Ok(())
                            };
                        });
                        key_string.pop();
                        // libc_println!("{:?}", key_string);
                        Ok(HeaplessStringTypes::U64(key_string))
                    }
                    (0x4, 0x4) => {
                        let mut key_bytes = [0; 8];
                        let _temp = ihit
                            .iter()
                            .chain(rhit.iter())
                            .enumerate()
                            .for_each(|(i, c)| key_bytes[i] = *c);

                        let mut key_string: String<U20> = String::new();
                        let _temp = key_bytes.iter().enumerate().for_each(|(i, byte)| {
                            key_string
                                .push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char)
                                .and_then(|_| {
                                    key_string.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize] as char)
                                });
                            if i == 1 {
                                key_string.push(':')
                            } else if i > 1 && ((i - 1) % 2) == 0 {
                                key_string.push(':')
                            } else {
                                Ok(())
                            };
                        });
                        key_string.pop();
                        // libc_println!("{:?}", key_string);
                        Ok(HeaplessStringTypes::U16(key_string))
                    }

                    (_, _) => Err(HIPError::IncorrectLength),
                }
            }
            (Some(ihit), None) => {
                let mut key_string: String<U40> = String::new();
                let _temp = ihit.iter().enumerate().for_each(|(i, byte)| {
                    key_string
                        .push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char)
                        .and_then(|_| {
                            key_string.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize] as char)
                        });
                    if i == 1 {
                        key_string.push(':')
                    } else if i > 1 && ((i - 1) % 2) == 0 {
                        key_string.push(':')
                    } else {
                        Ok(())
                    };
                });
                key_string.pop();
                Ok(HeaplessStringTypes::U32(key_string))
            }
            (None, Some(rhit)) => {
                let mut key_string: String<U40> = String::new();
                let _temp = rhit.iter().enumerate().for_each(|(i, byte)| {
                    key_string
                        .push(HEX_CHARS_LOWER[(byte >> 4) as usize] as char)
                        .and_then(|_| {
                            key_string.push(HEX_CHARS_LOWER[(byte & 0x0F) as usize] as char)
                        });
                    if i == 1 {
                        key_string.push(':')
                    } else if i > 1 && ((i - 1) % 2) == 0 {
                        key_string.push(':')
                    } else {
                        Ok(())
                    };
                });
                key_string.pop();
                Ok(HeaplessStringTypes::U32(key_string))
            }
            (None, None) => return Err(HIPError::Exhausted),
        }
    }

    pub fn ipv4_bytes_to_string(bytes: &[u8]) -> Option<String<U15>> {
        let mut addr_str: String<U15> = String::new();
        if bytes.len() != 0x4 {
            return None;
        } else {
            addr_str.push_str(String::<U3>::from(bytes[0]).as_str());
            addr_str.push('.');
            addr_str.push_str(String::<U3>::from(bytes[1]).as_str());
            addr_str.push('.');
            addr_str.push_str(String::<U3>::from(bytes[2]).as_str());
            addr_str.push('.');
            addr_str.push_str(String::<U3>::from(bytes[3]).as_str());
            Some(addr_str)
        }
    }

    pub fn ipv4_to_int(bytes: &[u8]) -> u32 {
        let addr: [u8; 4] = bytes.try_into().unwrap();
        let ipv4_int = u32::from_be_bytes(addr);
        ipv4_int
    }

    pub fn hip_ipv4_checksum(src: &[u8], dst: &[u8], protocol: u8, len: u16, data: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..data.len()).step_by(2) {
            let word16 = (((data[i] as u16) << 8u16) & 0xFF00) + (data[i + 1] & 0xFF) as u16;
            sum += word16 as u32;
        }
        for i in (0..src.len()).step_by(2) {
            let word16 = (((src[i] as u16) << 8u16) & 0xFF00) + (src[i + 1] & 0xFF) as u16;
            sum += word16 as u32;
        }
        for i in (0..dst.len()).step_by(2) {
            let word16 = (((dst[i] as u16) << 8u16) & 0xFF00) + (dst[i + 1] & 0xFF) as u16;
            sum += word16 as u32;
        }
        sum = sum + (protocol as u16 + len) as u32;
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (!sum & 0xFFFF) as u16;
    }

    pub fn compute_keymat_len(hmac_alg: u8, cipher_alg: u8) -> u16 {
        let hmac_len = match HMACFactory::get(hmac_alg) {
            HMACTypes::HMAC256(v) => SHA256HMAC::get_length(),
            HMACTypes::HMAC384(v) => SHA384HMAC::get_length(),
            HMACTypes::HMACSHA1(v) => SHA1HMAC::get_length(),
            _ => unimplemented!(),
        };
        let cipher_key_len = match SymmetricCiphersFactory::get(cipher_alg) {
            CipherTypes::AES128(_v) => 0x10,
            CipherTypes::AES256(_v) => 0x20,
            _ => unimplemented!(),
        };
        10 * (hmac_len + cipher_key_len) as u16
    }

    pub fn compute_hip_keymat_len(hmac_alg: u8, cipher_alg: u8) -> u8 {
        let hmac_len = match HMACFactory::get(hmac_alg) {
            HMACTypes::HMAC256(v) => SHA256HMAC::get_length(),
            HMACTypes::HMAC384(v) => SHA384HMAC::get_length(),
            HMACTypes::HMACSHA1(v) => SHA1HMAC::get_length(),
            _ => unimplemented!(),
        };
        let cipher_key_len = match SymmetricCiphersFactory::get(cipher_alg) {
            CipherTypes::AES128(_v) => 0x10,
            CipherTypes::AES256(_v) => 0x20,
            _ => unimplemented!(),
        };
        2 * (hmac_len + cipher_key_len)
    }

    pub fn get_keys<'a>(
        keymat: &'a [u8],
        hmac_alg: u8,
        cipher_alg: u8,
        ihit: &[u8],
        rhit: &[u8],
    ) -> Result<(&'a [u8], &'a [u8])> {
        let mut offset = 0u8;
        if ihit.len() != 0x10 || rhit.len() != 0x10 {
            return Err(HIPError::IncorrectLength);
        }

        let ihit = u128::from_be_bytes(ihit.try_into().unwrap());
        let rhit = u128::from_be_bytes(rhit.try_into().unwrap());

        let hmac_len = match HMACFactory::get(hmac_alg) {
            HMACTypes::HMAC256(v) => SHA256HMAC::get_length(),
            HMACTypes::HMAC384(v) => SHA384HMAC::get_length(),
            HMACTypes::HMACSHA1(v) => SHA1HMAC::get_length(),
            _ => unimplemented!(),
        };
        let cipher_key_len = match SymmetricCiphersFactory::get(cipher_alg) {
            CipherTypes::AES128(_v) => 0x10,
            CipherTypes::AES256(_v) => 0x20,
            _ => unimplemented!(),
        };

        if ihit < rhit {
            offset += (hmac_len + cipher_key_len);
        }

        let aes_key = &keymat[offset as usize..(offset + cipher_key_len) as usize];
        let hmac_key = &keymat
            [(offset + cipher_key_len) as usize..(offset + cipher_key_len + hmac_len) as usize];

        Ok((aes_key, hmac_key))
    }

    pub fn get_keys_esp<'a>(
        keymat: &'a [u8],
        keymat_index: u8,
        hmac_alg: u8,
        cipher_alg: u8,
        ihit: &[u8],
        rhit: &[u8],
    ) -> Result<(&'a [u8], &'a [u8])> {
        let mut offset = keymat_index;
        if ihit.len() != 0x10 || rhit.len() != 0x10 {
            return Err(HIPError::IncorrectLength);
        }

        let ihit = u128::from_be_bytes(ihit.try_into().unwrap());
        let rhit = u128::from_be_bytes(rhit.try_into().unwrap());

        let hmac_len = match HMACFactory::get(hmac_alg) {
            HMACTypes::HMAC256(v) => SHA256HMAC::get_length(),
            HMACTypes::HMAC384(v) => SHA384HMAC::get_length(),
            HMACTypes::HMACSHA1(v) => SHA1HMAC::get_length(),
            _ => unimplemented!(),
        };
        let cipher_key_len = match SymmetricCiphersFactory::get(cipher_alg) {
            CipherTypes::AES128(_v) => 0x10,
            CipherTypes::AES256(_v) => 0x20,
            _ => unimplemented!(),
        };

        if ihit > rhit {
            offset += (hmac_len + cipher_key_len);
        }

        let aes_key = &keymat[offset as usize..(offset + cipher_key_len) as usize];
        let hmac_key = &keymat[(offset + cipher_key_len) as usize
            ..offset as usize + cipher_key_len as usize + hmac_len as usize];

        Ok((aes_key, hmac_key))
    }

    pub fn sort_hits(ihit_bytes: &[u8], rhit_bytes: &[u8]) -> [u8; 32] {
        let ihit = u128::from_be_bytes(ihit_bytes.try_into().unwrap());
        let rhit = u128::from_be_bytes(rhit_bytes.try_into().unwrap());
        if ihit > rhit {
            let mut rhit_ihit = [0; 32];
            rhit_bytes
                .iter()
                .chain(ihit_bytes.iter())
                .enumerate()
                .for_each(|(i, x)| rhit_ihit[i] = *x);
            rhit_ihit
        } else {
            let mut ihit_rhit = [0; 32];
            ihit_bytes
                .iter()
                .chain(rhit_bytes.iter())
                .enumerate()
                .for_each(|(i, x)| ihit_rhit[i] = *x);
            ihit_rhit
        }
    }

    pub fn is_hit_smaller(ihit_bytes: &[u8], rhit_bytes: &[u8]) -> bool {
        let ihit = u128::from_be_bytes(ihit_bytes.try_into().unwrap());
        let rhit = u128::from_be_bytes(rhit_bytes.try_into().unwrap());
        if ihit < rhit {
            true
        } else {
            false
        }
    }

    /// HMAC-based Key Derivation Function (HKDF)
    ///
    /// - `len_in_octets` - is the sum of `hash + cipher key len`
    /// - `ikm` - input key material (variable length)
    /// - `info` - additional information
    /// - `salt` - an optional value but in this case, its the 32 byte value
    ///   (i.e. `irandom + jrandom`)
    /// - `okm` - output key material.
    ///
    /// `Note` - you only need the first `len_in_octets` bytes from the `okm`
    /// buffer.
    pub fn kdf(alg: u8, salt: &[u8], ikm: &[u8], info: &[u8], len_in_octets: u16) -> [u8; 800] {
        match HMACFactory::get(alg) {
            HMACTypes::HMAC256(v) => {
                let hk = Hkdf::<Sha256>::new(Some(salt), ikm); // Extract step
                let mut okm = [0u8; 800]; // max bytes allocated for key-material
                hk.expand(&info, &mut okm) // Expand step
                    .expect("Sha256 Hmac based key-derivation failed");
                okm
            }
            HMACTypes::HMAC384(v) => {
                let hk = Hkdf::<Sha384>::new(Some(salt), ikm); // Extract step
                let mut okm = [0u8; 800]; // max bytes allocated for key-material
                hk.expand(&info, &mut okm) // Expand step
                    .expect("Sha384 Hmac based key-derivation failed");
                okm
            }
            HMACTypes::HMACSHA1(v) => {
                let hk = Hkdf::<Sha1>::new(Some(salt), ikm); // Extract step
                let mut okm = [0u8; 800]; // max bytes allocated for key-material
                hk.expand(&info, &mut okm) // Expand step
                    .expect("Sha1 Hmac based key-derivation failed");
                okm
            }
            HMACTypes::__Nonexhaustive => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use core::str::FromStr;

    static IPV4_BYTES: [u8; 4] = [192, 168, 1, 0];
    static MALFORMED_IPV4_BYTES: [u8; 3] = [168, 1, 0];

    #[test]
    fn test_ipv4_bytes_to_string() {
        let ipv4_string = Utils::ipv4_bytes_to_string(&IPV4_BYTES);
        let malformed_ipv4_string = Utils::ipv4_bytes_to_string(&MALFORMED_IPV4_BYTES);
        assert_eq!(ipv4_string.unwrap(), "192.168.1.0");
        assert_eq!(malformed_ipv4_string, None);
    }

    static SRC: [u8; 4] = [192, 168, 12, 0];
    static DST: [u8; 4] = [192, 168, 23, 2];
    static SRC_IPv6: [u8; 16] = [128; 16];
    static DST_IPv6: [u8; 16] = [132; 16];
    static PROTO: u8 = 0x8B;
    static PAYLOAD: [u8; 88] = [123; 88];
    static LEN: u16 = 10;

    #[test]
    fn test_hip_ipv4_checksum() {
        let checksum = Utils::hip_ipv4_checksum(&SRC, &DST, PROTO, LEN, &PAYLOAD);
        let checksum_ipv6 = Utils::hip_ipv4_checksum(&SRC_IPv6, &DST_IPv6, PROTO, LEN, &PAYLOAD);
        assert_eq!(checksum, 8670);
        assert_eq!(checksum_ipv6, 40457);
        libc_println!("{:?}", checksum_ipv6);
    }

    #[test]
    fn test_hits_equal() {
        let ihit = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0xf4, 0x08, 0x9f, 0x29, 0x5e,
            0x34, 0x5f,
        ];
        let rhit = [
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        let bl = Utils::hits_equal(&ihit, &rhit);
        assert_eq!(false, bl);
    }

    #[test]
    fn test_hex_formatted_hit_bytes() {
        let ihit = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0xf4, 0x08, 0x9f, 0x29, 0x5e,
            0x34, 0x5f,
        ];
        let rhit = [
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let result = Utils::hex_formatted_hit_bytes(Some(&ihit), None);
        assert_eq!(
            HeaplessStringTypes::U32(
                String::from_str("fe80:0000:0000:0000:fbf4:089f:295e:345f").unwrap()
            ),
            result.unwrap()
        );
        let result = Utils::hex_formatted_hit_bytes(Some(&ihit), Some(&rhit));
        assert_eq!(
            HeaplessStringTypes::U64(
                String::from_str("fe80:0000:0000:0000:fbf4:089f:295e:345f:ff02:0000:0000:0000:0000:0000:0000:0002").unwrap()
            ),
            result.clone().unwrap()
        );
        println!(
            "{:?}",
            if let Ok(HeaplessStringTypes::U64(val)) = result {
                val.as_str().len()
            } else {
                unimplemented!()
            }
        );

        let ipv4_src = [1, 2, 3, 4];
        let ipv4_dst = [5, 6, 7, 8];

        let res = Utils::hex_formatted_hit_bytes(Some(&ipv4_src), Some(&ipv4_dst));
        assert_eq!(
            HeaplessStringTypes::U16(String::from_str("0102:0304:0506:0708").unwrap()),
            res.clone().unwrap()
        );
        println!(
            "{:?}",
            if let Ok(HeaplessStringTypes::U16(val)) = res {
                val.as_str().len()
            } else {
                unimplemented!()
            }
        );
    }
}
