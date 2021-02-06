use crate::crypto::aes::{AES128CBCCipher, AES256CBCCipher};
use crate::crypto::dh::{DH15, DH5};
use crate::crypto::digest::{SHA1HMAC, SHA256HMAC, SHA384HMAC};
use crate::crypto::ecdh::{ECDHNISTP256, ECDHNISTP384};
use crate::wire::constants;

#[derive(Debug, Clone, Copy)]
pub enum HMACTypes {
    HMAC256(SHA256HMAC),
    HMAC384(SHA384HMAC),
    HMACSHA1(SHA1HMAC),
    __Nonexhaustive,
}

#[derive(Debug, Clone, Copy)]
pub enum CipherTypes {
    AES128(AES128CBCCipher),
    AES256(AES256CBCCipher),
    NULL,
    __Nonexhaustive,
}
#[derive(Debug, Clone)]
pub enum DHTypes {
    ECDH256(ECDHNISTP256),
    ECDH384(ECDHNISTP384<48>),
    DH5(DH5),
    DH15(DH15),
    __Nonexhaustive,
}
pub struct HMACFactory;

impl HMACFactory {
    pub fn get(alg: u8) -> HMACTypes {
        match alg {
            0x1 | 0x10 => HMACTypes::HMAC256(SHA256HMAC),
            0x2 | 0x20 => HMACTypes::HMAC384(SHA384HMAC),
            0x3 | 0x30 => HMACTypes::HMACSHA1(SHA1HMAC),
            _ => unimplemented!(),
        }
    }
}

pub struct HITSuitFactory;

impl HITSuitFactory {
    pub fn get_supported_hash_algorithms() -> [u8; 2] {
        return [0x10, 0x20];
    }
}

pub struct TransportFactory;

impl TransportFactory {
    pub fn get_supported_transports() -> usize {
        return constants::field::ESP_TRANSPORT_FORMAT;
    }
}

pub struct ESPTransformFactory;

impl ESPTransformFactory {
    pub fn get(transform: u8) -> (CipherTypes, HMACTypes) {
        match transform {
            0x7 => return (CipherTypes::NULL, HMACTypes::HMAC256(SHA256HMAC)), /* NULL cipher */
            // with SHA256
            // HMAC
            0x8 => {
                return (
                    CipherTypes::AES128(AES128CBCCipher),
                    HMACTypes::HMAC256(SHA256HMAC),
                )
            } // # AES128CBC with SHA256 HMAC
            0x9 => {
                return (
                    CipherTypes::AES256(AES256CBCCipher),
                    HMACTypes::HMAC256(SHA256HMAC),
                )
            } //AES256CBC with SHA256 HMAC
            _ => unimplemented!(),
        }
    }
}

pub struct SymmetricCiphersFactory;

impl SymmetricCiphersFactory {
    pub fn get_supported_ciphers() -> [u8; 3] {
        [0x2, 0x4, 0x1]
    }

    pub fn get(cipher: u8) -> CipherTypes {
        match cipher {
            0x2 => CipherTypes::AES128(AES128CBCCipher),
            0x4 => CipherTypes::AES256(AES256CBCCipher),
            0x1 => CipherTypes::NULL,
            _ => unimplemented!(),
        }
    }
}

pub struct DHFactory;

impl DHFactory {
    pub fn get_supported_groups() -> [u8; 6] {
        [0x9, 0x8, 0x7, 0x3, 0x4, 0xa]
    }

    pub fn get(group: u8) -> DHTypes {
        match group {
            0x7 => DHTypes::ECDH256(ECDHNISTP256),
            0x8 => DHTypes::ECDH384(ECDHNISTP384),
            0x3 => DHTypes::DH5(DH5::new()),
            0x4 => DHTypes::DH15(DH15::new()),
            0x9 => DHTypes::__Nonexhaustive, // P521
            0xa => DHTypes::__Nonexhaustive, //
            _ => unimplemented!(),
        }
    }
}
