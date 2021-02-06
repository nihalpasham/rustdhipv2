// #![allow(warnings)]

use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384};

use core::convert::TryInto;

type HmacSha256 = Hmac<Sha256>;
type HmacSha384 = Hmac<Sha384>;
type HmacSha1 = Hmac<Sha1>;

/// A struct representing a SHA256 HMAC instance
#[derive(Debug, Clone, Copy)]
pub struct SHA256HMAC;

impl SHA256HMAC {
    /// Computes a SHA256 HMAC, given a slice of bytes and a variable length key
    pub fn hmac_256(data: &[u8], key: &[u8]) -> [u8; 32] {
        let mut mac = HmacSha256::new_varkey(key)
            .expect("failed to initialize mac instance with variable size key");
        mac.update(data);
        let mac256: [u8; 32] = mac.finalize().into_bytes().as_slice().try_into().unwrap();
        mac256
    }

    /// Returns the length of SHA256 HMAC
    pub fn get_length() -> u8 {
        0x20
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x1
    }
}

/// A struct representing a SHA384 HMAC instance
#[derive(Debug, Clone, Copy)]
pub struct SHA384HMAC;

impl SHA384HMAC {
    /// Computes a SHA384 HMAC, given a slice of bytes and a variable length key
    pub fn hmac_384(data: &[u8], key: &[u8]) -> [u8; 48] {
        let mut mac = HmacSha384::new_varkey(key)
            .expect("failed to initialize mac instance with variable size key");
        mac.update(data);
        let mac384: [u8; 48] = mac.finalize().into_bytes().as_slice().try_into().unwrap();
        mac384
    }

    /// Returns the length of SHA384 HMAC
    pub fn get_length() -> u8 {
        0x30
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x2
    }
}

/// A struct representing a SHA1 HMAC instance
#[derive(Debug, Clone, Copy)]
pub struct SHA1HMAC;

impl SHA1HMAC {
    /// Computes a SHA1 HMAC, given a slice of bytes and a variable length key
    pub fn hmac_1(data: &[u8], key: &[u8]) -> [u8; 20] {
        let mut mac = HmacSha1::new_varkey(key)
            .expect("failed to initialize mac instance with variable size key");
        mac.update(data);
        let mac1: [u8; 20] = mac.finalize().into_bytes().as_slice().try_into().unwrap();
        mac1
    }

    /// Returns the length of SHA1 HMAC
    pub fn get_length() -> u8 {
        0x14
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x3
    }
}
/// A struct representing a SHA256 Digest instance
pub struct SHA256Digest;

impl SHA256Digest {
    /// Computes the SHA256 digest of a slice of bytes.
    pub fn digest(&self, data: &[u8]) -> [u8; 32] {
        let sha256: [u8; 32] = Sha256::digest(data).as_slice().try_into().unwrap();
        sha256
    }

    /// Returns the length of SHA256 Digest
    pub fn get_length() -> u8 {
        0x20
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x1
    }
}

/// A struct representing a SHA384 Digest instance
pub struct SHA384Digest;

impl SHA384Digest {
    /// Computes the SHA384 digest of a slice of bytes.
    pub fn digest(&self, data: &[u8]) -> [u8; 48] {
        let sha384: [u8; 48] = Sha384::digest(data).as_slice().try_into().unwrap();
        sha384
    }

    /// Returns the length of SHA384 Digest
    pub fn get_length() -> u8 {
        0x30
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x2
    }
}

/// A struct representing a SHA1 Digest instance
pub struct SHA1Digest;

impl SHA1Digest {
    /// Computes the SHA1 digest of a slice of bytes.
    pub fn digest(&self, data: &[u8]) -> [u8; 20] {
        let sha1: [u8; 20] = Sha1::digest(data).as_slice().try_into().unwrap();
        sha1
    }

    /// Returns the length of SHA1 Digest
    pub fn get_length() -> u8 {
        0x14
    }

    /// Returns the Hash algorithm id. This is used to identify the hashing
    /// algorithm in HIPv2
    pub fn get_alg_id() -> u8 {
        0x3
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_digest_function() {
        let data = [12; 48]; // example data in byte form
        let sha256 = SHA256Digest;
        let hash256 = sha256.digest(&data);
        assert_eq!(
            [
                177, 18, 62, 234, 104, 222, 47, 4, 186, 46, 169, 156, 222, 129, 40, 140, 58, 53,
                15, 243, 80, 230, 160, 74, 213, 125, 70, 187, 244, 247, 12, 163
            ],
            hash256
        );
    }

    #[test]
    fn test_sha256hmac() {
        let data = [12; 48]; // example data in byte form
        let key = [22; 52]; // variable length key
        let mac = SHA256HMAC::hmac_256(&data, &key);
        assert_eq!(
            [
                141, 218, 31, 8, 166, 217, 124, 67, 35, 218, 36, 255, 84, 11, 232, 80, 192, 9, 224,
                176, 153, 221, 25, 11, 162, 255, 170, 63, 235, 130, 95, 198
            ],
            mac
        );
        assert_eq!(32, mac.len());
    }
}
