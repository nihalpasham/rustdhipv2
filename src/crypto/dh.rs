use num_bigint_dig::{BigUint, RandBigInt};
use rand;

use core::convert::TryInto;

use super::constants;

/// A function to convert (i.e. unhexlify) a hex-string to a byte array.  
///
/// Note: this function uses a generic constant `N` via `const-generics`. At the
/// time of this writing, `c-g` is not yet stable but will be in 2 weeks from
/// now.
pub fn unhexlify_to_bytearray<const N: usize>(prime: &str) -> [u8; N] {
    let mut bytearray = [0; N];
    let hex_string = prime;
    for i in (0..hex_string.len()).step_by(2) {
        if i > (2 * N - 2) {
            break;
        }
        let substring = &hex_string[i..i + 2];
        let z = (u8::from_str_radix(substring, 16)).unwrap();
        bytearray[(i - (i / 2))] = z;
    }
    return bytearray;
}

/// Returns supported DH_GROUPS or an 'Unsupported' error string.
pub fn get_dh(group: u8) -> DH {
    if group == constants::SUPPORTED_DH_GROUPS[0] {
        return DH::Dh5(DH5::new());
    } else if group == constants::SUPPORTED_DH_GROUPS[1] {
        return DH::Dh15(DH15::new());
    } else {
        return DH::UnSupported("UnSupported DH_GROUP");
    }
}

/// Only DH5 and DH15 are supported as per the RFC
#[derive(Debug, PartialEq, Clone)]
pub enum DH {
    Dh5(DH5),
    Dh14(DH14),
    Dh15(DH15),
    Dh16(DH16),
    Dh17(DH17),
    Dh18(DH18),
    UnSupported(&'static str),
}
/// A data struct to hold state for DH_GROUP_ID 5 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH5 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    private_key: BigUint, // should be private but marked pub for testing
    public_key: BigUint,
    shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH5 {
    /// Create a new DH5 group with a prime value `DH_GROUP_5_PRIME`, generator
    /// `2`, and exp_size `192`
    pub fn new() -> Self {
        DH5 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH5 group
    pub fn init_dh5(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<192>(
            &constants::DH_GROUP_5_PRIME
                .replace(" ", "")
                .replace("\n\t", ""),
        );
        self.prime_num = BigUint::from_bytes_be(&prime_byte_arr);
        self.generator = constants::DH_GROUP_5_GENERATOR;
        self.exp_size = constants::DH_GROUP_5_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in a bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

/// A data struct to hold state for DH_GROUP_ID 14 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH14 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    private_key: BigUint, // should be private but marked pub for testing
    public_key: BigUint,
    shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH14 {
    /// Create a new DH14 group with a prime value `DH_GROUP_14_PRIME`,
    /// generator `2`, and exp_size `256`
    pub fn new() -> Self {
        DH14 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH14 group
    pub fn init_dh14(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<256>(
            &constants::DH_GROUP_14_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        self.prime_num = BigUint::from_bytes_le(&prime_byte_arr);
        self.generator = constants::DH_GROUP_14_GENERATOR;
        self.exp_size = constants::DH_GROUP_14_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in an bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

/// A data struct to hold state for DH_GROUP_ID 15 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH15 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    pub private_key: BigUint, // should be private but marked pub for testing
    pub public_key: BigUint,
    pub shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH15 {
    /// Create a new DH15 group with a prime value `DH_GROUP_15_PRIME`,
    /// generator `2`, and exp_size `384`
    pub fn new() -> Self {
        DH15 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH15 group
    pub fn init_dh15(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<384>(
            &constants::DH_GROUP_15_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        self.prime_num = BigUint::from_bytes_le(&prime_byte_arr);
        self.generator = constants::DH_GROUP_15_GENERATOR;
        self.exp_size = constants::DH_GROUP_15_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in an bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

/// A data struct to hold state for DH_GROUP_ID 16 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH16 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    pub private_key: BigUint, // should be private but marked pub for testing
    pub public_key: BigUint,
    pub shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH16 {
    /// Create a new DH16 group with a prime value `DH_GROUP_16_PRIME`,
    /// generator `2`, and exp_size `512`
    pub fn new() -> Self {
        DH16 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH16 group
    pub fn init_dh16(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<512>(
            &constants::DH_GROUP_16_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        self.prime_num = BigUint::from_bytes_le(&prime_byte_arr);
        self.generator = constants::DH_GROUP_16_GENERATOR;
        self.exp_size = constants::DH_GROUP_16_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in an bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

/// A data struct to hold state for DH_GROUP_ID 17 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH17 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    pub private_key: BigUint, // should be private but marked pub for testing
    pub public_key: BigUint,
    pub shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH17 {
    /// Create a new DH17 group with a prime value `DH_GROUP_17_PRIME`,
    /// generator `2`, and exp_size `768`
    pub fn new() -> Self {
        DH17 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH17 group
    pub fn init_dh17(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<768>(
            &constants::DH_GROUP_17_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        self.prime_num = BigUint::from_bytes_le(&prime_byte_arr);
        self.generator = constants::DH_GROUP_17_GENERATOR;
        self.exp_size = constants::DH_GROUP_17_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in an bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

/// A data struct to hold state for DH_GROUP_ID 18 as per RFC - https://tools.ietf.org/html/rfc3526
#[derive(Debug, PartialEq, Clone)]
pub struct DH18 {
    prime_num: BigUint,
    generator: usize,
    exp_size: usize,
    pub private_key: BigUint, // should be private but marked pub for testing
    pub public_key: BigUint,
    pub shared_secret: BigUint, // should be private but marked pub for testing
}

impl DH18 {
    /// Create a new DH18 group with a prime value `DH_GROUP_18_PRIME`,
    /// generator `2`, and exp_size `1024`
    pub fn new() -> Self {
        DH18 {
            prime_num: BigUint::default(),
            generator: 0,
            exp_size: 0,
            private_key: BigUint::default(),
            public_key: BigUint::default(),
            shared_secret: BigUint::default(),
        }
    }

    /// Initialize the DH18 group
    pub fn init_dh18(&mut self) {
        let prime_byte_arr = unhexlify_to_bytearray::<1024>(
            &constants::DH_GROUP_18_PRIME
                .replace(" ", "")
                .replace("\n", "")
                .replace("\t", ""),
        );
        self.prime_num = BigUint::from_bytes_le(&prime_byte_arr);
        self.generator = constants::DH_GROUP_18_GENERATOR;
        self.exp_size = constants::DH_GROUP_18_EXPONENT_LENGTH;
    }

    /// Generate the private key
    pub fn generate_private_key(&mut self) -> BigUint {
        let mut rng = rand::thread_rng();
        self.private_key = rng.gen_biguint((self.exp_size * 8 as usize) as usize);
        // let bytes = Math::bigint_to_bytes(unsigned);
        // self.private_key = Math::bytes_to_bigint(&bytes)
        return self.private_key.clone(); // Need to change the return type to () after
                                         // testing
    }

    /// Generate the public key
    pub fn generate_pubic_key(&mut self) -> BigUint {
        self.public_key = BigUint::from(self.generator).modpow(&self.private_key, &self.prime_num);
        return self.public_key.clone(); // Need to change the return type to () after
                                        // testing
    }

    /// Compute the shared secret
    pub fn compute_shared_secret(&mut self, other_public_key: BigUint) -> BigUint {
        self.shared_secret = other_public_key.modpow(&self.private_key, &self.prime_num);
        self.shared_secret.clone() // Need to change the return type to () after testing
    }

    /// Returns the derived public key in an bytearray.
    pub fn encode_public_key<const N: usize>(&self) -> [u8; N] {
        let pub_key_bytes: [u8; N] = BigUint::to_bytes_be(&self.public_key).try_into().unwrap();
        pub_key_bytes
    }

    /// Given a bytearray representation of the public key, returns a `Bigint`
    pub fn decode_public_key(buffer: &[u8]) -> BigUint {
        BigUint::from_bytes_be(buffer)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_dh_exchange() {
        let mut alice = DH15::new();
        alice.init_dh15();
        let _alice_pk = alice.generate_private_key();
        let alice_pub_key = alice.generate_pubic_key();

        let mut bob = DH15::new();
        bob.init_dh15();
        let _bob_pk = bob.generate_private_key();
        let bob_pub_key = bob.generate_pubic_key();

        let bob_shared_secret = bob.compute_shared_secret(alice_pub_key);
        let alice_shared_secret = alice.compute_shared_secret(bob_pub_key);

        assert_eq!(alice_shared_secret, bob_shared_secret);
    }
}
