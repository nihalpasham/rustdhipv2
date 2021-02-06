// #![allow(warnings)]

use core::convert::TryInto;
use core::ops::Mul;

use num_bigint_dig::{BigInt, BigUint, Sign};
use rand_chacha::rand_core::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

use generic_array::{
    typenum::{self, Unsigned},
    ArrayLength, GenericArray,
};

use elliptic_curve::sec1::EncodedPoint as PubKey;
use elliptic_curve::{sec1::UncompressedPointSize, Curve};
use p256::{AffinePoint, NistP256, NonZeroScalar, PublicKey, Scalar};
use p384::{NistP384, SecretKey as P384Secret};

use super::affine_math::{APTypes, EncodedTypes, MyAffinePoint};

use super::{constants, dh};
use crate::{HIPError, Result};

/// Implemented by types that have a fixed-length byte representation
pub trait ToBytes {
    type OutputSize: ArrayLength<u8>;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize>;

    /// Returns the size (in bytes) of this type when serialized
    fn size() -> usize {
        Self::OutputSize::to_usize()
    }
}
/// Implemented by types that can be deserialized from byte representation
pub trait FromBytes: ToBytes + Sized {
    fn from_bytes(bytes: &[u8]) -> Result<Self>;
}
/// An ECDH-P256 private key is simply a scalar in the NIST P-256 field.
#[derive(Clone, Copy)]
pub struct SkP256(NonZeroScalar);
/// An ECDH-P256 public key. This is derived from the private key using scalar
/// point multiplication.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PkP256(p256::PublicKey);

// Everything is serialized and deserialized in uncompressed form
impl ToBytes for PkP256 {
    // A fancy way of saying "65 bytes"
    type OutputSize = UncompressedPointSize<NistP256>;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Get the uncompressed pubkey encoding
        let bytes = p256::EncodedPoint::encode(self.0, false);
        GenericArray::clone_from_slice(bytes.as_bytes())
    }
}

// Everything is serialized and deserialized in uncompressed form
impl FromBytes for PkP256 {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // In order to parse as an uncompressed curve point, we first make sure the
        // input length is correct. This also ensures we're receiving the uncompressed
        // representation.
        if bytes.len() != Self::OutputSize::to_usize() {
            return Err(HIPError::InvalidEncoding);
        }
        // Now just call the routine exposed by the p256 crate. This preserves the
        // invariant that public keys can't be the point at infinity, since the point at
        // infinity has no representation as a SEC1 bytestring.
        let parsed =
            p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| HIPError::InvalidEncoding)?;
        Ok(PkP256(parsed))
    }
}

impl ToBytes for SkP256 {
    // A fancy way of saying "32 bytes"
    type OutputSize = <NistP256 as Curve>::FieldSize;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Many of p256 types like `NonZeroScalar` require `GenericArrays` and to my
        // knowledge, there isnt an easy way way to convert from `Scalars` directly to
        // bytes. So, we still need this. It would be great, if we could switch to
        // const-generics
        self.0.into()
        // arr.as_slice().try_into().expect("Secret Key serialization failed")
    }
}

impl FromBytes for SkP256 {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Check the length
        if bytes.len() != Self::OutputSize::to_usize() {
            return Err(HIPError::InvalidEncoding);
        }
        // Copy the bytes into a fixed-size array
        let arr = GenericArray::<u8, Self::OutputSize>::clone_from_slice(bytes);
        // We do not allow private keys to be 0. This is so that we can avoid checking
        // the output of the P256::kex() function (see docs there for more detail)
        let scalar = Scalar::from_bytes_reduced(&arr);
        let nonzero_scalar = NonZeroScalar::new(scalar).ok_or(HIPError::InvalidEncoding)?;

        Ok(SkP256(nonzero_scalar))
    }
}

/// A struct to hold the computed shared secret.
#[derive(Debug, Clone, PartialEq)]
pub struct SharedSecretP256(pub AffinePoint);

/// We only need the x co-ordinate from the result (i.e. 32 bytes of a
/// coordinate from an Affine Point.)
impl ToBytes for SharedSecretP256 {
    type OutputSize = typenum::U32;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // §4.1: Representation of the KEX result is the serialization of the
        // x-coordinate
        let bytes = p256::EncodedPoint::from(self.0);
        GenericArray::<u8, Self::OutputSize>::clone_from_slice(bytes.x().unwrap())
    }
}

pub trait KeyExchange {
    type SKey: Clone + ToBytes + FromBytes;
    type PubKey: Clone + ToBytes + FromBytes;
    type CompSecret: ToBytes;

    fn generate_private_key(seed: [u8; 32]) -> Self::SKey;
    fn generate_public_key(sk: &Self::SKey) -> Self::PubKey;
    fn generate_shared_secret(sk: &Self::SKey, pk: &Self::PubKey) -> Result<Self::CompSecret>;
}
#[derive(Debug, Clone, Copy)]
pub struct ECDHNISTP256;

impl KeyExchange for ECDHNISTP256 {
    type SKey = SkP256;
    type PubKey = PkP256;
    type CompSecret = SharedSecretP256;

    fn generate_private_key(seed: [u8; 32]) -> Self::SKey {
        let mut rng = ChaCha20Rng::from_seed(seed); // test seed value.
        let mut dest = [0; 32];
        rng.fill_bytes(&mut dest);
        let arr = GenericArray::<u8, _>::clone_from_slice(&dest);
        SkP256(NonZeroScalar::from_repr(arr).expect("Private scalar value initialization failed"))
    }

    fn generate_public_key(sk: &Self::SKey) -> Self::PubKey {
        let affine_pub_key = AffinePoint::generator().mul(sk.0);
        PkP256(PublicKey::from_affine(affine_pub_key).expect("Failed to derive public key"))
    }

    fn generate_shared_secret(
        sk: &Self::SKey,
        others_pk: &Self::PubKey,
    ) -> Result<Self::CompSecret> {
        let shared_secret = others_pk.0.as_affine().mul(sk.0);
        Ok(SharedSecretP256(shared_secret))
    }
}

#[derive(Debug, Clone)]
pub struct SkP384(P384Secret);
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PkP384(pub PubKey<NistP384>);
#[derive(Debug, Clone, PartialEq)]
pub struct SharedSecretP384(pub PubKey<NistP384>);

// Everything is serialized and deserialized in uncompressed form
impl ToBytes for PkP384 {
    // A fancy way of saying "97 bytes"
    type OutputSize = UncompressedPointSize<NistP384>;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Get the uncompressed pubkey encoding
        GenericArray::clone_from_slice(self.0.as_bytes())
    }
}

// Everything is serialized and deserialized in uncompressed form
impl FromBytes for PkP384 {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // In order to parse as an uncompressed curve point, we first make sure the
        // input length is correct. This also ensures we're receiving the uncompressed
        // representation.
        if bytes.len() != Self::OutputSize::to_usize() {
            return Err(HIPError::InvalidEncoding);
        }
        // Now just call the routine exposed by the p256 crate. This preserves the
        // invariant that public keys can't be the point at infinity, since the point at
        // infinity has no representation as a SEC1 bytestring.
        let parsed = PubKey::from_bytes(bytes).map_err(|_| HIPError::InvalidEncoding)?;
        Ok(PkP384(parsed))
    }
}

impl ToBytes for SkP384 {
    // A fancy way of saying "48 bytes"
    type OutputSize = <NistP384 as Curve>::FieldSize;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // Many of p256 types like `NonZeroScalar` require `GenericArrays` and to my
        // knowledge, there isnt an easy way way to convert from `Scalars` directly to
        // bytes. So, we still need this. It would be great, if we could switch to
        // const-generics
        self.0.to_bytes()
        // arr.as_slice().try_into().expect("Secret Key serialization failed")
    }
}

impl FromBytes for SkP384 {
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // Check the length
        if bytes.len() != Self::OutputSize::to_usize() {
            return Err(HIPError::InvalidEncoding);
        }

        Ok(SkP384(
            P384Secret::from_bytes(bytes).expect("Failed to deserialize raw private scalar"),
        ))
    }
}

/// We only need the x co-ordinate from the result (i.e. 48 bytes of a
/// coordinate from an Affine Point.)
impl ToBytes for SharedSecretP384 {
    type OutputSize = typenum::U48;

    fn to_bytes(&self) -> GenericArray<u8, Self::OutputSize> {
        // §4.1: Representation of the KEX result is the serialization of the
        // x-coordinate
        let bytes = p384::EncodedPoint::from(self.0);
        GenericArray::<u8, Self::OutputSize>::clone_from_slice(bytes.x().unwrap())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ECDHNISTP384<const N: usize>;

impl<const N: usize> KeyExchange for ECDHNISTP384<N> {
    type SKey = SkP384;
    type PubKey = PkP384;
    type CompSecret = SharedSecretP384;

    fn generate_private_key(seed: [u8; 32]) -> Self::SKey {
        let mut rng = ChaCha20Rng::from_seed(seed); // test seed value.
        let mut dest = [0; N];
        rng.fill_bytes(&mut dest);
        SkP384(P384Secret::from_bytes(&dest).expect("Failed to generate a `P384` private key"))
    }

    fn generate_public_key(sk: &Self::SKey) -> Self::PubKey {
        let mod_prime =
            dh::unhexlify_to_bytearray::<N>(&constants::ECDH_NIST_384_MODP.replace("0x", ""));
        let b_val =
            dh::unhexlify_to_bytearray::<N>(&constants::ECDH_NIST_384_B_VAL.replace("0x", ""));

        let a = BigInt::from(-3);
        let b = BigInt::from_bytes_be(Sign::Plus, &b_val);
        let modp = BigInt::from_bytes_be(Sign::Plus, &mod_prime);

        let gen = MyAffinePoint::<N>::generator();
        let pk = match gen {
            APTypes::P384(gen) => {
                let pub_key = MyAffinePoint::<48>::double_and_add(
                    gen,
                    BigUint::from_bytes_be(sk.clone().to_bytes().as_slice()),
                    &a,
                    &b,
                    &modp,
                );
                if let EncodedTypes::EncodedTypeP384(pubkey) = pub_key.to_uncompressed_bytes(false)
                {
                    pubkey
                } else {
                    unreachable!() // technically, should be unreachable
                }
            }
            _ => unreachable!(),
        };
        pk
    }

    fn generate_shared_secret(
        sk: &Self::SKey,
        others_pk: &Self::PubKey,
    ) -> Result<Self::CompSecret> {
        let mod_prime =
            dh::unhexlify_to_bytearray::<N>(&constants::ECDH_NIST_384_MODP.replace("0x", ""));
        let b_val =
            dh::unhexlify_to_bytearray::<N>(&constants::ECDH_NIST_384_B_VAL.replace("0x", ""));

        let a = BigInt::from(-3);
        let b = BigInt::from_bytes_be(Sign::Plus, &b_val);
        let modp = BigInt::from_bytes_be(Sign::Plus, &mod_prime);

        if others_pk.0.as_bytes().len() != 97 {
            panic!()
        };
        let pk: [u8; 97] = others_pk
            .0
            .as_bytes()
            .try_into()
            .expect("failed to serialize `EncodedPoint`");
        let affine_pt = MyAffinePoint {
            x: BigInt::from_bytes_be(Sign::Plus, &pk[1..N + 1]),
            y: BigInt::from_bytes_be(Sign::Plus, &pk[N + 1..97]),
            infinity: false,
        };

        let shared_secret = MyAffinePoint::<48>::double_and_add(
            affine_pt,
            BigUint::from_bytes_be(sk.clone().to_bytes().as_slice()),
            &a,
            &b,
            &modp,
        );
        if let EncodedTypes::EncodedTypeP384_SS(sharedsecret) =
            shared_secret.to_uncompressed_bytes(true)
        {
            Ok(sharedsecret)
        } else {
            unreachable!() // technically, should be unreachable
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_ecdh_p256_curve() {
        let alice_sk = ECDHNISTP256::generate_private_key([13; 32]);
        let alice_pk = ECDHNISTP256::generate_public_key(&alice_sk);

        let bob_sk = ECDHNISTP256::generate_private_key([14; 32]);
        let bob_pk = ECDHNISTP256::generate_public_key(&bob_sk);

        let alice_ss = ECDHNISTP256::generate_shared_secret(&alice_sk, &bob_pk);
        let bob_ss = ECDHNISTP256::generate_shared_secret(&bob_sk, &alice_pk);

        assert_eq!(alice_ss, bob_ss);
    }

    #[test]
    fn test_ecdh_p384_curve() {
        let alice_sk = ECDHNISTP384::<48>::generate_private_key([12; 32]);
        let alice_pk = ECDHNISTP384::<48>::generate_public_key(&alice_sk);

        let bob_sk = ECDHNISTP384::<48>::generate_private_key([21; 32]);
        let bob_pk = ECDHNISTP384::<48>::generate_public_key(&bob_sk);

        let alice_ss = ECDHNISTP384::<48>::generate_shared_secret(&alice_sk, &bob_pk);
        let bob_ss = ECDHNISTP384::<48>::generate_shared_secret(&bob_sk, &alice_pk);

        assert_eq!(alice_ss, bob_ss);
    }
}
