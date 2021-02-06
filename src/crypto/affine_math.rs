#![allow(warnings)]

use core::convert::TryInto;
use elliptic_curve::group;
// use libc_print::libc_println;
use generic_array::GenericArray;
use num_bigint_dig::{BigInt, BigUint, ModInverse, RandBigInt, Sign};
use num_traits::Zero;
use p384::{EncodedPoint, NistP384};

use crate::HIPError;

use super::ecdh::{PkP384, SharedSecretP384};

#[derive(Debug, Clone, PartialEq)]
pub enum APTypes {
    P384(MyAffinePoint<48>),
    P521(MyAffinePoint<66>),
    __Nonexhaustive,
}
#[derive(Debug, Clone, PartialEq)]
pub enum BitArrayTypes {
    P384([u8; 48 * 8]),
    P521([u8; 66 * 8]),
    __Nonexhaustive,
}
#[derive(Debug, Clone, PartialEq)]
pub enum EncodedTypes {
    EncodedTypeP384(PkP384),
    EncodedTypeP384_SS(SharedSecretP384),
    __Nonexhaustive,
}

/// Affine coordinates are the conventional way of expressing elliptic curve
/// points in two dimensional space i.e. (x, y) Typically, `x and y` are 2 very
/// large integers (in the order of say 256 or 384 bits, hence the name). In
/// ECC, points are represented
/// in modulo a prime number.  in the domain
#[derive(Debug, Clone, PartialEq)]
pub struct MyAffinePoint<const N: usize> {
    pub x: BigInt,
    pub y: BigInt,
    pub infinity: bool,
}

impl<const N: usize> MyAffinePoint<N> {
    /// Returns the base point of a NIST p-cURVE.
    pub fn generator() -> APTypes {
        match N {
            // NIST P-384 basepoint in affine coordinates:
            // x = aa87ca22 be8b0537 8eb1c71ef 320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d
            // bf55296c 3a545e38 72760ab7 y = 3617de4a 96262c6f 5d9e98bf9 292dc29 f8f41dbd 289a147c
            // e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
            48 => {
                // Is this expected? The compiler cant seem to tell that the generic constant
                // `N` equals `48`in a `matched` arm. I'm assuming the compiler has access to
                // this information at compile time.
                let x: [u8; 48] = [
                    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
                    0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7,
                    0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29,
                    0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                ];
                let y: [u8; 48] = [
                    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
                    0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda,
                    0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81,
                    0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                ];

                APTypes::P384(MyAffinePoint {
                    x: BigInt::from_bytes_be(Sign::Plus, &x),
                    y: BigInt::from_bytes_be(Sign::Plus, &y),
                    infinity: false,
                })
            }

            66 => APTypes::__Nonexhaustive,
            _ => APTypes::__Nonexhaustive,
        }
    }

    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> MyAffinePoint<N> {
        Self {
            x: Zero::zero(),
            y: Zero::zero(),
            infinity: true,
        }
    }

    /// Is this point the identity point?
    pub fn is_identity(&self) -> bool {
        self.infinity
    }

    /// `Point doubling` and `Point addition`.
    /// This method performs the actual math i.e. `POINT` doubling and addition
    /// operations. Its a texbook implementation taken from RFC https://tools.ietf.org/html/rfc6090#section-3
    pub fn do_the_math(
        &self,
        pointP: MyAffinePoint<N>,
        a: &BigInt,
        b: &BigInt,
        modp: &BigInt,
    ) -> MyAffinePoint<N> {
        if bool::from(self.is_identity()) && bool::from(pointP.infinity) {
            Self::identity()
        } else if bool::from(self.is_identity()) {
            pointP
        } else if bool::from(pointP.infinity) {
            MyAffinePoint {
                x: self.x.clone(),
                y: self.y.clone(),
                infinity: false,
            }
        } else {
            // Point doubling when bitarray[i] == 0
            if pointP.x == self.x && pointP.y == self.y {
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let t = ((2u8 * &y1) % modp).mod_inverse(modp).unwrap();
                let slope = (((3u8 * &x1 * &x1) + a) * t) % modp;
                let x3 = ((&slope * &slope) - (2u8 * &x1)) % modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % modp;
                // libc_println!("double triggered");
                MyAffinePoint {
                    x: x3,
                    y: y3,
                    infinity: false,
                }
            } else if (pointP.x == self.x) && pointP.y == -self.y.clone() {
                Self::identity()
            } else if pointP.x != self.x || pointP.y != self.y {
                // Point addition when bitarray[i] == 1
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let y2 = pointP.y;
                let x2 = pointP.x;
                let t1 = (&x2 - &x1).mod_inverse(modp).unwrap();
                let slope = ((&y2 - &y1) * t1) % modp;
                let x3 = (&slope * &slope - &x1 - &x2) % modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % modp;
                // libc_println!("add triggered");
                MyAffinePoint {
                    x: x3,
                    y: y3,
                    infinity: false,
                }
            } else {
                unreachable!()
            }
        }
    }

    /// Using `group law`, it is easy to `add` points together and to `multiply`
    /// a point by an integer, but very hard to work backwards to `divide` a
    /// point by a number; this asymmetry is the basis for elliptic
    /// curve cryptography.
    ///
    /// This function performs the point doubling and addition operations, given
    /// a nonzero scalar value (i.e. private key) and a generator point or a
    /// public key value (which is just another point). It is used to do 2
    /// things - generate a public key or a shared secret/key.
    pub fn double_and_add(
        g: MyAffinePoint<N>,
        k: BigUint,
        a: &BigInt,
        b: &BigInt,
        modp: &BigInt,
    ) -> MyAffinePoint<N> {
        let bits = Self::to_bit_array(k, false);
        let mut p = Self::identity();
        let mut q = g;
        // let mut counter: u16 = 0;
        match bits {
            BitArrayTypes::P384(bitarray) => {
                for i in 0..bitarray.len() {
                    if bitarray[i] == 1 {
                        if q == Self::identity() {
                            return Self::identity();
                        } else {
                            // counter += 1;
                            // libc_println!("counter: {:?}", &counter);
                            p = p.do_the_math(q.clone(), a, b, modp);
                        }
                    }
                    q = q.do_the_math(q.clone(), a, b, modp);
                }
                if p.y.sign() == Sign::Minus {
                    num_bigint_dig::negate_sign(&mut p.y);
                    p.y = modp - p.y;
                    // libc_println!("p.y:  {:x}", modp - &p.y);
                    p
                } else {
                    p
                }
            }
            _ => Self::identity(),
        }
    }

    /// Returns an array of bits i.e. its elements represent a `scalar` bit
    /// pattern. Note - this function takes a +ve scalar value.
    pub fn to_bit_array(mut scalar: BigUint, reverse: bool) -> BitArrayTypes {
        match N {
            48 => {
                let mut bit_array = [0u8; 48 * 8]; // Need full featured `const_generics` to make this array generic
                let mut i = 0;
                while &scalar > &BigUint::from(0u8) {
                    let r = scalar.clone() & BigUint::from(1u8);
                    scalar >>= 1;
                    let rclone: [u8; 1] = r.clone().to_bytes_be().try_into().unwrap();
                    bit_array[i] = rclone[0];
                    i += 1;
                }
                if reverse {
                    bit_array.reverse();
                }
                BitArrayTypes::P384(bit_array)
            }
            _ => BitArrayTypes::__Nonexhaustive,
        }
    }

    /// A method to transform `MyAffinePoint` types into RustCrypto's
    /// `EncodedPoint`. Encoded points are the uncompressed form of a point on
    /// the curve
    pub fn to_uncompressed_bytes(&self, ss: bool) -> EncodedTypes {
        match N {
            48 => {
                let mut bytes = GenericArray::default();
                let pub_key_x: [u8; N] = self
                    .x
                    .to_bytes_be()
                    .1
                    .try_into()
                    .expect("failed to serialize pub_x to bytearray");
                let pub_key_y: [u8; N] = self
                    .y
                    .to_bytes_be()
                    .1
                    .try_into()
                    .expect("failed to serialize pub_y to bytearray");
                bytes[..pub_key_x.len()].copy_from_slice(&pub_key_x);
                bytes[pub_key_x.len()..].copy_from_slice(&pub_key_y);
                if ss {
                    EncodedTypes::EncodedTypeP384_SS(SharedSecretP384(
                        EncodedPoint::from_untagged_bytes(&bytes),
                    ))
                } else {
                    EncodedTypes::EncodedTypeP384(PkP384(EncodedPoint::from_untagged_bytes(&bytes)))
                }
            }
            _ => EncodedTypes::__Nonexhaustive,
        }
    }

    ///  A method to transform `EncodedPoint` types into `MyAffinePoint` types.
    ///
    /// TODO - `EncodedPoint` type needs to be generic here.
    pub fn from_encoded_point(point: EncodedPoint) -> Self {
        match N {
            48 => {
                let pubkey_x =
                    BigInt::from_bytes_be(Sign::Plus, point.x().map(|x| x.as_slice()).unwrap());
                let pubkey_y =
                    BigInt::from_bytes_be(Sign::Plus, point.y().map(|y| y.as_slice()).unwrap());
                MyAffinePoint {
                    x: pubkey_x,
                    y: pubkey_y,
                    infinity: false,
                }
            }
            _ => unimplemented!(),
        }
    }
}

impl<const N: usize> Default for MyAffinePoint<N> {
    /// Default impl for `MyAffinePoint` point. Returns the identity element.
    fn default() -> Self {
        Self::identity()
    }
}

use super::digest::SHA384Digest;
use super::{constants, dh};
use crate::Result;
use rand;
// use libc_print::libc_println;
/// A `SignerType` struct to sign messages and verify signatures.
#[derive(Debug, Clone, PartialEq)]
pub struct ECSignerType<const N: usize>;

impl<const N: usize> ECSignerType<N> {
    /// Given a message and a signing key, returns the signature.
    ///
    /// `k` used here is an ephemeral scalar value,
    /// As k is a random integer, signatures produced by this func are
    /// non-determinstic
    ///
    /// Note: `RNG` used here is `NOT` cryptographically secure.
    pub fn sign(data: &[u8], sk: &[u8]) -> (BigInt, BigInt) {
        let hash_type = match N {
            48 => SHA384Digest,
            _ => unimplemented!(),
        };

        let (a, b, modp, g_ord) = match N {
            48 => get_p384_constants(),
            _ => unimplemented!(),
        };
        let digest = hash_type.digest(data);
        let e = BigInt::from_bytes_be(Sign::Plus, &digest); // what is `z's` bit-length,
        let z = e; // do we need this - if e.bits() != 8 * N
                   // {panic!("Ln must be equal to {:?} not {:?}", N * 8, e.bits())};
        let mut r: BigInt = Zero::zero();
        let mut s: BigInt = Zero::zero();
        while &r == &BigInt::from(0) || &s == &BigInt::from(0) {
            let mut rng = rand::thread_rng();
            let k = rng.gen_biguint((N * 8 as usize) as usize) % &g_ord.to_biguint().unwrap();
            if k < BigUint::from(1u8) || k > &g_ord.to_biguint().unwrap() - BigUint::from(1u8) {
                panic!("k has to be within group order")
            };
            let gen = MyAffinePoint::<N>::generator();
            let k_mul = match gen {
                APTypes::P384(gen) => MyAffinePoint::<48>::double_and_add(
                    // Scalar multiplication of k with Generator point for the curve
                    gen,
                    k.clone(),
                    &a,
                    &b,
                    &modp,
                ),
                _ => unimplemented!(),
            };

            // Calculate `r` and  `s` components which together constitute an ECDSA
            // signature.
            r = k_mul.x % &g_ord;
            if r != BigInt::from(0) {
                let k_inverse = k.mod_inverse(&g_ord).unwrap();
                let sk_bigint = BigInt::from_bytes_be(Sign::Plus, &sk);
                s = (k_inverse * (&z + (&r * sk_bigint) % &g_ord)) % &g_ord;
                if s != BigInt::from(0) {
                    break;
                }
            }
        }
        (r, s)
    }

    /// Given a `message`, `signature` and the `corresponding public key` of the
    /// private key used to generate the signature, returns a `Ok(true)` value
    /// if verification suceeds or an Error.
    pub fn verify(data: &[u8], signature: &[u8], pk: EncodedPoint) -> Result<bool> {
        // pk here is specific to p384 curve
        if signature.len() != 2 * N {
            // type needs fixing if we want to make this
            panic!("invalid signature: {:?}", signature.len()) // generic
        };

        let hash_type = match N {
            48 => SHA384Digest,
            _ => unimplemented!(),
        };
        let digest = hash_type.digest(data);
        let e = BigInt::from_bytes_be(Sign::Plus, &digest);
        let z = e;

        let (a, b, modp, g_ord) = match N {
            48 => get_p384_constants(),
            _ => unimplemented!(),
        };
        let r_bytes: [u8; N] = signature[..N].try_into().unwrap();
        let s_bytes: [u8; N] = signature[N..].try_into().unwrap();

        let r = BigInt::from_bytes_be(Sign::Plus, &r_bytes);
        let s = BigInt::from_bytes_be(Sign::Plus, &s_bytes);

        if r < BigInt::from(1) || r > &g_ord - BigInt::from(1) {
            return Err(HIPError::SignatureError);
        } else if s < BigInt::from(1) || s > &g_ord - BigInt::from(1) {
            return Err(HIPError::SignatureError);
        }

        // Calculate u1 and u2
        let s_inverse = s.mod_inverse(&g_ord).unwrap();
        let u1 = (z * &s_inverse) % &g_ord;
        let u2 = (&r * &s_inverse) % &g_ord;

        // Calculate curve point (x1, y1) = u1 * G + u2 * P, where G - generator and P -
        // PublicKey
        let gen = MyAffinePoint::<N>::generator();

        // u1 * G - operation
        let u1_mul_result = match gen {
            APTypes::P384(gen) => {
                MyAffinePoint::<48>::double_and_add(gen, u1.to_biguint().unwrap(), &a, &b, &modp)
            }
            _ => unimplemented!(),
        };

        // u2 * P - operation
        let u2_mul_result = match N {
            48 => {
                //Get P - PublicKey in affine-form.
                let affine_pubkey = MyAffinePoint::<48>::from_encoded_point(pk);
                MyAffinePoint::<48>::double_and_add(
                    affine_pubkey,
                    u2.to_biguint().unwrap(),
                    &a,
                    &b,
                    &modp,
                )
            }
            _ => unimplemented!(),
        };
        let result = u1_mul_result.do_the_math(u2_mul_result, &a, &b, &modp); // does point adddition
        if r == (result.x % &g_ord) {
            Ok(true)
        } else {
            Err(HIPError::SignatureError)
        }
    }
}

/// Returns p384 constants as `BigInts`
pub fn get_p384_constants() -> (BigInt, BigInt, BigInt, BigInt) {
    let mod_prime =
        dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_MODP.replace("0x", ""));
    let b_val = dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_B_VAL.replace("0x", ""));
    let group_order =
        dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_GROUP_ORDER.replace("0x", ""));

    let a = BigInt::from(-3);
    let b = BigInt::from_bytes_be(Sign::Plus, &b_val);
    let modp = BigInt::from_bytes_be(Sign::Plus, &mod_prime);
    let g_ord = BigInt::from_bytes_be(Sign::Plus, &group_order);
    (a, b, modp, g_ord)
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_ecc_arithmetic() {
        // Get constants
        let mod_prime =
            dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_MODP.replace("0x", ""));
        let b_val =
            dh::unhexlify_to_bytearray::<48>(&constants::ECDH_NIST_384_B_VAL.replace("0x", ""));

        let a = BigInt::from(-3);
        let b = BigInt::from_bytes_be(Sign::Plus, &b_val);
        let modp = BigInt::from_bytes_be(Sign::Plus, &mod_prime);

        // Generate Private keys
        let mut rng = ChaCha20Rng::from_seed([13; 32]); // test seed value.
        let mut dest = [0; 48];
        rng.fill_bytes(&mut dest);
        let alice_sk = BigUint::from_bytes_be(&dest);
        assert_eq!("11170896102203727991758886450861263973236976793128788009149135622101268823239998037326098942096629308770540425451085", 
            &alice_sk.to_str_radix(10));

        let mut rng2 = ChaCha20Rng::from_seed([14; 32]); // test seed value.
        let mut dest2 = [0; 48];
        rng2.fill_bytes(&mut dest2);
        let bob_sk = BigUint::from_bytes_be(&dest2);
        assert_eq!("38305807842167674311144980997614633981874715198239934499358813886250599395126120530628620894661434226083697393679497", 
            &bob_sk.to_str_radix(10));

        // Derive Public keys
        let gen = MyAffinePoint::<48>::generator();
        let alice_pk = match gen {
            APTypes::P384(gen) => {
                let pub_key =
                    MyAffinePoint::<48>::double_and_add(gen, alice_sk.clone(), &a, &b, &modp);
                assert_eq!("35663529837623977401755290460685567256846537824510335251097307644407536535508948482771609820198489241193807453645240",
                    pub_key.x.to_str_radix(10));
                assert_eq!("9234530617530014052084366936652986971753396189816612717755253268282828822209034972082687982097648090028111755008604", 
                    pub_key.y.to_str_radix(10));
                pub_key
            }
            _ => unreachable!(),
        };

        let gen2 = MyAffinePoint::<48>::generator();
        let bob_pk = match gen2 {
            APTypes::P384(gen) => {
                let pub_key =
                    MyAffinePoint::<48>::double_and_add(gen, bob_sk.clone(), &a, &b, &modp);
                assert_eq!("30069593711305352016485549282471905676652899365420892626543790649161903474985978304504087364444701909930230950800065", 
                    pub_key.x.to_str_radix(10));
                assert_eq!("7036250050345415350123014569446587083000375391345786839287021779342878864411216081360074037536920098601874332666396", 
                    pub_key.y.to_str_radix(10));
                pub_key
            }

            _ => unreachable!(),
        };

        // Evaluate Shared secret keys
        let alice_ss = MyAffinePoint::<48>::double_and_add(bob_pk, alice_sk.clone(), &a, &b, &modp);
        let bob_ss = MyAffinePoint::<48>::double_and_add(alice_pk, bob_sk.clone(), &a, &b, &modp);

        assert_eq!(alice_ss, bob_ss);

        assert_eq!("50404b4bc99c21e8b2f4dfe523dd6344ce37b032840c1996e2de961f58d01c3098f30fa15a0826e15fde412a5e98e849", 
            &alice_ss.x.to_str_radix(16));
        assert_eq!("6b78a7fcf793587bef1f16b307113fa6f86477e0adede50b3f87088ba5ed80952696d710df65814bdacfe6a54d585228", 
            &alice_ss.y.to_str_radix(16));

        assert_eq!("50404b4bc99c21e8b2f4dfe523dd6344ce37b032840c1996e2de961f58d01c3098f30fa15a0826e15fde412a5e98e849", 
            &bob_ss.x.to_str_radix(16));
        assert_eq!("6b78a7fcf793587bef1f16b307113fa6f86477e0adede50b3f87088ba5ed80952696d710df65814bdacfe6a54d585228", 
            &bob_ss.y.to_str_radix(16));
    }
}
