use elliptic_curve::subtle::{Choice, ConstantTimeEq, CtOption};
use libc_print::libc_println;

pub enum APTypes {
    P384(MyAffinePoint<48>),
    P521(MyAffinePoint<66>),
    __Nonexhaustive,
}

pub enum BitArrayTypes {
    P384([u8; 48 * 8]),
    P521([u8; 66 * 8]),
    __Nonexhaustive,
}

#[derive(Debug, Clone)]
pub struct MyAffinePoint<const N: usize> {
    pub x: [u8; N],
    pub y: [u8; N],
    pub infinity: Choice,
}

impl<const N: usize> MyAffinePoint<N> {
    /// Returns the base point of a NIST p-cURVE.
    pub fn generator() -> APTypes {
        if N == 48 {
            // NIST P-384 basepoint in affine coordinates:
            // x = aa87ca22 be8b0537 8eb1c71ef 320ad74 6e1d3b62 8ba79b98 59f741e0 82542a38 5502f25d bf55296c 3a545e38 72760ab7
            // y = 3617de4a 96262c6f 5d9e98bf9 292dc29 f8f41dbd 289a147c e9da3113 b5f0b8c0 0a60b1ce 1d7e819d 7a431d7c 90ea0e5f
            APTypes::P384(MyAffinePoint {
                x: [
                    0xaa, 0x87, 0xca, 0x22, 0xbe, 0x8b, 0x05, 0x37, 0x8e, 0xb1, 0xc7, 0x1e, 0xf3,
                    0x20, 0xad, 0x74, 0x6e, 0x1d, 0x3b, 0x62, 0x8b, 0xa7, 0x9b, 0x98, 0x59, 0xf7,
                    0x41, 0xe0, 0x82, 0x54, 0x2a, 0x38, 0x55, 0x02, 0xf2, 0x5d, 0xbf, 0x55, 0x29,
                    0x6c, 0x3a, 0x54, 0x5e, 0x38, 0x72, 0x76, 0x0a, 0xb7,
                ],
                y: [
                    0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f, 0x5d, 0x9e, 0x98, 0xbf, 0x92,
                    0x92, 0xdc, 0x29, 0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c, 0xe9, 0xda,
                    0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0, 0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81,
                    0x9d, 0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
                ],
                infinity: Choice::from(0),
            })
        } else if N == 66 {
            APTypes::__Nonexhaustive
        } else {
            APTypes::__Nonexhaustive
        }
    }

    /// Returns the identity of the group: the point at infinity.
    pub fn identity() -> MyAffinePoint<N> {
        Self {
            x: [0; N],
            y: [0; N],
            infinity: Choice::from(1),
        }
    }

    /// Is this point the identity point?
    pub fn is_identity(&self) -> Choice {
        self.infinity
    }

    pub fn add_infinity(
        pointP: MyAffinePoint<N>,
        a: BigInt,
        b: BigInt,
        modp: BigInt,
    ) -> MyAffinePoint<N> {
        if bool::from(pointP.infinity) {
            Self::identity()
        } else {
            // libc_println!("Infinity: {:?}", &pointP);
            MyAffinePoint {
                x: pointP.x,
                y: pointP.y,
                infinity: Choice::from(0),
            }
        }
    }

    pub fn add_normal(
        &self,
        pointP: MyAffinePoint<N>,
        a: BigInt,
        b: BigInt,
        modp: BigInt,
    ) -> MyAffinePoint<N> {
        if bool::from(self.is_identity()) && bool::from(pointP.infinity) {
            Self::identity()
        } else if bool::from(self.is_identity()) {
            pointP
        } else if bool::from(pointP.infinity) {
            MyAffinePoint {
                x: self.x.clone(),
                y: self.y.clone(),
                infinity: Choice::from(0),
            }
        } else {
            if pointP.x == self.x && pointP.y == self.y {
                let y1 = self.y;
                let x1 = self.x;
                let t = Self::mul_inverse(
                    (2u8 * BigInt::from_bytes_be(Sign::Plus, &y1)) % &modp,
                    modp.clone(),
                );
                let slope = (((3u8
                    * BigInt::from_bytes_be(Sign::Plus, &x1)
                    * BigInt::from_bytes_be(Sign::Plus, &x1))
                    + a)
                    * t)
                    % &modp;
                let x3 =
                    ((&slope * &slope) - (2u8 * BigInt::from_bytes_be(Sign::Plus, &x1))) % &modp;
                let y3 = ((&slope * (BigInt::from_bytes_be(Sign::Plus, &x1) - &x3))
                    - BigInt::from_bytes_be(Sign::Plus, &y1))
                    % &modp;
                libc_println!("x3: {}", &x3);
                libc_println!("y3: {}", &y3);
                MyAffinePoint {
                    x: x3
                        .to_bytes_be()
                        .1
                        .try_into()
                        .expect("failed to serialize Vec<u8> to bytes (x co-ord)"),
                    y: y3
                        .to_bytes_be()
                        .1
                        .try_into()
                        .expect("failed to serialize Vec<u8> to bytes (y co-ord)"),
                    infinity: Choice::from(0),
                }
            } else if BigInt::from_bytes_be(Sign::Plus, &pointP.x)
                == BigInt::from_bytes_be(Sign::Plus, &self.x)
                && BigInt::from_bytes_be(Sign::Plus, &pointP.y)
                    == BigInt::from_bytes_be(Sign::Minus, &self.y)
            {
                Self::identity()
            } else if pointP.x != self.x || pointP.y != self.y {
                let y1 = self.y;
                let x1 = self.x;
                let y2 = pointP.y;
                let x2 = pointP.x;
                let t1 = Self::mul_inverse(
                    (BigInt::from_bytes_be(Sign::Plus, &x2)
                        - BigInt::from_bytes_be(Sign::Plus, &x1)),
                    modp.clone(),
                );
                let slope = (BigInt::from_bytes_be(Sign::Plus, &y2)
                    - (BigInt::from_bytes_be(Sign::Plus, &y1)) * t1)
                    % &modp;
                let x3 = (&slope * &slope
                    - (BigInt::from_bytes_be(Sign::Plus, &x1)
                        - BigInt::from_bytes_be(Sign::Plus, &x2)))
                    % &modp;
                let y3 = (&slope * (BigInt::from_bytes_be(Sign::Plus, &x1) - &x3)
                    - BigInt::from_bytes_be(Sign::Plus, &y1))
                    % &modp;
                libc_println!("xadd: {}", &x3);
                libc_println!("yadd: {}", &y3);
                MyAffinePoint {
                    x: x3.to_bytes_be().1.try_into().unwrap(),
                    y: y3.to_bytes_be().1.try_into().unwrap(),
                    infinity: Choice::from(0),
                }
            } else {
                panic!()
            }
        }
    }

    pub fn double_and_add(
        g: MyAffinePoint<N>,
        k: BigInt,
        a: BigInt,
        b: BigInt,
        modp: BigInt,
    ) -> MyAffinePoint<N> {
        let bits = Self::to_bit_array(k, false);
        let mut p = Self::identity();
        let mut q = g;
        // libc_println!("q_x: {:x?}", &q.x);
        // libc_println!("p_x: {:x?}", &p.x);

        if let BitArrayTypes::P384(bitarray) = bits {
            for i in (0..bitarray.len()) {
                if bitarray[i] == 1 {
                    // libc_println!("{:?}", &q.x);
                    p = Self::add_infinity(q.clone(), a.clone(), b.clone(), modp.clone());
                    if p == Self::identity() {
                        return Self::identity();
                    } else {
                        p = p.add_normal(q.clone(), a.clone(), b.clone(), modp.clone());
                    }
                }
                q = q.add_normal(q.clone(), a.clone(), b.clone(), modp.clone());
            }
            p
        } else {
            unreachable!()
        }
    }

    pub fn to_bit_array(mut scalar: BigInt, reverse: bool) -> BitArrayTypes {
        match N {
            48 => {
                let mut bit_array = [0u8; 48 * 8];
                let mut i = 0;
                while &scalar > &BigInt::from(0u8) {
                    // libc_println!("{}", scalar);
                    let r = scalar.clone() & BigInt::from(1u8);
                    scalar >>= 1;
                    let rclone: [u8; 1] = r.clone().to_bytes_be().1.try_into().unwrap();
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

    pub fn mul_inverse(n: BigInt, modulus: BigInt) -> BigInt {
        let mut a0 = n;
        let mut b0 = modulus.clone();
        let mut t0 = BigInt::from(0u8);
        let mut t = BigInt::from(1u8);
        let mut s0 = BigInt::from(1u8);
        let mut s = BigInt::from(0u8);
        let mut q = a0.clone() / b0.clone();
        let mut r = a0.clone() % b0.clone();
        while &r > &BigInt::from(0u8) {
            let mut temp = &t0 - &q * &t;
            t0 = t.clone();
            t = temp.clone();
            temp = &s0 - &q * &s;
            s0 = s.clone();
            s = temp.clone();
            a0 = b0.clone();
            b0 = r.clone();
            q = &a0 / &b0;
            r = &a0 - &q * &b0;
        }
        r = b0;
        (s % modulus)
    }
}

impl<const N: usize> ConstantTimeEq for MyAffinePoint<N> {
    fn ct_eq(&self, other: &MyAffinePoint<N>) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y) & self.infinity.ct_eq(&other.infinity)
    }
}

impl<const N: usize> Default for MyAffinePoint<N> {
    fn default() -> Self {
        Self::identity()
    }
}

impl<const N: usize> PartialEq for MyAffinePoint<N> {
    fn eq(&self, other: &MyAffinePoint<N>) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for MyAffinePoint<N> {}

   /// `Point doubling and Point addition`. 
    /// This method performs the actual `POINT` doubling and addition operations.
    pub fn add_normal(
        &self,
        pointP: MyAffinePoint<N>,
        a: BigInt,
        b: BigInt,
        modp: BigInt,
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
            if pointP.x == self.x && pointP.y == self.y {
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let t = ((2u8 * &y1) % &modp).mod_inverse(&modp).unwrap();
                let slope = (((3u8 * &x1 * &x1) + a) * t) % &modp;
                let x3 = ((&slope * &slope) - (2u8 * &x1)) % &modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % &modp;

                MyAffinePoint {
                    x: x3,
                    y: y3,
                    infinity: false,
                }
            } else if (pointP.x == self.x) && pointP.y == -self.y.clone() {
                Self::identity()
            } else if pointP.x != self.x || pointP.y != self.y {
                let y1 = self.y.clone();
                let x1 = self.x.clone();
                let y2 = pointP.y;
                let x2 = pointP.x;
                let t1 = (&x2 - &x1).mod_inverse(&modp).unwrap();
                let slope = ((&y2 - &y1) * t1) % &modp;
                let x3 = ((&slope * &slope) - &x1 - &x2) % &modp;
                let y3 = (&slope * (&x1 - &x3) - &y1) % &modp;

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

    // impl<const N: usize> ConstantTimeEq for MyAffinePoint<N> {
//     fn ct_eq(&self, other: &MyAffinePoint<N>) -> Choice {
//         self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y) & self.infinity.ct_eq(&other.infinity)
//     }
// }

// pub fn add_infinity(
//     pointP: MyAffinePoint<N>,
//     a: BigInt,
//     b: BigInt,
//     modp: BigInt,
// ) -> MyAffinePoint<N> {
//     if bool::from(pointP.infinity) {
//         Self::identity()
//     } else {
//         MyAffinePoint {
//             x: pointP.x,
//             y: pointP.y,
//             infinity: false,
//         }
//     }
// }
// impl<const N: usize> PartialEq for MyAffinePoint<N> {
//     fn eq(&self, other: &MyAffinePoint<N>) -> bool {
//         self.ct_eq(other).into()
//     }
// }

// impl<const N: usize> Eq for MyAffinePoint<N> {}

// impl<const N: usize> Mul<NonZeroScalar> for MyAffinePoint<N> {
//     type Output = MyAffinePoint<N>;

//     fn mul(self, scalar: NonZeroScalar) -> Self {
//         (ProjectivePoint::from(self) * scalar.as_ref()).to_affine()
//     }
// }

// pub struct ECDHNIST256 {
//     private_key_size: usize,
//     modp: BigUint,
//     group_order: BigUint,
//     b: BigUint,
//     a: isize,
//     generator_x_coord: BigUint,
//     generator_y_coord: BigUint,
//     cofactor: usize,
//     component_bit_length: usize,
//     pub private_key: NonZeroScalar, // should be private but marked pub for testing
//     pub public_key: PublicKey,
//     pub shared_secret: BigUint, // should be private but marked pub for testing
// }

// impl ECDHNIST256 {

//     pub fn new(seed:[u8;32]) -> Self {

//         let mut rng = ChaCha20Rng::from_seed(seed); // test seed value.
//         let mut dest = [0;32];
//         rng.fill_bytes(&mut dest);
//         let arr = GenericArray::<u8, _>::clone_from_slice(&dest);

//         ECDHNIST256 {
//             private_key_size: 0,
//             modp: BigUint::default(),
//             group_order: BigUint::default(),
//             b: BigUint::default(),
//             a: 0,
//             generator_x_coord: BigUint::default(),
//             generator_y_coord: BigUint::default(),
//             cofactor: 0,
//             component_bit_length: 0x20,
//             private_key: NonZeroScalar::from_repr(arr).expect("Private scalar field initialization failed"),
//             public_key: PublicKey::from_affine(AffinePoint::generator().mul(&ECDHNIST256.private_key)).expect("Public key derivation failed"),
//                 //     x: FieldElement::from_bytes(&arr![u8;
//                 //         0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
//                 //         0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
//                 //         0xd8, 0x98, 0xc2, 0x96
//                 //     ])
//                 //     .unwrap(),
//                 //     y: FieldElement::from_bytes(&arr![u8;
//                 //         0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
//                 //         0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
//                 //         0x37, 0xbf, 0x51, 0xf5
//                 //     ])
//                 //     .unwrap(),
//                 //     infinity: Choice::from(0),
//                 // },
//             shared_secret: BigUint::default(),
//         }
//     }

//     pub fn init_ecdh_nist256(&mut self) {
//         self.private_key_size = constants::ECDH_NIST_256_PVT_KEY_SIZE;
//         self.modp = BigUint::from_bytes_be(&dh::unhexlify_to_bytearray::<32>(
//             &constants::ECDH_NIST_256_MODP.replace("0x", ""),
//         ));
//         self.group_order = BigUint::from_bytes_be(&dh::unhexlify_to_bytearray::<32>(
//             &constants::ECDH_NIST_256_GROUP_ORDER.replace("0x", ""),
//         ));
//         self.b = BigUint::from_bytes_be(&dh::unhexlify_to_bytearray::<32>(
//             &constants::ECDH_NIST_256_B_VAL.replace("0x", "")
//         ));
//         self.generator_x_coord = BigUint::from_bytes_be(&dh::unhexlify_to_bytearray::<32>(
//             &constants::ECDH_NIST_256_GEN_X.replace("0x", "")
//         ));
//         self.generator_y_coord = BigUint::from_bytes_be(&dh::unhexlify_to_bytearray::<32>(
//             &constants::ECDH_NIST_256_GEN_Y.replace("0x", "")
//         ));
//         self.a = -3;
//         self.cofactor = 0x1;
//         self.component_bit_length = 0x20;
//     }

//     pub fn generate_private_key(&mut self, seed:[u8;32]) {
//         // let mut rng = rand::thread_rng();
//         // self.private_key = rng.gen_biguint((self.private_key_size * 8) as u64);

//         let mut rng = ChaCha20Rng::from_seed(seed); // test seed value.
//         let mut dest = [0;32];
//         rng.fill_bytes(&mut dest);
//         if let Ok(secret) = SecretKey::from_bytes(&dest) {
//             self.private_key = secret;
//         }
//     }

//     pub fn generate_pub_key(&mut self) -> Result<PublicKey> {
//         let generator = AffinePoint::generator();
//         let scalar_sk = Scalar::(&self.private_key);
//         if let Some(secret_key) = NonZeroScalar::new(scalar_sk) {
//             self.public_key = PublicKey::from_affine(generator.mul(secret_key))?; // derive public key from secret key
//             Ok(self.public_key)
//         } else{
//             Err(HIPError::ECCError)
//         }
//     }

//     pub fn compute_shared_secret(&mut self, other_party_pub_key: &[u8]) -> Result<()> {
//         let recieved_pub_key = PublicKey::from_sec1_bytes(other_party_pub_key)?;
//         let scalar_sk = Scalar::from(&self.private_key);
//         if let Some(secret_key) = NonZeroScalar::new(scalar_sk) {
//             let shared_secret = recieved_pub_key.as_affine().mul(secret_key);
//             Ok(())
//         } else{
//             Err(HIPError::ECCError)
//         }
//     }

//     pub fn encode_public_key<const N:usize>(&self) -> [u8; N] {
//         let bytes_pub_key = self.public_key.as_affine().to_bytes_point(false);
//         let raw_pub_key_bytes: [u8; N] = bytes_pub_key.as_bytes().try_into().unwrap();
//         raw_pub_key_bytes
//     }

//     pub fn decode_public_key(&self) {

//     }
// }