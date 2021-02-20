#![allow(warnings)]

use super::constants;
use libc_print::libc_println;
use num_bigint_dig::BigUint;

use heapless::{consts::U21, String};

pub fn DOMAIN_ID() -> String<U21> {
    String::from("nihal.pasham@test.com")
}

pub enum HostIdTypes {
    ECDSAId256([u8; constants::NIST_P_256_LENGTH * 2 + 2]),
    ECDSAId384([u8; constants::NIST_P_384_LENGTH * 2 + 2]),
    ECDSAId160([u8; constants::SECP160R1_LENGTH * 2 + 2]),
    __Nonexhaustive,
}

impl<'a> HostIdTypes {
    pub fn as_bytes(&self) -> &'_ [u8] {
        match self {
            HostIdTypes::ECDSAId256(val) => {val},
            HostIdTypes::ECDSAId384(val) => {val},
            HostIdTypes::ECDSAId160(val) => {val},
            HostIdTypes::__Nonexhaustive => {&[]}
        }
    }
}
// pub struct RSAHostId<'a>(&'a [u8]);

// impl<'a> RSAHostId<'a> {
//     pub fn new_hostid(&self, exp: BigUint, modp: BigUint) {
//         let exponent_bytes = BigUint::to_bytes_be(&exp);
//         let modulus_bytes = BigUint::to_bytes_be(&modp);
//         let exp_len = exponent_bytes.len();
//     }
// }

pub struct ECDSAHostId;

impl ECDSAHostId {
    pub fn get_host_id<const LEN: usize>(x_bytes: &[u8], y_bytes: &[u8]) -> HostIdTypes {
        // let x_bytes = BigUint::to_bytes_be(&x);
        // let y_bytes = BigUint::to_bytes_be(&y);

        if x_bytes.len() != LEN || y_bytes.len() != LEN {
            panic!("Inavlid byte-length x: {:?}, y: {:?}", &x_bytes, &y_bytes);
        }
        match LEN {
            constants::NIST_P_256_LENGTH => {
                let curve_id = [0; 2];
                let mut host_id = [0u8; constants::NIST_P_256_LENGTH * 2 + 2];
                let _temp: &() = &curve_id
                    .iter()
                    .chain(x_bytes.iter())
                    .chain(y_bytes.iter())
                    .enumerate()
                    .map(|(i, x)| host_id[i] = *x)
                    .collect();
                host_id[0] = 0x0;
                host_id[1] = 0x1; // curve id
                HostIdTypes::ECDSAId256(host_id)
            }
            constants::NIST_P_384_LENGTH => {
                let curve_id = [0; 2];
                let mut host_id = [0u8; constants::NIST_P_384_LENGTH * 2 + 2];
                let _temp: &() = &curve_id
                    .iter()
                    .chain(x_bytes.iter())
                    .chain(y_bytes.iter())
                    .enumerate()
                    .map(|(i, x)| host_id[i] = *x)
                    .collect();
                host_id[0] = 0x0;
                host_id[1] = 0x2; // curve id
                HostIdTypes::ECDSAId384(host_id)
            }
            constants::SECP160R1_LENGTH => {
                let curve_id = [0; 2];
                let mut host_id = [0u8; constants::SECP160R1_LENGTH * 2 + 2];
                let _temp: &() = &curve_id
                    .iter()
                    .chain(x_bytes.iter())
                    .chain(y_bytes.iter())
                    .enumerate()
                    .map(|(i, x)| host_id[i] = *x)
                    .collect();
                host_id[0] = 0x0;
                host_id[1] = 0x0; // curve id
                HostIdTypes::ECDSAId160(host_id)
            }
            _ => HostIdTypes::__Nonexhaustive,
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn get_host_id_from_buffer(buf: HostIdTypes) -> ([u8; 2], (BigUint, BigUint)) {
        match buf {
            HostIdTypes::ECDSAId256(buffer) => {
                let curve_id = [buffer[0], buffer[1]];
                let x = &buffer[constants::CURVE_ID_LENGTH
                    ..constants::CURVE_ID_LENGTH + constants::NIST_P_256_LENGTH];
                let y = &buffer[constants::CURVE_ID_LENGTH + constants::NIST_P_256_LENGTH..];
                (
                    curve_id,
                    (BigUint::from_bytes_be(x), BigUint::from_bytes_be(y)),
                )
            }
            HostIdTypes::ECDSAId384(buffer) => {
                let curve_id = [buffer[0], buffer[1]];
                let x = &buffer[constants::CURVE_ID_LENGTH
                    ..constants::CURVE_ID_LENGTH + constants::NIST_P_384_LENGTH];
                let y = &buffer[constants::CURVE_ID_LENGTH + constants::NIST_P_384_LENGTH..];
                (
                    curve_id,
                    (BigUint::from_bytes_be(x), BigUint::from_bytes_be(y)),
                )
            }
            HostIdTypes::ECDSAId160(buffer) => {
                let curve_id = [buffer[0], buffer[1]];
                let x = &buffer[constants::CURVE_ID_LENGTH
                    ..constants::CURVE_ID_LENGTH + constants::SECP160R1_LENGTH];
                let y = &buffer[constants::CURVE_ID_LENGTH + constants::SECP160R1_LENGTH..];
                (
                    curve_id,
                    (BigUint::from_bytes_be(x), BigUint::from_bytes_be(y)),
                )
            }

            HostIdTypes::__Nonexhaustive => unimplemented!(),
        }
    }

    pub fn get_hostid_length(buf: HostIdTypes) -> usize {
        match buf {
            HostIdTypes::ECDSAId256(buffer) => buffer.len(),
            HostIdTypes::ECDSAId384(buffer) => buffer.len(),
            HostIdTypes::ECDSAId160(buffer) => buffer.len(),
            _ => unimplemented!(),
        }
    }

    pub fn get_curve_id(buf: HostIdTypes) -> [u8; 2] {
        match buf {
            HostIdTypes::ECDSAId256(buffer) => [buffer[0], buffer[1]],
            HostIdTypes::ECDSAId384(buffer) => [buffer[0], buffer[1]],
            HostIdTypes::ECDSAId160(buffer) => [buffer[0], buffer[1]],
            _ => unimplemented!(),
        }
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn get_x(buf: HostIdTypes) -> BigUint {
        let host_id = Self::get_host_id_from_buffer(buf);
        host_id.1 .0
    }

    #[cfg(any(feature = "std", feature = "alloc"))]
    pub fn get_y(buf: HostIdTypes) -> BigUint {
        let host_id = Self::get_host_id_from_buffer(buf);
        host_id.1 .1
    }

    pub fn get_algorithm(buf: &HostIdTypes) -> u8 {
        match buf {
            &HostIdTypes::ECDSAId256(_buffer) => constants::HI_ECDSA,
            &HostIdTypes::ECDSAId384(_buffer) => constants::HI_ECDSA,
            &HostIdTypes::ECDSAId160(_buffer) => constants::HI_ECDSA_LOW,
            _ => unimplemented!(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn test_get_host_id() {
        let mut rng1 = ChaCha20Rng::from_seed([13; 32]); // test seed value.
        let mut x_bytes = [0; 48];
        rng1.fill_bytes(&mut x_bytes);
        // let x = BigUint::from_bytes_be(&dest1);

        let mut rng2 = ChaCha20Rng::from_seed([14; 32]); // test seed value.
        let mut y_bytes = [0; 48];
        rng2.fill_bytes(&mut y_bytes);
        // let y = BigUint::from_bytes_be(&dest2);

        let hostid = ECDSAHostId::get_host_id::<48>(&x_bytes, &y_bytes);
        if let HostIdTypes::ECDSAId384(val) = hostid {
            assert_eq!(
                [
                    0, 0, 72, 148, 42, 178, 176, 178, 212, 166, 113, 187, 181, 165, 121, 179, 221,
                    232, 162, 179, 3, 165, 72, 24, 88, 153, 221, 42, 228, 172, 205, 189, 128, 157,
                    186, 28, 253, 242, 141, 158, 230, 37, 88, 229, 171, 32, 45, 222, 22, 77, 248,
                    224, 187, 36, 162, 83, 225, 183, 111, 174, 151, 136, 101, 42, 43, 51, 126, 253,
                    134, 187, 181, 106, 30, 137, 245, 1, 230, 239, 240, 194, 30, 220, 204, 223,
                    174, 28, 20, 77, 6, 91, 2, 87, 71, 153, 129, 80, 60, 137
                ],
                val
            );
            assert_eq!(98, val.len()); // 2 byte curveid + 96 byte public-key
        }
    }

    #[test]
    #[cfg(any(feature = "std", feature = "alloc"))]
    fn test_get_host_id_from_buffer() {
        let mut rng1 = ChaCha20Rng::from_seed([13; 32]); // test seed value.
        let mut x_bytes = [0; 48];
        rng1.fill_bytes(&mut x_bytes);
        // let x = BigUint::from_bytes_be(&dest1);

        let mut rng2 = ChaCha20Rng::from_seed([14; 32]); // test seed value.
        let mut y_bytes = [0; 48];
        rng2.fill_bytes(&mut y_bytes);
        // let y = BigUint::from_bytes_be(&dest2);

        let hostid = ECDSAHostId::get_host_id::<48>(&x_bytes, &y_bytes);
        let host_id_int_form = ECDSAHostId::get_host_id_from_buffer(hostid);
        assert_eq!([0, 2], host_id_int_form.0); // first 2 bytes indicate curve_id
        assert_eq!("48942ab2b0b2d4a671bbb5a579b3dde8a2b303a548185899dd2ae4accdbd809dba1cfdf28d9ee62558e5ab202dde164d", 
            host_id_int_form.1.0.to_str_radix(16));
        assert_eq!("f8e0bb24a253e1b76fae9788652a2b337efd86bbb56a1e89f501e6eff0c21edcccdfae1c144d065b0257479981503c89", 
            host_id_int_form.1.1.to_str_radix(16));
    }
}
