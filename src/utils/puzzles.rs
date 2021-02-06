#![allow(warnings)]

use super::{constants, hit::DigestTypes};
use rand::{self, Rng};
use rand_chacha::rand_core::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;

pub struct PuzzleSolver<'a, u8: 'a>(pub &'a mut [u8], pub &'a mut [u8]);

impl<'a> PuzzleSolver<'a, u8> {
    pub fn ltrunc(&mut self, bytestring: &[u8], length: usize) -> &'_ [u8] {
        let req_byte_len = length / constants::BITS_IN_BYTE;
        let partial_bits = length % constants::BITS_IN_BYTE;
        let full_bytes = &bytestring[bytestring.len() - req_byte_len..bytestring.len()];
        if partial_bits > 0 {
            let mask = (2 << partial_bits) - 1;
            let mut max_bytes = [0u8; 33]; // assuming we're using 32-byte random bytestrings for puzzles,
                                           // we'll need a 32+1 sized array
            let _temp: () = [bytestring[bytestring.len() - req_byte_len - 1] & mask]
                .iter()
                .chain(full_bytes.iter())
                .enumerate()
                .map(|(i, x)| max_bytes[i] = *x)
                .collect();
            self.0[..full_bytes.len() + 1].copy_from_slice(&max_bytes[..full_bytes.len() + 1]);
            &self.0[..full_bytes.len() + 1]
        } else {
            self.0[..full_bytes.len()].copy_from_slice(full_bytes);
            &self.0[..full_bytes.len()]
        }
    }

    pub fn solve_puzzle(
        &mut self,
        irandom: &[u8],
        responders_hit: &[u8],
        senders_hit: &[u8],
        difficulty: usize,
        digesttype: &DigestTypes,
    ) -> &'_ [u8] {
        let zero_byte_arr = [0u8; 33];
        let mut expected_solution = &zero_byte_arr[..difficulty / constants::BITS_IN_BYTE];
        if difficulty % constants::BITS_IN_BYTE > 0 {
            expected_solution = &zero_byte_arr[..difficulty / constants::BITS_IN_BYTE + 1];
        }
        let mut jrandom = getrandom::<32>([12; 32]); // gives you a random 32-byte array.
        let rhash = match digesttype {
            DigestTypes::SHA256(v) => v,
            _ => unimplemented!(),
        };

        let mut rng = rand::thread_rng();
        while self.ltrunc(
            &rhash.digest(&{
                let mut bytes = [0; 96]; // irandom + rhit + ihit + jrandom = 96 bytes in total
                let _temp: () = irandom
                    .iter()
                    .chain(responders_hit.iter())
                    .chain(senders_hit.iter())
                    .chain(jrandom.iter())
                    .enumerate()
                    .map(|(i, x)| bytes[i] = *x)
                    .collect();
                bytes
            }),
            difficulty,
        ) != expected_solution
        {
            jrandom = rng.gen();
        }
        self.1.copy_from_slice(&jrandom[..]);
        self.1
    }

    pub fn verify_puzzle(
        &mut self,
        irandom: &[u8],
        jrandom: &[u8],
        responders_hit: &[u8],
        senders_hit: &[u8],
        difficulty: usize,
        digesttype: &DigestTypes,
    ) -> bool {
        let zero_byte_arr = [0u8; 33];
        let mut expected_solution = &zero_byte_arr[..difficulty / constants::BITS_IN_BYTE];
        if difficulty % constants::BITS_IN_BYTE > 0 {
            expected_solution = &zero_byte_arr[..difficulty / constants::BITS_IN_BYTE + 1];
        }
        let rhash = match digesttype {
            DigestTypes::SHA256(v) => v,
            _ => unimplemented!(),
        };
        let mut bytes = [0; 96]; // irandom + rhit + ihit + jrandom = 96 bytes in total
        let _temp: () = irandom
            .iter()
            .chain(responders_hit.iter())
            .chain(senders_hit.iter())
            .chain(jrandom.iter())
            .enumerate()
            .map(|(i, x)| bytes[i] = *x)
            .collect();
        self.ltrunc(&rhash.digest(&bytes), difficulty) == expected_solution
    }
}

pub fn getrandom<const N: usize>(seed: [u8; 32]) -> [u8; N] {
    let mut rng = ChaChaRng::from_seed(seed); // test seed value.
    let mut dest = [0; N];
    rng.fill_bytes(&mut dest);
    dest
}

#[cfg(test)]
mod test {

    use libc_print::libc_println;

    use super::*;
    use crate::crypto::digest::SHA256Digest;
    use core::convert::TryInto;

    #[test]
    fn solve_and_verify_puzzle() {
        let mut i = [0u8; 32];
        let mut j = [0u8; 32];
        let mut solver = PuzzleSolver(&mut i, &mut j);

        let irandom = getrandom::<32>([11; 32]);
        let responders_hit = getrandom::<16>([13; 32]);
        let senders_hit = getrandom::<16>([121; 32]);
        let digesttype = DigestTypes::SHA256(SHA256Digest);
        let difficulty = 16;

        let jrandom: [u8; 32] = solver
            .solve_puzzle(
                &irandom,
                &responders_hit,
                &senders_hit,
                difficulty,
                &digesttype,
            )
            .try_into()
            .unwrap();
        let verify_puzzle = solver.verify_puzzle(
            &irandom,
            &jrandom,
            &responders_hit,
            &senders_hit,
            difficulty,
            &digesttype,
        );

        assert_eq!(verify_puzzle, true);
        assert_eq!(
            irandom,
            [
                111, 87, 233, 204, 14, 77, 25, 13, 145, 211, 248, 46, 169, 133, 16, 120, 223, 90,
                190, 10, 80, 214, 81, 151, 191, 233, 68, 32, 186, 114, 119, 42
            ]
        );
    }
}
