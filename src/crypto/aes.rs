#[allow(warnings)]
use aes::{Aes128, Aes256};
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};

use core::convert::TryInto;

/// Type alias for CBC mode AES128
type Aes128Cbc = Cbc<Aes128, Pkcs7>;
/// Type alias for CBC mode AES256
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

#[derive(Debug, Clone, Copy)]
pub struct AES128CBCCipher;

impl AES128CBCCipher {
    pub fn encrypt(&self, key: &[u8], iv: &[u8], data: &[u8]) -> [u8; 1024] {
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        // buffer must have enough space for message+padding
        let mut buffer = [0u8; 1024];
        // copy message to the buffer
        let pos = data.len();
        buffer[..pos].copy_from_slice(data);
        let _ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        buffer
    }
    pub fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> [u8; 1024] {
        let cipher = Aes128Cbc::new_var(&key, &iv).unwrap();
        let mut buf: [u8; 1024] = ciphertext.try_into().unwrap();
        let _decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
        buf
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AES256CBCCipher;

impl AES256CBCCipher {
    pub fn encrypt(&self, key: &[u8], iv: &[u8], plaintext: &[u8]) -> [u8; 1024] {
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        // buffer must have enough space for message+padding
        let mut buffer = [0u8; 1024];
        // copy message to the buffer
        let pos = plaintext.len();
        buffer[..pos].copy_from_slice(plaintext);
        let _ciphertext = cipher.encrypt(&mut buffer, pos).unwrap();
        buffer
    }
    pub fn decrypt(&self, key: &[u8], iv: &[u8], ciphertext: &[u8]) -> [u8; 1024] {
        let cipher = Aes256Cbc::new_var(&key, &iv).unwrap();
        let mut buf: [u8; 1024] = ciphertext.try_into().unwrap();
        let _decrypted_ciphertext = cipher.decrypt(&mut buf).unwrap();
        buf
    }
}
