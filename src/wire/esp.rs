#![deny(unsafe_code)]
#![allow(warnings)]

use byteorder::{ByteOrder, NetworkEndian};
use elliptic_curve::rand_core::block;
// use core::{cmp, fmt, i32, ops};
use core::convert::TryInto;

use super::constants::field;
use crate::{HIPError, Result};

/// A read/write wrapper around a `Encapsulating Security Payload` packet
/// buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct ESPPacket<T> {
    buffer: T,
}

impl<T: AsRef<[u8]>> ESPPacket<T> {
    /// Construct a new unchecked ESP packet struct.
    #[inline]
    pub fn new_unchecked(buffer: T) -> ESPPacket<T> {
        ESPPacket { buffer }
    }

    /// Returns the security parameter index value
    #[inline]
    pub fn get_spi(&self) -> u32 {
        let data = self.buffer.as_ref();
        let spi = NetworkEndian::read_u32(&data[field::ESP_SPI_OFFSET]);
        spi
    }

    /// Returns the value of the `sequence field`
    #[inline]
    pub fn get_sequence(&self) -> u32 {
        let data = self.buffer.as_ref();
        let seq = NetworkEndian::read_u32(&data[field::ESP_SEQUENCE_OFFSET]);
        seq
    }

    /// Returns the value of the `next_header` field.
    ///
    /// Note: This method must only be called only after you call
    /// `get_padded_data`, otherwise you'll get an invalid result.
    #[inline]
    pub fn get_next_header(&self) {
        let data = self.buffer.as_ref();
        let next_header = data[&data.len() - 1];
    }

    /// Consume the packet, returning the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }
}

impl<'a, T: AsRef<[u8]> + AsMut<[u8]> + ?Sized> ESPPacket<&'a mut T> {
    /// Returns a pointer to the `variable length payload` along with padding
    /// bytes, padding length and next header field.
    #[inline]
    pub fn get_payload(&self) -> &'_ [u8] {
        let data = self.buffer.as_ref();
        &data[field::ESP_PAYLOAD_OFFSET]
    }

    /// Returns the slice of padded data (inlcudes the padded length and
    /// next_header fields).
    ///
    /// This method also sets padding data, padding length and next header field
    /// in an ESPPacket buffer and we assume a max cipher block size of 32 bytes
    /// (i.e. AES-256)
    pub fn get_paddded_data(&mut self, block_size: usize, next_header: u8) -> &'_ [u8] {
        let pad_len = block_size - ((self.get_payload().len() + 2) % block_size) & 0xFF;
        let mut max_padding = [0u8; 32]; // assuming AES-256 is the max cipher block size we're using
        let padding = (1..pad_len + 1)
            .enumerate()
            .for_each(|(i, x)| max_padding[i] = i as u8);
        let last_2_bytes = [pad_len as u8, next_header];

        let len = self.get_payload().len();
        let padding_offset = field::ESP_PAYLOAD_OFFSET.start + len;

        let mut _data = self.buffer.as_mut();
        _data[padding_offset..padding_offset + pad_len].copy_from_slice(&max_padding[..pad_len]);
        _data[padding_offset + pad_len..padding_offset + pad_len + 2]
            .copy_from_slice(&last_2_bytes[..]);
        &_data[field::ESP_PAYLOAD_OFFSET.start..padding_offset + pad_len + 2]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ESPPacket<T> {
    /// Initialize an ESP packet i.e. set SPI and SEQUENCE values to `0`.
    #[inline]
    pub fn init_esp_packet(&mut self) {
        let mut _data = self.buffer.as_mut();
        _data = &mut [0; field::ESP_SPI_LENGTH + field::ESP_SEQUENCE_LENGTH];
    }

    /// Set the security parameter index value
    #[inline]
    pub fn set_spi(&mut self, spi: u32) -> Result<()> {
        let mut _data = self.buffer.as_mut();
        Ok(NetworkEndian::write_u32(
            &mut _data[field::ESP_SPI_OFFSET],
            spi,
        ))
    }

    /// Set the value of the `sequence field`
    #[inline]
    pub fn set_sequence(&mut self, seq: u32) -> Result<()> {
        let mut _data = self.buffer.as_mut();
        Ok(NetworkEndian::write_u32(
            &mut _data[field::ESP_SEQUENCE_OFFSET],
            seq,
        ))
    }

    /// Append payload to the ESP buffer
    #[inline]
    pub fn add_payload(&mut self, payload: &[u8]) -> Result<()> {
        let len = payload.len();
        let mut _data = self.buffer.as_mut();
        Ok(
            _data[field::ESP_PAYLOAD_OFFSET.start..field::ESP_PAYLOAD_OFFSET.start + len]
                .copy_from_slice(payload),
        )
    }
}
