use crate::crypto::factory::*;
use crate::utils::misc::*;
use core::cmp::Ordering;
use heapless::{consts::*, String};
use managed::ManagedMap;

use crate::{HIPError, Result};
#[derive(Debug, Copy, Clone)]
pub struct SecurityAssociationRecord<'a> {
    seq: u32,
    spi: Option<u32>,
    aes_key: &'a [u8],
    hmac_key: &'a [u8],
    aes_alg: CipherTypes,
    hmac_alg: HMACTypes,
    src: [u8; 16],
    dst: [u8; 16],
}

impl<'a> SecurityAssociationRecord<'a> {
    pub fn new(
        aes_alg: u8,
        hmac_alg: u8,
        aes_key: &'a [u8],
        hmac_key: &'a [u8],
        src: [u8; 16],
        dst: [u8; 16],
    ) -> Self {
        SecurityAssociationRecord {
            seq: 1,
            spi: None,
            aes_key,
            hmac_key,
            aes_alg: SymmetricCiphersFactory::get(aes_alg),
            hmac_alg: HMACFactory::get(hmac_alg),
            src,
            dst,
        }
    }

    pub fn get_spi(&self) -> Option<u32> {
        self.spi
    }

    pub fn set_spi(&mut self, spi: u32) {
        self.spi = Some(spi);
    }

    pub fn get_sequence(&self) -> u32 {
        self.seq
    }

    pub fn increment_sequence(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    pub fn get_hmac_alg(&self) -> HMACTypes {
        self.hmac_alg
    }

    pub fn get_aes_alg(&self) -> CipherTypes {
        self.aes_alg
    }

    pub fn get_aes_key(&self) -> &'a [u8] {
        self.aes_key
    }

    pub fn get_hmac_key(&self) -> &'a [u8] {
        self.hmac_key
    }

    pub fn get_src(&self) -> [u8; 16] {
        self.src
    }

    pub fn get_dst(&self) -> [u8; 16] {
        self.dst
    }
}

#[derive(Debug, Clone)]
pub struct SAKeyString {
    s: String<U80>,
}

impl Ord for SAKeyString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.s.as_str().cmp(other.s.as_str())
    }
}

impl PartialOrd for SAKeyString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for SAKeyString {
    fn eq(&self, other: &Self) -> bool {
        self.s.as_str() == other.s.as_str()
    }
}

impl Eq for SAKeyString {}

#[derive(Debug)]
pub struct SAMap<'a, Q> {
    map_store: ManagedMap<'a, SAKeyString, Q>,
}

impl<'a, Q> SAMap<'a, Q> {
    /// Create a `SAMap store`. The backing storage is cleared upon creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new<T>(storage: T) -> SAMap<'a, Q>
    where
        T: Into<ManagedMap<'a, SAKeyString, Q>>,
    {
        SAMap::new_with_limit(storage)
    }

    pub fn new_with_limit<T>(storage: T) -> SAMap<'a, Q>
    where
        T: Into<ManagedMap<'a, SAKeyString, Q>>,
    {
        let mut map_store = storage.into();
        map_store.clear();

        SAMap { map_store }
    }
}
/// The `SA Record Store`. A wrapper struct to hold 5 (key, value) pairs, each
/// representing an ``SA Record` This is essentially a stack-allocated array
/// that serves as a backing-store for our `NoHeapMap`.
///
/// A `SecurityAssociationDatabase` instance mutably borrows a `SARecordStore`
/// to create a new `SAMap`.
pub struct SARecordStore<'a> {
    sa_record_store: [Option<(SAKeyString, SecurityAssociationRecord<'a>)>; 5],
}

impl<'a> SARecordStore<'a> {
    pub fn new() -> SARecordStore<'a> {
        SARecordStore {
            sa_record_store: [None, None, None, None, None],
        }
    }
}
/// A `SecurityAssociationDatabase` that can be used to track 5 (for now) SA
/// records.
///
/// Note: Its just a wrapper around SAMap
pub struct SecurityAssociationDatabase<'a> {
    record: SAMap<'a, SecurityAssociationRecord<'a>>,
}

impl<'a> SecurityAssociationDatabase<'a> {
    /// Create a new `SecurityAssociationDatabase`, given a SARecordStore (i.e.
    /// a stack allocated array of optional key, value pairs)
    ///
    /// - Key: concatenated string `src + dst` ipv4 addresses
    /// - Value: an instance of `SecurityAssociationRecord`
    pub fn new(record_store: &'a mut SARecordStore<'a>) -> SecurityAssociationDatabase<'a> {
        let record = SAMap::new(&mut record_store.sa_record_store[..]);
        SecurityAssociationDatabase { record }
    }

    /// Returns an option containing the `value` if the key exists, else returns
    /// a `None`.
    ///
    /// The key is constructed by concatenating the `stringified bytes` of `src
    /// and dst ipv4 addresses`
    ///
    /// Note - `SAKeyString` is just a wrapper around an actual `heapless
    /// String<>` type from the heapless crate.
    pub fn get_record(
        &mut self,
        src: &[u8],
        dst: &[u8],
    ) -> Result<Option<&SecurityAssociationRecord<'a>>> {
        let mut sa_key: String<U80> = String::new();
        let _src_str = sa_key.push_str(Utils::ipv4_bytes_to_string(src).unwrap().as_str());
        let _dst_str = sa_key.push_str(Utils::ipv4_bytes_to_string(dst).unwrap().as_str());
        if self
            .record
            .map_store
            .get(&SAKeyString { s: sa_key.clone() })
            .is_none()
        {
            Ok(None)
        } else {
            Ok(self.record.map_store.get(&SAKeyString { s: sa_key }))
        }
    }

    /// Inserts a new key along with the associated value into the map (map
    /// backed by SARecordStore).
    pub fn add_record(
        &mut self,
        sa_key: String<U80>,
        val: SecurityAssociationRecord<'a>,
    ) -> Result<SecurityAssociationRecord<'a>> {
        let status = match self.record.map_store.insert(SAKeyString { s: sa_key }, val) {
            Ok(val) => val.unwrap(),
            Err(_e) => return Err(HIPError::MapInsertionOpFailed),
        };
        Ok(status)
    }

    /// Removes a key,value pair from the map.
    pub fn remove(
        &mut self,
        src: &[u8],
        dst: &[u8],
    ) -> Result<Option<SecurityAssociationRecord<'a>>> {
        let mut sa_key: String<U80> = String::new();
        let _src_str = sa_key.push_str(Utils::ipv4_bytes_to_string(src).unwrap().as_str());
        let _dst_str = sa_key.push_str(Utils::ipv4_bytes_to_string(dst).unwrap().as_str());
        if self
            .record
            .map_store
            .get(&SAKeyString { s: sa_key.clone() })
            .is_none()
        {
            Ok(None)
        } else {
            Ok(self.record.map_store.remove(&SAKeyString { s: sa_key }))
        }
    }
}
