use crate::crypto::{aes, factory::*};
use crate::utils::misc::*;
use core::cmp::Ordering;
use core::convert::TryInto;
use heapless::{consts::*, String};
use managed::ManagedMap;

use crate::{HIPError, Result};

/// Enum to represent AES keys (i.e. ESP keys)
#[derive(Debug, Copy, Clone)]
pub enum AESKeys {
    Aes128([u8; 16]),
    Aes256([u8; 32]),
    Default,
}

#[derive(Debug, Copy, Clone)]
pub enum SAData {
    Typev4([u8; 4]),
    Typev6([u8; 16]),
    Default,
}


#[derive(Debug, Copy, Clone)]
pub struct SecurityAssociationRecord {
    seq: u32,
    spi: Option<u32>,
    aes_key: AESKeys,
    hmac_key: [u8; 32],
    aes_alg: CipherTypes,
    hmac_alg: HMACTypes,
    src: SAData,
    dst: SAData,
}

impl SecurityAssociationRecord {
    pub fn new(
        aes_alg: u8,
        hmac_alg: u8,
        aes_key: &[u8],
        hmac_key: &[u8],
        src: SAData,
        dst: SAData,
    ) -> Self {
        let aeskey_len = aes_key.len();
        let mut aes_128 = [0; 16];
        let mut aes_256 = [0; 32];

        let record = match aeskey_len {
            0x10 => {
                aes_128 = aes_key.try_into().unwrap();
                SecurityAssociationRecord {
                    seq: 1,
                    spi: None,
                    aes_key: AESKeys::Aes128(aes_128),
                    hmac_key: hmac_key.try_into().unwrap(),
                    aes_alg: SymmetricCiphersFactory::get(aes_alg),
                    hmac_alg: HMACFactory::get(hmac_alg),
                    src,
                    dst,
                }
            }
            0x20 => {
                aes_256 = aes_key.try_into().unwrap();
                SecurityAssociationRecord {
                    seq: 1,
                    spi: None,
                    aes_key: AESKeys::Aes256(aes_256),
                    hmac_key: hmac_key.try_into().unwrap(),
                    aes_alg: SymmetricCiphersFactory::get(aes_alg),
                    hmac_alg: HMACFactory::get(hmac_alg),
                    src,
                    dst,
                }
            }
            _ => unimplemented!(),
        };
        record
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

    pub fn get_aes_key(&self) -> AESKeys {
        self.aes_key
    }

    pub fn get_hmac_key(&self) -> [u8; 32] {
        self.hmac_key
    }

    pub fn get_src(&self) -> SAData {
        self.src
    }

    pub fn get_dst(&self) -> SAData {
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
pub struct SARecordStore {
    sa_record_store: [Option<(SAKeyString, SecurityAssociationRecord)>; 5],
}

impl SARecordStore {
    pub fn new() -> SARecordStore {
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
    record: SAMap<'a, SecurityAssociationRecord>,
}

impl<'a> SecurityAssociationDatabase<'a> {
    /// Create a new `SecurityAssociationDatabase`, given a SARecordStore (i.e.
    /// a stack allocated array of optional key, value pairs)
    ///
    /// - Key: concatenated string `src + dst` ipv4 addresses
    /// - Value: an instance of `SecurityAssociationRecord`
    pub fn new(record_store: &'a mut SARecordStore) -> SecurityAssociationDatabase<'a> {
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
    ) -> Result<Option<&SecurityAssociationRecord>> {
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
        val: SecurityAssociationRecord,
    ) -> Result<Option<SecurityAssociationRecord>> {
        let status = match self.record.map_store.insert(SAKeyString { s: sa_key }, val) {
            Ok(val) => match val {
                None => {
                    hip_debug!("(key, value) pair inserted");
                    val
                }
                _ => unreachable!(),
            },
            Err(e) => return Err(HIPError::MapInsertionOpFailed),
        };
        Ok(status)
    }

    /// Removes a key,value pair from the map.
    pub fn remove(&mut self, src: &[u8], dst: &[u8]) -> Result<Option<SecurityAssociationRecord>> {
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
