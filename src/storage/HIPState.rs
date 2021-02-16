#![allow(warnings)]

use super::constants::{self, *};
use hmac::crypto_mac::Key;
use managed::ManagedMap;

use core::fmt;

use libc_print::libc_println;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

/// Struct to represent the various `HIP connection states` i.e.
/// The state of a HIPv2 connection, according to RFC 7401 [4.4.2. HIP States].
///
/// [RFC 7401]: https://tools.ietf.org/html/rfc7401#section-4.4
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    Unassociated,
    I1Sent,
    R1Sent,
    I2Sent,
    R2Sent,
    Established,
    Closing,
    Closed,
    EFailed,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &State::Unassociated => write!(f, "UNASSOCIATED"),
            &State::I1Sent => write!(f, "I1-SENT"),
            &State::R1Sent => write!(f, "R1-SENT"),
            &State::I2Sent => write!(f, "I2-SENT"),
            &State::R2Sent => write!(f, "R2-SENT"),
            &State::Established => write!(f, "ESTABLISHED"),
            &State::Closing => write!(f, "CLOSING"),
            &State::Closed => write!(f, "CLOSED"),
            &State::EFailed => write!(f, "E-FAILED"),
        }
    }
}

impl AsRef<[u8]> for State {
    /// Never call this method. Apparently, its `valid rust` i.e. type checks
    /// but in essence its a infinitely recursive call.
    fn as_ref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl State {
    pub fn init(mut self) {
        self = State::Unassociated;
    }

    pub fn is_unassociated(&self) -> bool {
        self == &State::Unassociated
    }

    pub fn unassociated(mut self) {
        self = State::Unassociated;
    }

    pub fn is_i1_sent(&self) -> bool {
        self == &State::I1Sent
    }

    pub fn i1_sent(mut self) {
        self = State::I1Sent;
    }

    pub fn is_i2_sent(&self) -> bool {
        self == &State::I2Sent
    }

    pub fn i2_sent(mut self) {
        self = State::I2Sent;
    }

    pub fn is_r2_sent(&self) -> bool {
        self == &State::R2Sent
    }

    pub fn r2_sent(mut self) {
        self = State::R2Sent;
    }

    pub fn is_established(&self) -> bool {
        self == &State::Established
    }

    pub fn established(mut self) {
        self = State::Established;
    }
    pub fn is_closing(&self) -> bool {
        self == &State::Closing
    }

    pub fn closing(mut self) {
        self = State::Closing;
    }

    pub fn is_closed(&self) -> bool {
        self == &State::Closed
    }

    pub fn closed(mut self) {
        self = State::Closed;
    }

    pub fn is_failed(&self) -> bool {
        self == &State::EFailed
    }

    pub fn failed(mut self) {
        self = State::EFailed;
    }

    pub fn get_state(&self) -> Self {
        *self
    }
}

/// A wrapper type for `heapless String<U80>`. We need an 80 byte stack
/// allocated string to hold our key. A key is the hex representation of  of 2 *
/// 16-byte slices. (that's `32 * 2 chars in hex + 16 chars for ':' formatting`)
///
/// This allows us to implement the `Ord` trait for a `heapless String<>`.
/// `ManagedMap` has a `Ord trait-bound` for orderable keys
#[derive(Debug, Clone)]
pub struct HeaplessString {
    s: String<U80>,
}

impl Ord for HeaplessString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.s.as_str().cmp(other.s.as_str())
    }
}

impl PartialOrd for HeaplessString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for HeaplessString {
    fn eq(&self, other: &Self) -> bool {
        self.s.as_str() == other.s.as_str()
    }
}

impl Eq for HeaplessString {}

/// A dictionary/map data structure for accessing multiple types of (key, value)
/// pairs.
///
/// Again - just a wrapper type for `ManagedMap`
#[derive(Debug)]
pub struct NoHeapMap<'a, Q> {
    map_store: ManagedMap<'a, HeaplessString, Q>,
}

impl<'a, Q> NoHeapMap<'a, Q> {
    /// Create a `NoHeapMap store`. The backing storage is cleared upon
    /// creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new<T>(storage: T) -> NoHeapMap<'a, Q>
    where
        T: Into<ManagedMap<'a, HeaplessString, Q>>,
    {
        NoHeapMap::new_with_limit(storage)
    }

    pub fn new_with_limit<T>(storage: T) -> NoHeapMap<'a, Q>
    where
        T: Into<ManagedMap<'a, HeaplessString, Q>>,
    {
        let mut map_store = storage.into();
        map_store.clear();

        NoHeapMap { map_store }
    }
}
/// The `HIP State Store`. A wrapper struct to hold 5 (key, value) pairs, each
/// representing a HIP connection and its current state. This is essentially a
/// stack-allocated array that serves as a backing-store for our `NoHeapMap`.
///
/// A `Statemachine` instance mutably borrows a `StateStore` to create a new
/// `NoHeapMap`.
pub struct StateStore {
    hip_state_store: [Option<(HeaplessString, State)>; 5],
}

impl StateStore {
    pub fn new() -> Self {
        StateStore {
            hip_state_store: [None, None, None, None, None],
        }
    }
}

impl Default for StateStore {
    fn default() -> Self {
        StateStore {
            hip_state_store: [None, None, None, None, None],
        }
    }
}

// impl<'a> From<&'a mut [Option<(HeaplessString, State)>; 0]> for StateStore {
//     fn from(_: &'a mut [Option<(HeaplessString, State)>; 0]) -> Self {
//         StateStore {
//             hip_state_store: [None, None, None, None, None],
//         }
//     }
// }

use crate::{
    crypto::ecdh::{PkP256, PkP384, SkP256, SkP384},
    time::Duration,
    utils::misc::{HeaplessStringTypes, Utils},
};
use crate::{HIPError, Result};
use core::{cmp::Ordering, ops::Deref};
use heapless::{consts::*, String};

/// A StateMachine that can be used to track 5 (for now) HIP connections.
///
/// Note: Its just a wrapper around NoHeapMap
pub struct StateMachine<'a> {
    hip_states: NoHeapMap<'a, State>,
}

impl<'a> StateMachine<'a> {
    /// Create a new `StateMachine`, given a HIP StateStore (i.e. a stack
    /// allocated array of optional key, value pairs)
    ///
    /// - Key: concatenated hex formatted string of `ihit + rhit`
    /// - Value: associated state of HIP connection
    pub fn new(state_store: &'a mut StateStore) -> Self {
        let mut hip_states = NoHeapMap::new(&mut state_store.hip_state_store[..]);
        StateMachine { hip_states }
    }

    /// Returns an option containing the `state value` if the key exists, else
    /// returns a `None`.
    ///
    /// The key is constructed by concatenating the raw `initiator and responder
    /// hit` bytes and hex-formatting the concatenated byte-string.
    ///
    /// Note - `HeaplessString` is just a wrapper around an actual `heapless
    /// String<>` type from the heapless crate.
    pub fn get(&mut self, ihit: &[u8], rhit: &[u8]) -> Result<Option<&State>> {
        let key = match Utils::hex_formatted_hit_bytes(Some(ihit), Some(rhit)) {
            Ok(v) => {
                if let HeaplessStringTypes::U64(key) = v {
                    key
                } else {
                    return Err(HIPError::__Nonexhaustive);
                }
            }
            Err(e) => return Err(e),
        };
        if self
            .hip_states
            .map_store
            .get(&HeaplessString { s: key.clone() })
            .is_none()
        {
            self.add_new_key(key.clone());
            Ok(None)
        } else {
            Ok(self.hip_states.map_store.get(&HeaplessString { s: key }))
        }
    }

    /// Adds a new key with a `HIP_STATE_UNASSOCIATED` value to the HIP
    /// StateStore.
    pub fn add_new_key(&mut self, key: String<U80>) {
        self.hip_states
            .map_store
            .insert(HeaplessString { s: key }, State::Unassociated);
    }
}

/// The `Generic Data Store`. A wrapper struct to hold 5 (key, value) pairs,
/// where
/// - a key is a concatenated hex-formatted string of a `ihit + rhit`
/// - values are generic. Values can be of type `dh_storage, keymat_storage,
///   cipher_storage` etc. (essentially a block of bytes)
///
/// This is nothing more than a stack-allocated array that serves as a
/// backing-store for our `NoHeapMap`.
///
/// A `Storage` map instance mutably borrows a `GenericValueStore` to create a
/// new `NoHeapMap`.
///
/// - For now, its limited to 5 keys as `Copy` cant be implemented for
///   `HeaplessString` (a wrapper for `String<U80>`)
#[derive(Debug)]
pub struct GenericValueStore<T> {
    kv_store: [Option<(HeaplessString, T)>; 5],
}

impl<T> GenericValueStore<T> {
    pub fn new(buffer: T) -> Self {
        GenericValueStore {
            kv_store: [None, None, None, None, None],
        }
    }
}

impl<T> Default for GenericValueStore<T> {
    fn default() -> Self {
        GenericValueStore {
            kv_store: [None, None, None, None, None],
        }
    }
}
/// A generic data storage map. `Q` - here is a generic type (i.e. represents
/// the `value` in a key, value pair) which satisfies the trait bound
/// `AsRef<[u8]>`.
///
/// Note - It is simply a wrapper around a `NoHeapMap` (i.e. a ManagedMap)
pub struct Storage<'a, Q> {
    store: NoHeapMap<'a, Q>,
}

impl<'a, Q> Storage<'a, Q> {
    /// Create a new `Storage`, given a Generic DataStore (i.e. a stack
    /// allocated array of optional key, value pairs)
    ///
    /// - Key: concatenated hex formatted string of `ihit + rhit`
    /// - Value: associated state of HIP connection
    pub fn new(generic_store: &'a mut GenericValueStore<Q>) -> Storage<'a, Q> {
        let mut store = NoHeapMap::new(&mut generic_store.kv_store[..]);
        Storage { store }
    }

    /// Returns a result containing an optional `ref` to the `state value` if the key exists, else
    /// returns a `None`.
    ///
    /// The key is constructed by concatenating the raw `initiator and responder
    /// hit` bytes and hex-formatting the concatenated byte-string.
    ///
    /// Note - `HeaplessString` is just a wrapper around an actual `heapless
    /// String<>` type from the heapless crate.
    pub fn get(&mut self, ihit: &[u8], rhit: &[u8]) -> Result<Option<&Q>> {
        let key = match Utils::hex_formatted_hit_bytes(Some(ihit), Some(rhit)) {
            Ok(v) => {
                if let HeaplessStringTypes::U64(key) = v {
                    key
                } else {
                    return Err(HIPError::__Nonexhaustive);
                }
            }
            Err(e) => return Err(e),
        };
        if self
            .store
            .map_store
            .get(&HeaplessString { s: key.clone() })
            .is_none()
        {
            Ok(None)
        } else {
            Ok(self.store.map_store.get(&HeaplessString { s: key }))
        }
    }

    /// Returns a result containing an optional `mutable ref` to the `state value` if the key exists, else
    /// returns a `None`.
    ///
    /// The key is constructed by concatenating the raw `initiator and responder
    /// hit` bytes and hex-formatting the concatenated byte-string.
    ///
    /// Note - `HeaplessString` is just a wrapper around an actual `heapless
    /// String<>` type from the heapless crate.
    pub fn get_mut(&mut self, ihit: &[u8], rhit: &[u8]) -> Result<Option<&mut Q>> {
        let key = match Utils::hex_formatted_hit_bytes(Some(ihit), Some(rhit)) {
            Ok(v) => {
                if let HeaplessStringTypes::U64(key) = v {
                    key
                } else {
                    return Err(HIPError::__Nonexhaustive);
                }
            }
            Err(e) => return Err(e),
        };
        if self
            .store
            .map_store
            .get_mut(&HeaplessString { s: key.clone() })
            .is_none()
        {
            Ok(None)
        } else {
            Ok(self.store.map_store.get_mut(&HeaplessString { s: key }))
        }
    }

    /// Same as `get` but a `heapless String<>` is provided as the input
    /// argument. Returns an option containing the `state value` if the key
    /// exists, else returns a `None`.
    pub fn get_by_key(&self, key: String<U80>) -> Result<Option<&Q>> {
        if self
            .store
            .map_store
            .get(&HeaplessString { s: key.clone() })
            .is_none()
        {
            Ok(None)
        } else {
            Ok(self.store.map_store.get(&HeaplessString { s: key }))
        }
    }

    /// Updates the value for a supplied key or inserts a new key,value pair
    /// into the datastore. Returns a result containing an optional value.
    ///
    /// - `Ok(Some()):` indicates an value for a given key was successfully
    ///   updated
    /// - `Ok(None):`   indicates the supplied key, value pair does not exist
    ///   and attempts to insert it into the store.
    /// - `Err(HIPError):` indicates insertion failed.
    pub fn save(&mut self, ihit: &[u8], rhit: &[u8], val: Q) -> Result<Option<()>> {
        let key = match Utils::hex_formatted_hit_bytes(Some(ihit), Some(rhit)) {
            Ok(v) => {
                if let HeaplessStringTypes::U64(key) = v {
                    key
                } else {
                    return Err(HIPError::__Nonexhaustive);
                }
            }
            Err(e) => return Err(e),
        };
        if self
            .store
            .map_store
            .get(&HeaplessString { s: key.clone() })
            .is_none()
        {
            match self.add_new_key(key, val) {
                Ok(val) => Ok(None),
                Err(e) => return Err(e),
            }
        } else {
            let mut value = self
                .store
                .map_store
                .get_mut(&HeaplessString { s: key })
                .unwrap();
            Ok(Some(*value = val))
        }
    }

    /// Inserts a new key along with the associated value into the map (map
    /// backed by GenericValueStore).
    pub fn add_new_key(&mut self, key: String<U80>, val: Q) -> Result<Q> {
        let status = match self.store.map_store.insert(HeaplessString { s: key }, val) {
            Ok(val) => val.unwrap(),
            Err(e) => return Err(HIPError::MapInsertionOpFailed),
        };
        Ok(status)
    }

    /// Removes a key,value pair from the map.
    pub fn remove(&mut self, ihit: &[u8], rhit: &[u8]) -> Result<Option<Q>> {
        let key = match Utils::hex_formatted_hit_bytes(Some(ihit), Some(rhit)) {
            Ok(v) => {
                if let HeaplessStringTypes::U64(key) = v {
                    key
                } else {
                    return Err(HIPError::__Nonexhaustive);
                }
            }
            Err(e) => return Err(e),
        };
        Ok(self.store.map_store.remove(&HeaplessString { s: key }))
    }

    /// Returns a list  of optional keys. A key is a `optional heapless
    /// String<U80>` (i.e. an 80 byte array represented by a `GenericArray<u8;
    /// U80>`).
    ///
    /// - For now - its limited to 5 keys as `Copy` isnt implemented for
    ///   String<U80>
    pub fn keys(&self) -> [Option<String<U80>>; 5] {
        let mut keys = [None, None, None, None, None];
        let _temp = self
            .store
            .map_store
            .iter()
            .enumerate()
            .for_each(|(i, (k, v))| keys[i] = Some(k.s.clone()));
        keys
    }
}

// impl Deref for HeaplessString {
//     type Target = String<U80>;

//     fn deref(&self) -> &Self::Target {
//         &self.s
//     }
// }

// impl Copy for String<U80> {}

use crate::time::Instant;
use core::convert::TryInto;
// use heapless::Vec;

// const DEFAULT_TIMEOUT_SECONDS: Instant = Instant::from_secs(5);

#[derive(Debug, Clone, Copy)]
pub struct I2Pkt {
    pub buffer: [u8; 512],
    pub len: u16,
}

#[rustfmt::skip]
#[derive(Debug, Clone, Copy)]
pub struct StateVariables {
	state: State,
	rhit: [u8; 16],
	ihit: [u8; 16],
	src:  [u8; 16],
	dst:  [u8; 16],
	// timer: Instant,
	update_timeout: Instant,
	pub i1_timeout: Instant,
	pub i1_retries: u8,
	i2_timeout: Instant,
	i2_retries: u8,
	pub i2_packet: Option<I2Pkt>,
	update_seq: u8,
	pub is_responder: bool,
	pub data_timeout: Instant,
	pub ec_complete_timeout: Instant,
	closing_timeout: Instant,
	closed_timeout:  Instant,
	failed_timeout:  Instant,
}

// #[rustfmt::skip]
impl StateVariables {
    pub fn new(
        state: State,
        ihit: &[u8],
        rhit: &[u8],
        src: &[u8],
        dst: &[u8],
        i2_packet: Option<I2Pkt>,
    ) -> Self {
        StateVariables {
            state: State::Unassociated,
            rhit: rhit.try_into().unwrap(),
            ihit: ihit.try_into().unwrap(),
            src: src.try_into().unwrap(),
            dst: dst.try_into().unwrap(),
            // timer: Instant,
            update_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            i1_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            i1_retries: 0,
            i2_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            i2_retries: 0,
            i2_packet,
            update_seq: 0,
            is_responder: true,
            data_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            ec_complete_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            closing_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            closed_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
            failed_timeout: Instant::now()
                + Duration {
                    millis: (DEFAULT_TIMEOUT_SECONDS * 1000) as u64,
                },
        }
    }
}

pub trait AsByteArray<const N: usize> {
    fn as_bytearray(&self) -> [u8; N];
}
#[derive(Debug, Clone, Copy)]
pub struct KeyInfo {
    /// 16 byte initiator + 16 byte responder hit
    pub info: [u8; 32],
    /// 32 byte irandom + 32 byte jrandom
    pub salt: [u8; 64],
    /// hmac algorithm in use.
    pub alg_id: u8,
}

impl AsByteArray<97> for KeyInfo {
    fn as_bytearray(&self) -> [u8; 97] {
        let mut buf = [0; 97];
        self.info
            .iter()
            .chain(self.salt.iter())
            .chain([self.alg_id; 1].iter())
            .enumerate()
            .for_each(|(i, x)| buf[i] = *x);
        buf
    }
}

impl KeyInfo {
    pub fn new(&mut self, info: &[u8], salt: &[u8], alg_id: u8) {
        self.info = info.try_into().unwrap();
        self.salt = salt.try_into().unwrap();
        self.alg_id = alg_id;
    }
}

/// Enum to represent responder (i.e. remote) public keys
#[derive(Debug, Copy, Clone)]
pub enum ResponderPubKey {
    Pk256([u8; 64]),
    Pk384([u8; 96]),
}

/// Enum to represent the Initiator's keys (i.e. public and private keys)
#[derive(Clone)]
pub enum InitiatorDHKeys {
    EcdhP256(SkP256, PkP256),
    EcdhP384(SkP384, PkP384),
    Default,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn no_key_in_statemachine() {
        let mut hip_state_store = StateStore::new();
        let mut state_machine = StateMachine::new(&mut hip_state_store);

        let ihit = [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb, 0xf4, 0x08, 0x9f, 0x29, 0x5e,
            0x34, 0x5f,
        ];
        let rhit = [
            0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let no_key_val = match state_machine.get(&ihit, &rhit) {
            Ok(v) => v,
            Err(e) => panic!("error: {:?}", e),
        };
        assert_eq!(None, no_key_val);

        let key_val = match state_machine.get(&ihit, &rhit) {
            Ok(v) => v,
            Err(e) => panic!("error: {:?}", e),
        };
        assert_eq!(Some(&State::Unassociated), key_val);
    }
}
