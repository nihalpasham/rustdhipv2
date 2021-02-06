#![allow(warnings)]

use super::constants;
use managed::ManagedMap;

use libc_print::libc_println;

const HEX_CHARS_LOWER: &[u8; 16] = b"0123456789abcdef";

#[derive(Debug, Clone)]
pub struct State {
    state: usize,
}

impl State {
    pub fn init(&mut self) {
        self.state = constants::HIP_STATE_UNASSOCIATED;
    }

    pub fn is_unassociated(&self) -> bool {
        self.state == constants::HIP_STATE_UNASSOCIATED
    }

    pub fn unassociated(&mut self) {
        self.state = constants::HIP_STATE_UNASSOCIATED;
    }

    pub fn is_i1_sent(&self) -> bool {
        self.state == constants::HIP_STATE_I1_SENT
    }

    pub fn is_i2_sent(&self) -> bool {
        self.state == constants::HIP_STATE_I2_SENT
    }

    pub fn i2_sent(&mut self) {
        self.state = constants::HIP_STATE_I2_SENT;
    }

    pub fn is_r2_sent(&self) -> bool {
        self.state == constants::HIP_STATE_R2_SENT
    }

    pub fn r2_sent(&mut self) {
        self.state = constants::HIP_STATE_R2_SENT;
    }

    pub fn is_established(&self) -> bool {
        self.state == constants::HIP_STATE_ESTABLISHED
    }

    pub fn established(&mut self) {
        self.state = constants::HIP_STATE_ESTABLISHED;
    }
    pub fn is_closing(&self) -> bool {
        self.state == constants::HIP_STATE_CLOSING
    }

    pub fn closing(&mut self) {
        self.state = constants::HIP_STATE_CLOSING;
    }

    pub fn is_closed(&self) -> bool {
        self.state == constants::HIP_STATE_CLOSED
    }

    pub fn closed(&mut self) {
        self.state = constants::HIP_STATE_CLOSED;
    }

    pub fn is_failed(&self) -> bool {
        self.state == constants::HIP_STATE_E_FAILED
    }

    pub fn failed(&mut self) {
        self.state = constants::HIP_STATE_E_FAILED;
    }

    // pub fn __str__(self)  {
    //      str(self.state);
    // }

    pub fn get_state(&self) {
        self.state;
    }
}

/// A dictionary/map data structure to hold multiple types of (key, value) pairs.
#[derive(Debug)]
pub struct NoHeapMap<'a> {
    map_store: ManagedMap<'a, &'a str, State>,
}

impl<'a> NoHeapMap<'a> {
    /// Create a `NoHeapMap store`. The backing storage is cleared upon creation.
    ///
    /// # Panics
    /// This function panics if `storage.len() == 0`.
    pub fn new<T>(storage: T) -> NoHeapMap<'a>
    where
        T: Into<ManagedMap<'a, &'a str, State>>,
    {
        NoHeapMap::new_with_limit(storage)
    }

    pub fn new_with_limit<T>(storage: T) -> NoHeapMap<'a>
    where
        T: Into<ManagedMap<'a, &'a str, State>>,
    {
        let mut map_store = storage.into();
        map_store.clear();

        NoHeapMap { map_store }
    }
}

pub struct StateStore<'b> {
    hip_state_store: [Option<(&'b str, State)>; 5],
}

impl<'b> StateStore<'b> {
    pub fn new() -> StateStore<'b> {
        StateStore {
            hip_state_store: [None, None, None, None, None],
        }
    }
}

use heapless::{consts::*, String};

use crate::utils::misc::{HeaplessStringTypes, Utils};
use crate::{HIPError, Result};

/// A StateMachine that can be used to track 5 (for now) HIP connections.
pub struct StateMachine<'a> {
    hip_states: NoHeapMap<'a>,
}

impl<'a> StateMachine<'a> {
    /// Create a new `StateMachine`, given a HIP StateStore (i.e. a dictionary of key, value pairs)
    ///
    /// - Key: concatenated hex formatted string of `ihit + rhit`
    /// - Value: associated state of HIP connection
    pub fn new(state_store: &'a mut StateStore<'a>) -> StateMachine<'a> {
        let mut hip_states = NoHeapMap::new(&mut state_store.hip_state_store[..]);
        StateMachine { hip_states }
    }

    /// Returns state value, given a key.
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
        if self.hip_states.map_store.get(key.as_str()).is_none() {
            self.add_new_key(key.clone());
            Ok(None)
        } else {
            Ok(self.hip_states.map_store.get(key.as_str()))
        }
    }

    pub fn add_new_key(&mut self, key: String<U80>) {
        self.hip_states.map_store.insert(
            key,
            State {
                state: constants::HIP_STATE_UNASSOCIATED,
            },
        );
    }
}
