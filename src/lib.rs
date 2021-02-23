#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![deny(unsafe_code)]
#![feature(stmt_expr_attributes)]

#[macro_use]
mod macros;

pub mod crypto;
pub mod daemon;
pub mod storage;
pub mod time;
pub mod utils;
pub mod wire;

use core::fmt;

/// The HIPError type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HIPError {
    /// An operation is not permitted in the current state.
    /// i.e. an invalid HIP state was reached.
    InvalidState,
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// HIP has variable length parameters i.e. contents field length + padding
    /// may be computed at runtime. Variant to indicate if the allocated buffer
    /// is too short.
    Bufferistooshort,
    /// If the length field of a HIP parameter packet is not equal to size of
    /// its contents
    IncorrectHeaderLength,
    /// A HIP parameter packet size has to be a mutiple of 8
    LengthNotMultiple8,
    /// The value of a field in a param packet was already set. Ex: header field
    /// was not set.
    FieldisAlreadySet,
    /// The value of a field in a param packet was not set
    FieldisNOTSet,
    /// Error while performing an EC Crypto operation
    ECCError,
    /// Invalid encoding
    InvalidEncoding,
    /// Signature Error
    SignatureError,
    /// Invalid buffer length
    IncorrectLength,
    /// Key, Value Insertion Failed
    MapInsertionOpFailed,
    /// Unrecongnized is blanket error type for anything that we dont recognize
    /// in HIPv2 standard
    Unrecognized,
    /// A timer expired. Could be a `HIP BEX timeout or data timeout or an impl-specific timeout`
    TimeOut,

    #[doc(hidden)]
    __Nonexhaustive,
}

/// The result type for HIP.
pub type Result<T> = core::result::Result<T, HIPError>;

#[rustfmt::skip]
impl fmt::Display for HIPError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &HIPError::InvalidState             => write!(f, "Invalid State, operation not permitted"),
            &HIPError::Exhausted                => write!(f, "Buffer is empty or full"),
            &HIPError::Bufferistooshort         => write!(f, "Buffer size is insufficent - too small"),
            &HIPError::IncorrectHeaderLength    => write!(f, "Malformed packet"),
            &HIPError::LengthNotMultiple8       => write!(f, "Length has to be multiple of 8"),
            &HIPError::FieldisAlreadySet        => write!(f, "Value of the field was already set"),
            &HIPError::FieldisNOTSet            => write!(f, "Value of the field is not set"),
            &HIPError::ECCError                 => write!(f, "EC Crypto operation failed"),
            &HIPError::InvalidEncoding          => write!(f, "Invalid encoding"),
            &HIPError::SignatureError           => write!(f, "Signature Error"),
            &HIPError::IncorrectLength          => write!(f, "The length of a buffer is invalid"),
            &HIPError::MapInsertionOpFailed     => write!(f, "New key, value insertion failed"),
            &HIPError::Unrecognized             => write!(f, "Unrecognized item"),
            &HIPError::TimeOut                  => write!(f, "Timeout Error"),
            &HIPError::__Nonexhaustive          => unreachable!(),
        }
    }
}

impl From<p256::elliptic_curve::Error> for HIPError {
    fn from(_error: p256::elliptic_curve::Error) -> Self {
        HIPError::ECCError
    }
}
