#[cfg(feature = "log")]
macro_rules! hip_log {
    (trace, $($arg:expr),*) => { log::trace!($($arg),*); };
    (debug, $($arg:expr),*) => { log::debug!($($arg),*); };
}

#[cfg(not(feature = "log"))]
#[macro_use]
macro_rules! hip_log {
    ($level:ident, $($arg:expr),*) => { $( let _ = $arg; )* }
}

macro_rules! hip_trace {
    ($($arg:expr),*) => (hip_log!(trace, $($arg),*));
}

macro_rules! hip_debug {
    ($($arg:expr),*) => (hip_log!(debug, $($arg),*));
}
