#![allow(dead_code)]

use std::io::Write;
use std::env;

#[cfg(feature = "log")]
use log::{Level, LevelFilter};
#[cfg(feature = "log")]
use env_logger::Builder;

use rustdhipv2::time::Instant;

#[cfg(feature = "log")]
pub fn setup_logging_with_clock<F>(filter: &str, since_startup: F)
        where F: Fn() -> Instant + Send + Sync + 'static {
    Builder::new()
        .format(move |buf, record| {
            let elapsed = since_startup();
            let timestamp = format!("[{}]", elapsed);
            if record.target().starts_with("smoltcp::") {
                writeln!(buf, "\x1b[0m{} ({}): {}\x1b[0m", timestamp,
                         record.target().replace("smoltcp::", ""), record.args())
            } else if record.level() == Level::Trace {
                let message = format!("{}", record.args());
                writeln!(buf, "\x1b[37m{} {}\x1b[0m", timestamp,
                         message.replace("\n", "\n             "))
            } else {
                writeln!(buf, "\x1b[32m{} ({}): {}\x1b[0m", timestamp,
                         record.target(), record.args())
            }
        })
        .filter(None, LevelFilter::Trace)
        .parse_filters(filter)
        .parse_filters(&env::var("RUST_LOG").unwrap_or_else(|_| "".to_owned()))
        .init();
}

#[cfg(feature = "log")]
pub fn setup_logging(filter: &str) {
    setup_logging_with_clock(filter, move  || {
        Instant::now()
    })
}