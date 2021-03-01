/*! Time structures.

The `time` module contains structures used to represent both
absolute and relative time.

 - [Instant] is used to represent absolute time.
 - [Duration] is used to represet relative time.

[Instant]: struct.Instant.html
[Duration]: struct.Duration.html
*/

// re-export `Duration` and `Instant`
pub use smoltcp::time::{Duration, Instant};
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Timer {
    pub start: Instant,
    pub expires_at: Instant,
    pub duration: Duration,
    pub elapsed_time: Option<Duration>,
}

impl Timer {
    #[cfg(feature = "std")]
    pub fn new(duration: Duration) -> Self {
        Timer {
            start: Instant::now(),
            expires_at: Instant::now() + duration,
            duration,
            elapsed_time: None,
        }
    }

    #[cfg(feature = "std")]
    pub fn get_elapsed_time(&mut self) -> Option<Duration> {
        self.elapsed_time = Some(Instant::now() - self.start);
        self.elapsed_time
    }
}
