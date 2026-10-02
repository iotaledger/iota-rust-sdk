// Copyright (c) 2026 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

/// How often, and how far apart, the client sends a request again after a
/// [retryable](crate::Error::is_retryable) failure.
///
/// The delay starts at the initial backoff and doubles after every attempt, up
/// to the maximum backoff. The default makes three attempts, waiting 200 ms
/// and then 400 ms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    max_attempts: u32,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl RetryPolicy {
    /// Make up to `max_attempts` attempts in total, with the default backoff.
    /// Zero counts as one.
    pub fn new(max_attempts: u32) -> Self {
        Self {
            max_attempts: max_attempts.max(1),
            ..Self::default()
        }
    }

    /// Send every request once.
    pub fn none() -> Self {
        Self::new(1)
    }

    /// Wait `initial` before the first retry, doubling after every attempt up
    /// to `max`.
    pub fn with_backoff(mut self, initial: Duration, max: Duration) -> Self {
        self.initial_backoff = initial;
        self.max_backoff = max.max(initial);
        self
    }

    /// The number of attempts, including the first.
    pub fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// The delay before attempt `attempt + 1`, where the first attempt is 1.
    pub(crate) fn backoff(&self, attempt: u32) -> Duration {
        let factor = 2u32.saturating_pow(attempt.saturating_sub(1));
        self.initial_backoff
            .saturating_mul(factor)
            .min(self.max_backoff)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(2),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_the_maximum() {
        let policy = RetryPolicy::new(10)
            .with_backoff(Duration::from_millis(100), Duration::from_millis(500));
        let delays = (1..=5).map(|attempt| policy.backoff(attempt).as_millis());
        assert_eq!(delays.collect::<Vec<_>>(), [100, 200, 400, 500, 500]);
    }

    #[test]
    fn at_least_one_attempt() {
        assert_eq!(RetryPolicy::new(0).max_attempts(), 1);
        assert_eq!(RetryPolicy::none().max_attempts(), 1);
    }
}
