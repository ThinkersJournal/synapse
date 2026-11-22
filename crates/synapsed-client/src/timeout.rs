// SPDX-License-Identifier: MIT OR Apache-2.0
//! How long the client waits for the daemon, adapted to how long the daemon has been taking
//! (`docs/CLIENT_TIMEOUTS_DESIGN.md`, rules R3 and R4). CireSnave 2026-11-21: *"Can the timeouts be based on
//! a running average so when things take longer it allows them to take longer unless it is excessively
//! longer?"*
//!
//! The method is the TCP retransmission timer (Jacobson/Karels, RFC 6298): a smoothed round trip `srtt` and
//! a smoothed deviation `rttvar`, allowance `srtt + 4 * rttvar`, clamped to `[FLOOR, CEILING]`. Each sample
//! is capped at `CEILING` so one spike does not stretch the average for long, and a request that times out
//! is not a sample: it doubles the next allowance (Karn's rule) until a success.

use std::time::Duration;

/// The shortest allowance, whatever the average says.
pub const FLOOR: Duration = Duration::from_secs(2);
/// The longest allowance: slower than this is excessive and fails.
pub const CEILING: Duration = Duration::from_secs(60);

/// A smoothed latency and deviation, in seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct Estimator {
    smoothed: Option<f64>,
    deviation: f64,
    /// How many timeouts in a row since the last success; each doubles the allowance.
    backoff: u32,
}

impl Estimator {
    /// An estimator that has seen nothing: it answers `FLOOR` (before backoff).
    #[must_use]
    pub fn new() -> Estimator {
        Estimator::default()
    }

    /// Seed from a value another process measured (the daemon's `synapsed-latency.json`): a smoothed
    /// latency and a deviation, each capped at `CEILING`. Anything not finite or negative is ignored.
    #[must_use]
    pub fn seeded(smoothed: Duration, deviation: Duration) -> Estimator {
        let cap = CEILING.as_secs_f64();
        Estimator {
            smoothed: Some(smoothed.as_secs_f64().min(cap)),
            deviation: deviation.as_secs_f64().min(cap),
            backoff: 0,
        }
    }

    /// Record a request that completed in `took`.
    pub fn sample(&mut self, took: Duration) {
        let s = took.as_secs_f64().min(CEILING.as_secs_f64());
        match self.smoothed {
            None => {
                self.smoothed = Some(s);
                self.deviation = s / 2.0;
            }
            Some(avg) => {
                self.deviation = 0.75 * self.deviation + 0.25 * (avg - s).abs();
                self.smoothed = Some(0.875 * avg + 0.125 * s);
            }
        }
        self.backoff = 0;
    }

    /// Record a request that hit its allowance without an answer.
    pub fn timed_out(&mut self) {
        self.backoff = self.backoff.saturating_add(1).min(8);
    }

    /// The smoothed latency, if any sample was seen.
    #[must_use]
    pub fn smoothed(&self) -> Option<Duration> {
        self.smoothed.map(Duration::from_secs_f64)
    }

    /// The smoothed deviation.
    #[must_use]
    pub fn deviation(&self) -> Duration {
        Duration::from_secs_f64(self.deviation)
    }

    /// How long to wait for the next request: `srtt + 4 * rttvar` clamped to `[FLOOR, CEILING]`, doubled
    /// per timeout in a row, never above `CEILING`.
    #[must_use]
    pub fn allowance(&self) -> Duration {
        let base = self
            .smoothed
            .map_or(FLOOR.as_secs_f64(), |avg| avg + 4.0 * self.deviation);
        let scaled = base.clamp(FLOOR.as_secs_f64(), CEILING.as_secs_f64())
            * f64::from(1u32 << self.backoff.min(8));
        Duration::from_secs_f64(scaled.clamp(FLOOR.as_secs_f64(), CEILING.as_secs_f64()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_new_estimator_waits_the_floor() {
        assert_eq!(Estimator::new().allowance(), FLOOR);
    }

    #[test]
    fn the_allowance_grows_with_load_and_shrinks_when_load_drops() {
        let mut e = Estimator::new();
        for _ in 0..20 {
            e.sample(ms(200));
        }
        assert_eq!(e.allowance(), FLOOR, "a quiet daemon stays at the floor");
        for _ in 0..40 {
            e.sample(Duration::from_secs(3));
        }
        let loaded = e.allowance();
        assert!(
            loaded > Duration::from_secs(3) && loaded < CEILING,
            "a slow daemon is given longer than it takes: {loaded:?}"
        );
        for _ in 0..200 {
            e.sample(ms(200));
        }
        assert_eq!(e.allowance(), FLOOR, "and it shrinks back");
    }

    #[test]
    fn one_spike_is_capped_and_does_not_stretch_the_average_for_long() {
        let mut e = Estimator::new();
        for _ in 0..20 {
            e.sample(ms(200));
        }
        e.sample(Duration::from_secs(3600));
        assert!(
            e.smoothed().unwrap() <= Duration::from_secs(9),
            "the sample was capped at the ceiling: {:?}",
            e.smoothed()
        );
        assert!(e.allowance() <= CEILING);
        for _ in 0..60 {
            e.sample(ms(200));
        }
        assert!(
            e.allowance() < Duration::from_secs(5),
            "recovered: {:?}",
            e.allowance()
        );
    }

    #[test]
    fn a_timeout_doubles_the_next_allowance_until_a_success_and_never_passes_the_ceiling() {
        let mut e = Estimator::new();
        e.sample(ms(500));
        let base = e.allowance();
        e.timed_out();
        assert_eq!(e.allowance(), base * 2);
        for _ in 0..20 {
            e.timed_out();
        }
        assert_eq!(
            e.allowance(),
            CEILING,
            "slower than the ceiling is excessive"
        );
        e.sample(ms(500));
        assert!(
            e.allowance() < Duration::from_secs(5),
            "a success resets the backoff"
        );
    }

    #[test]
    fn a_seeded_value_is_capped_at_the_ceiling() {
        let e = Estimator::seeded(Duration::from_secs(10_000), Duration::from_secs(10_000));
        assert_eq!(e.allowance(), CEILING);
        let e = Estimator::seeded(ms(100), ms(10));
        assert_eq!(e.allowance(), FLOOR);
    }
}
