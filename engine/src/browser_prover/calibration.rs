//! Device calibration for the browser prover (decided 2026-10-23: devices calibrate
//! themselves in the background). A device proves one dummy input of the real circuit when it is
//! idle, once per circuit version, and keeps the measured time on that device only. This module
//! owns the logic of what that measurement means: the device class and the prediction, BEFORE a
//! proof, of whether the proof fits the server's window. The measurement and its storage are
//! glue (the frame host); nothing here reads a clock, a network or a store, and nothing leaves
//! the device.
use crate::Error;
use serde::Serialize;

/// A proof predicted to take at most this share of the window is `Fast`.
pub const FAST_PERCENT: u64 = 30;
/// Up to this share the device is `Ok`.
pub const OK_PERCENT: u64 = 55;
/// Up to this share the device is `Slow`; above it the proof is predicted not to fit. The rest
/// of the window is the margin for preparing, signing and sending the request.
pub const SLOW_PERCENT: u64 = 80;
/// Longest measurement taken at face value (one hour); anything longer is no measurement.
pub const MAX_MEASURED_MILLIS: u64 = 3_600_000;
/// Longest window a prediction is made against (one hour).
pub const MAX_WINDOW_SECONDS: u64 = 3_600;

/// How fast this device proves the real circuit, relative to the server's window.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Fast,
    Ok,
    Slow,
    /// The proof is predicted to overrun the window.
    TooSlow,
}

impl DeviceClass {
    /// The stable wire name shown to the member and kept in events.
    pub const fn key(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Ok => "ok",
            Self::Slow => "slow",
            Self::TooSlow => "too_slow",
        }
    }

    /// Whether a proof is predicted to finish inside the window.
    pub const fn fits(self) -> bool {
        !matches!(self, Self::TooSlow)
    }
}

/// The prediction made before a proof: the class, the measured time it rests on and the
/// window it was made against.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Forecast {
    pub class: DeviceClass,
    pub predicted_millis: u64,
    pub window_seconds: u64,
    pub fits: bool,
}

/// Class of a device whose calibration proof took `measured_millis` against a window of
/// `window_seconds`. Integer arithmetic only: the same inputs give the same class everywhere.
pub fn classify(measured_millis: u64, window_seconds: u64) -> Result<DeviceClass, Error> {
    if measured_millis == 0
        || measured_millis > MAX_MEASURED_MILLIS
        || window_seconds == 0
        || window_seconds > MAX_WINDOW_SECONDS
    {
        return Err(Error::Invalid);
    }
    // measured / (window * 1000) <= percent / 100, without a division.
    let within = |percent: u64| measured_millis * 100 <= window_seconds * 1_000 * percent;
    Ok(if within(FAST_PERCENT) {
        DeviceClass::Fast
    } else if within(OK_PERCENT) {
        DeviceClass::Ok
    } else if within(SLOW_PERCENT) {
        DeviceClass::Slow
    } else {
        DeviceClass::TooSlow
    })
}

/// The prediction for a proof on a device with this measurement.
pub fn forecast(measured_millis: u64, window_seconds: u64) -> Result<Forecast, Error> {
    let class = classify(measured_millis, window_seconds)?;
    Ok(Forecast {
        class,
        predicted_millis: measured_millis,
        window_seconds,
        fits: class.fits(),
    })
}

/// The time a stored measurement is replaced by after a real proof took `actual_millis`: a real
/// proof that took longer than the stored measurement corrects it upward (the device is slower
/// than the dummy proof said); a faster one never lowers it (only a new calibration may).
pub fn corrected(stored_millis: u64, actual_millis: u64) -> u64 {
    stored_millis.max(actual_millis).min(MAX_MEASURED_MILLIS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_class_follows_the_share_of_the_window_with_exact_edges() {
        let window = 100; // 100 s
        for (millis, class) in [
            (1, DeviceClass::Fast),
            (30_000, DeviceClass::Fast),
            (30_001, DeviceClass::Ok),
            (55_000, DeviceClass::Ok),
            (55_001, DeviceClass::Slow),
            (80_000, DeviceClass::Slow),
            (80_001, DeviceClass::TooSlow),
            (MAX_MEASURED_MILLIS, DeviceClass::TooSlow),
        ] {
            assert_eq!(classify(millis, window), Ok(class), "{millis} ms");
        }
    }

    #[test]
    fn a_longer_window_moves_the_edges_with_it() {
        assert_eq!(classify(90_000, 100), Ok(DeviceClass::TooSlow));
        assert_eq!(classify(100_000, 300), Ok(DeviceClass::Ok));
        assert_eq!(classify(90_000, 300), classify(30_000, 100));
    }

    #[test]
    fn a_measurement_or_window_out_of_bounds_is_no_prediction() {
        for (millis, window) in [
            (0, 100),
            (MAX_MEASURED_MILLIS + 1, 100),
            (1_000, 0),
            (1_000, MAX_WINDOW_SECONDS + 1),
        ] {
            assert_eq!(classify(millis, window), Err(Error::Invalid));
            assert_eq!(forecast(millis, window), Err(Error::Invalid));
        }
    }

    #[test]
    fn only_the_too_slow_class_predicts_an_overrun() {
        for class in [DeviceClass::Fast, DeviceClass::Ok, DeviceClass::Slow] {
            assert!(class.fits());
        }
        assert!(!DeviceClass::TooSlow.fits());
        let fast = forecast(10_000, 100).expect("forecast");
        assert_eq!((fast.class, fast.fits), (DeviceClass::Fast, true));
        let slow = forecast(95_000, 100).expect("forecast");
        assert_eq!(
            (slow.class, slow.fits, slow.predicted_millis, slow.window_seconds),
            (DeviceClass::TooSlow, false, 95_000, 100)
        );
    }

    #[test]
    fn the_wire_names_are_closed_and_match_the_serialized_form() {
        let all = [
            DeviceClass::Fast,
            DeviceClass::Ok,
            DeviceClass::Slow,
            DeviceClass::TooSlow,
        ];
        assert_eq!(
            all.map(DeviceClass::key),
            ["fast", "ok", "slow", "too_slow"]
        );
        for class in all {
            assert_eq!(
                serde_json::to_string(&class).expect("json"),
                format!("\"{}\"", class.key())
            );
        }
        assert_eq!(
            serde_json::to_string(&forecast(40_000, 100).expect("forecast")).expect("json"),
            r#"{"class":"ok","predicted_millis":40000,"window_seconds":100,"fits":true}"#
        );
    }

    #[test]
    fn a_real_proof_corrects_a_measurement_upward_only() {
        assert_eq!(corrected(40_000, 70_000), 70_000);
        assert_eq!(corrected(40_000, 20_000), 40_000);
        assert_eq!(corrected(40_000, u64::MAX), MAX_MEASURED_MILLIS);
    }
}
