//! The Touch ID rung.
//!
//! Two questions, and they are not the same one. `available` asks whether biometrics
//! can be used here at all — it is false on a Mac driving an external display with the
//! lid shut, where the sensor cannot be reached, which is the answer we want even
//! though Apple calls that a bug. `authenticate` asks the person.

use block2::RcBlock;
use objc2::runtime::Bool;
use objc2_foundation::{NSError, NSString};
use objc2_local_authentication::{LAContext, LAPolicy};
use std::sync::mpsc;

const POLICY: LAPolicy = LAPolicy::DeviceOwnerAuthenticationWithBiometrics;

/// There is no timeout case in LAError, so there is no branch for one: the dialog
/// waits until somebody answers it.
pub enum Outcome {
    Approved,
    /// The person said no. Signing stops here rather than asking a different way —
    /// offering the terminal instead would turn a refusal into another question.
    Refused,
    /// Biometrics could not decide, or the person asked for the other way.
    TryAnotherRung,
}

pub fn available() -> bool {
    let context = unsafe { LAContext::new() };
    unsafe { context.canEvaluatePolicy_error(POLICY) }.is_ok()
}

pub fn authenticate(reason: &str) -> Outcome {
    let context = unsafe { LAContext::new() };
    unsafe {
        context.setLocalizedFallbackTitle(Some(&NSString::from_str("改用密碼")));
    }

    let (tx, rx) = mpsc::channel();
    let reply = RcBlock::new(move |granted: Bool, error: *mut NSError| {
        let code = if error.is_null() {
            0
        } else {
            unsafe { (*error).code() }
        };
        let _ = tx.send((granted.as_bool(), code));
    });
    unsafe {
        context.evaluatePolicy_localizedReason_reply(POLICY, &NSString::from_str(reason), &reply);
    }

    match rx.recv() {
        Ok((true, _)) => Outcome::Approved,
        // kLAErrorUserCancel
        Ok((false, -2)) => Outcome::Refused,
        _ => Outcome::TryAnotherRung,
    }
}
