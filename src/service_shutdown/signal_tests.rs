use super::*;
use std::io;

#[test]
fn signal_registration_failure_is_finite_and_named() {
    let result = StopSignals::install_with(
        || Err(io::Error::other("injected SIGTERM registration failure")),
        || Err(io::Error::other("injected SIGINT registration failure")),
    );
    match result {
        Ok(_) => panic!("injected signal registration unexpectedly succeeded"),
        Err(error) => {
            let text = error.to_string();
            assert!(text.contains("SIGTERM handler registration failed"), "{text}");
            assert!(!text.contains("SIGINT handler registration failed"), "{text}");
        }
    }
}
