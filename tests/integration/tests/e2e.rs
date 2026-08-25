use confidential_lab::run_demo;
use tempfile::tempdir;

#[test]
fn phase1_allowed_and_denied() {
    let allowed_dir = tempdir().unwrap();
    let allowed = run_demo(allowed_dir.path(), 100, 25, 50).expect("allowed demo");
    assert!(allowed.allowed);

    let denied_balance = tempdir().unwrap();
    let denied = run_demo(denied_balance.path(), 20, 25, 50).expect("denied balance demo");
    assert!(!denied.allowed);

    let denied_limit = tempdir().unwrap();
    let denied = run_demo(denied_limit.path(), 100, 60, 50).expect("denied limit demo");
    assert!(!denied.allowed);
}
