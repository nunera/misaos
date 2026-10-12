use misa_image::tools::run_capture;
use std::{process::Command, time::Duration};

#[test]
fn deadline_covers_inherited_pipes_after_the_direct_child_exits() {
    // A real grandchild keeps stdout/stderr open after its direct parent exits.
    // The tool deadline must still apply while draining those descriptors.
    let error = run_capture(
        Command::new("sh").args(["-c", "sleep 2 &"]),
        Duration::from_millis(100),
        1024,
    )
    .expect_err("an inherited pipe must not outlive the tool deadline");
    assert_eq!(error.code, "E_BUILD");
}
