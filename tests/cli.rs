use assert_cmd::Command;

#[test]
fn info_help_exits_zero() {
    Command::cargo_bin("ykox")
        .unwrap()
        .args(["info", "--help"])
        .assert()
        .success();
}

#[test]
fn serial_flag_is_accepted() {
    // Parsing only: no hardware is needed to reject or accept the flag itself.
    Command::cargo_bin("ykox")
        .unwrap()
        .args(["info", "--serial", "12345678"])
        .assert()
        // The key is likely not connected in CI; a clean error is fine, a
        // usage error (code 2) is not.
        .failure()
        .code(1);
}
