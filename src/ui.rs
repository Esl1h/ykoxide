//! Human-facing output: everything goes to stderr, data goes to stdout.

pub fn info(msg: impl AsRef<str>) {
    eprintln!("[*] {}", msg.as_ref());
}

pub fn fail(msg: impl AsRef<str>) {
    eprintln!("[✗] {}", msg.as_ref());
}
