use std::io::Write;
use std::process::Command as SysCommand;
use std::str::FromStr;

use age::armor::{ArmoredWriter, Format};
use age::secrecy::ExposeSecret;
use age::{Encryptor, Recipient, x25519};
use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

/// Generates a fresh age X25519 identity and returns (identity file path, recipient string).
fn make_identity(dir: &TempDir) -> (String, String) {
    let identity = x25519::Identity::generate();
    let path = dir.path().join("identity.txt");
    std::fs::write(&path, format!("{}\n", identity.to_string().expose_secret())).unwrap();
    let recipient = identity.to_public().to_string();
    (path.display().to_string(), recipient)
}

fn write_plaintext(dir: &TempDir, name: &str, content: &str) -> String {
    let path = dir.path().join(name);
    std::fs::write(&path, content).unwrap();
    path.display().to_string()
}

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

#[test]
fn encrypt_decrypt_round_trip() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain.txt", "round trip content\n");
    let encrypted = dir.path().join("plain.txt.age");
    let decrypted = dir.path().join("out.txt");

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert!(encrypted.exists());

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "decrypt",
            encrypted.to_str().unwrap(),
            "-i",
            &identity,
            "-o",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&decrypted).unwrap(),
        "round trip content\n"
    );
}

#[test]
fn decrypt_accepts_armored_input() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);

    // Produce an armored age file with the age library directly.
    let _key =
        x25519::Identity::from_str(std::fs::read_to_string(&identity).unwrap().trim()).unwrap();
    let recipient_key: Box<dyn Recipient + Send> =
        Box::new(x25519::Recipient::from_str(&recipient).unwrap());
    let encryptor =
        Encryptor::with_recipients(std::iter::once(&*recipient_key as &dyn Recipient)).unwrap();
    let armored_path = dir.path().join("armored.txt.age");
    let file = std::fs::File::create(&armored_path).unwrap();
    let mut writer = encryptor
        .wrap_output(ArmoredWriter::wrap_output(file, Format::AsciiArmor).unwrap())
        .unwrap();
    writer.write_all(b"armored content\n").unwrap();
    let armored = writer.finish().unwrap();
    armored.finish().unwrap();

    let decrypted = dir.path().join("armored.out");
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "decrypt",
            armored_path.to_str().unwrap(),
            "-i",
            &identity,
            "-o",
            decrypted.to_str().unwrap(),
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(&decrypted).unwrap(),
        "armored content\n"
    );
}

#[test]
fn default_output_is_input_with_age_extension() {
    let dir = TempDir::new().unwrap();
    let (_, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain2.txt", "content\n");

    Command::cargo_bin("ykox")
        .unwrap()
        .args(["age", "encrypt", &plaintext, "-r", &recipient])
        .assert()
        .success();
    assert!(dir.path().join("plain2.txt.age").exists());
}

#[test]
fn existing_output_fails_without_force_and_overwrites_with_force() {
    let dir = TempDir::new().unwrap();
    let (_, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain3.txt", "content\n");
    let encrypted = dir.path().join("plain3.txt.age");
    std::fs::write(&encrypted, "stale").unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("output already exists"));

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
            "--force",
        ])
        .assert()
        .success();
    assert!(
        std::fs::read(&encrypted)
            .unwrap()
            .starts_with(b"age-encryption.org/v1")
    );
}

#[test]
fn output_dash_writes_to_stdout() {
    let dir = TempDir::new().unwrap();
    let (_, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain4.txt", "stdout content\n");

    let output = SysCommand::new(env!("CARGO_BIN_EXE_ykox"))
        .args(["age", "encrypt", &plaintext, "-r", &recipient, "-o", "-"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(output.stdout.starts_with(b"age-encryption.org/v1"));
}

#[test]
fn garbage_input_decrypt_fails_cleanly() {
    let dir = TempDir::new().unwrap();
    let (identity, _) = make_identity(&dir);
    let garbage = dir.path().join("garbage.bin");
    std::fs::write(&garbage, b"not an age file at all").unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args(["age", "decrypt", garbage.to_str().unwrap(), "-i", &identity])
        .assert()
        .failure();
}

#[test]
fn decrypt_default_output_strips_age_extension() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain5.txt", "default out\n");
    let encrypted = dir.path().join("plain5.txt.age");

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Decrypting back to the original path hits the overwrite convention.
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "decrypt",
            encrypted.to_str().unwrap(),
            "-i",
            &identity,
            "--force",
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("plain5.txt")).unwrap(),
        "default out\n"
    );
}

#[test]
fn decrypt_without_age_extension_uses_decrypted_suffix() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "plain6-source.txt", "renamed\n");
    let encrypted = dir.path().join("plain6.bin");

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "decrypt",
            encrypted.to_str().unwrap(),
            "-i",
            &identity,
        ])
        .assert()
        .success();
    assert_eq!(
        std::fs::read_to_string(dir.path().join("plain6.bin.decrypted")).unwrap(),
        "renamed\n"
    );
}

#[test]
fn hmac_decrypt_honors_output_before_touching_the_key() {
    let dir = TempDir::new().unwrap();
    let enc = dir.path().join("secret.txt.yk.enc");
    let taken = dir.path().join("elsewhere.txt");
    std::fs::write(&enc, "Salted__").unwrap();
    std::fs::write(&taken, "keep").unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "hmac",
            "decrypt",
            enc.to_str().unwrap(),
            "-o",
            taken.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains(format!(
            "output already exists: {}",
            taken.display()
        )));
    assert_eq!(std::fs::read_to_string(&taken).unwrap(), "keep");
}

#[test]
fn verify_passes_for_a_valid_age_file() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "v.txt", "verify me\n");
    let encrypted = dir.path().join("v.txt.age");

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("ykox")
        .unwrap()
        .args(["verify", encrypted.to_str().unwrap(), "-i", &identity])
        .assert()
        .success()
        .stderr(contains("decrypts"));
}

#[test]
fn verify_fails_for_a_tampered_file() {
    let dir = TempDir::new().unwrap();
    let (identity, recipient) = make_identity(&dir);
    let plaintext = write_plaintext(&dir, "t.txt", "tamper me\n");
    let encrypted = dir.path().join("t.txt.age");

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "age",
            "encrypt",
            &plaintext,
            "-r",
            &recipient,
            "-o",
            encrypted.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Flip one byte in the last chunk.
    let mut data = std::fs::read(&encrypted).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xff;
    std::fs::write(&encrypted, &data).unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args(["verify", encrypted.to_str().unwrap(), "-i", &identity])
        .assert()
        .failure()
        .code(1);
}

#[test]
fn verify_reports_unknown_format() {
    let dir = TempDir::new().unwrap();
    let garbage = dir.path().join("g.bin");
    std::fs::write(&garbage, b"definitely not an encrypted file").unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args(["verify", garbage.to_str().unwrap()])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("unknown file format"));
}

#[test]
fn verify_sig_accepts_authorized_signer() {
    let fixture = |p: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sshsig")
            .join(p)
            .display()
            .to_string()
    };

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            &fixture("plain.txt"),
            "--allowed-signers",
            &fixture("allowed_signers"),
            "--identity",
            "ykoxide-fixtures",
        ])
        .assert()
        .success()
        .stderr(contains("Good"));
}

#[test]
fn verify_sig_with_pubkey() {
    let fixture = |p: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sshsig")
            .join(p)
            .display()
            .to_string()
    };

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            &fixture("plain.txt"),
            "--pubkey",
            &fixture("pubkey.txt"),
        ])
        .assert()
        .success();
}

#[test]
fn verify_sig_rejects_tampered_file() {
    let dir = TempDir::new().unwrap();
    let fixture = |p: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sshsig")
            .join(p)
            .display()
            .to_string()
    };

    let tampered = dir.path().join("tampered.txt");
    std::fs::write(&tampered, "tampered content\n").unwrap();

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            tampered.to_str().unwrap(),
            "--pubkey",
            &fixture("pubkey.txt"),
            "--signature",
            &fixture("plain.txt.sig"),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("bad signature"));
}

#[test]
fn verify_sig_with_allowed_signers_tells_a_modified_file_from_an_unknown_signer() {
    let dir = TempDir::new().unwrap();
    let fixture = |p: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sshsig")
            .join(p)
            .display()
            .to_string()
    };

    let tampered = dir.path().join("tampered.txt");
    std::fs::write(&tampered, "tampered content\n").unwrap();

    // The signer is allowed and its key matches, so the message must point at
    // the contents, not at the principal.
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            tampered.to_str().unwrap(),
            "--allowed-signers",
            &fixture("allowed_signers"),
            "--identity",
            "ykoxide-fixtures",
            "--signature",
            &fixture("plain.txt.sig"),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("the signature does not verify"));

    // A principal that never signed must keep the matcher message.
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            &fixture("plain.txt"),
            "--allowed-signers",
            &fixture("allowed_signers"),
            "--identity",
            "someone-else",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(contains("no allowed signer matched principal someone-else"));
}

#[test]
fn sign_with_plain_key_round_trips() {
    let dir = TempDir::new().unwrap();
    let fixture = |p: &str| {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/sshsig")
            .join(p)
            .display()
            .to_string()
    };

    let signed = dir.path().join("plain.txt.sig");
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "sign",
            &fixture("plain.txt"),
            "--key",
            &fixture("ssh/id_ed25519"),
            "-o",
            signed.to_str().unwrap(),
        ])
        .assert()
        .success();

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "verify-sig",
            &fixture("plain.txt"),
            "--signature",
            signed.to_str().unwrap(),
            "--pubkey",
            &fixture("pubkey.txt"),
        ])
        .assert()
        .success();
}

#[test]
fn sign_rejects_rsa_keys() {
    let dir = TempDir::new().unwrap();
    let key = dir.path().join("id_rsa");
    let file = dir.path().join("plain.txt");
    std::fs::write(&file, "x").unwrap();
    let status = SysCommand::new("ssh-keygen")
        .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
        .arg(&key)
        .status()
        .unwrap();
    assert!(status.success());

    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "sign",
            file.to_str().unwrap(),
            "--key",
            key.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(contains("unsupported key type ssh-rsa"));
    assert!(!dir.path().join("plain.txt.sig").exists());
}

#[test]
fn sign_requires_a_key_source() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("nokey.txt");
    std::fs::write(&file, "x").unwrap();

    // --key and --piv-slot are mutually exclusive groups; without either the
    // default key path is used and fails cleanly when absent.
    Command::cargo_bin("ykox")
        .unwrap()
        .args([
            "sign",
            file.to_str().unwrap(),
            "-o",
            dir.path().join("s.sig").to_str().unwrap(),
        ])
        .assert()
        .failure();
}
