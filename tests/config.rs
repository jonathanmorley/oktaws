use assert_cmd::prelude::*;
use predicates::prelude::*;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

// Requires a working test/fixtures/oktaws/test.toml file
#[test]
fn calling_oktaws_against_test_oktaws_config() {
    let config_path = PathBuf::from("tests/fixtures/oktaws/test.toml");
    assert!(config_path.exists());

    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .env("OKTAWS_CONFIG", config_path)
        .assert()
        .success();
}

#[test]
fn calling_oktaws_against_nonexistant_oktaws_config() {
    let home_dir = tempdir().unwrap();

    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .env_remove("OKTAWS_CONFIG")
        .env("HOME", home_dir.path())
        .arg("-v")
        .assert()
        .failure()
        // TODO: Give better error message
        .stderr(predicate::str::contains(format!(
            "INFO - creating \"{}/.config/oktaws\" directory",
            home_dir.path().to_string_lossy()
        )))
        .stderr(predicate::str::contains(format!(
            "INFO - creating \"{}/.config/oktaws/oktaws.toml\" file",
            home_dir.path().to_string_lossy()
        )))
        .stderr(predicate::str::contains(
            r#"Error: No profiles found matching [""]"#,
        ));

    assert!(home_dir.path().join(".config/oktaws/oktaws.toml").exists());
}

#[test]
fn calling_oktaws_against_explicit_nonexistant_oktaws_config() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("oktaws.toml");

    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .env("OKTAWS_CONFIG", &config_path)
        .assert()
        .failure()
        .stderr(format!(
            "Error: config path provided from $OKTAWS_CONFIG ({}) not found\n",
            &config_path.display()
        ));
}

#[test]
fn calling_oktaws_against_directory() {
    let temp = tempdir().unwrap();
    let config_path = temp.path();

    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .env("OKTAWS_CONFIG", config_path)
        .assert()
        .failure()
        .stderr(format!(
            "Error: config at {} is not a file\n",
            config_path.display()
        ));
}

#[test]
fn calling_oktaws_against_unparseable_file() {
    let temp = tempdir().unwrap();
    let config_path = temp.path().join("oktaws.toml");

    std::fs::write(&config_path, "[").unwrap();

    Command::cargo_bin(env!("CARGO_PKG_NAME"))
        .unwrap()
        .env("OKTAWS_CONFIG", &config_path)
        .assert()
        .failure()
        .stderr(format!(
            "Error: unable to parse config from {}: expected a table key, found eof at line 1\n",
            config_path.display()
        ));
}
