use assert_cmd::prelude::*;
use failure::Error;
use std::path::PathBuf;
use std::process::Command;
use tempfile::tempdir;

// Requires a working test/fixtures/oktaws/test.toml file
#[test]
fn calling_oktaws_against_test_okta() -> Result<(), Error> {
    let oktaws_dir = PathBuf::from("tests/fixtures/oktaws");

    let toml_path = oktaws_dir.join("test.toml");
    assert!(toml_path.exists());

    Command::main_binary()?
        .env("OKTAWS_HOME", oktaws_dir)
        .arg("--profiles=test/*")
        .assert()
        .success();

    Ok(())
}

#[test]
fn calling_oktaws_against_invalid_oktaws_dir() -> Result<(), Error> {
    let temp_dir = tempdir()?;

    let oktaws_dir = temp_dir.path().join(".oktaws");

    assert!(!oktaws_dir.exists());

    Command::main_binary()?
        .env("OKTAWS_CONFIG_DIR", oktaws_dir)
        .assert()
        .failure()
        .stderr("Error: No organizations found\n");
    // TODO: Give better error message

    Ok(())
}

#[test]
fn calling_oktaws_against_invalid_organization() -> Result<(), Error> {
    let temp_dir = tempdir()?;

    let oktaws_dir = temp_dir.path();
    assert!(oktaws_dir.exists());

    let toml_path = oktaws_dir.join("test.toml");
    assert!(!toml_path.exists());

    Command::main_binary()?
        .env("OKTAWS_CONFIG_DIR", oktaws_dir)
        .arg("--profiles=test/*")
        .assert()
        .failure()
        .stderr("Error: No organizations found\n");

    Ok(())
}

#[test]
fn calling_oktaws_against_invalid_profile() -> Result<(), Error> {
    let oktaws_dir = PathBuf::from("tests/fixtures/oktaws");

    let toml_path = oktaws_dir.join("example.toml");
    assert!(toml_path.exists());

    Command::main_binary()?
        .env("OKTAWS_CONFIG_DIR", oktaws_dir)
        .arg("--profiles=example/no_profile")
        .assert()
        .success()
        .stderr(" WARN  oktaws > No profiles found matching example/no_profile in example\n WARN  oktaws > No profiles found matching example/no_profile in test\n");

    Ok(())
}
