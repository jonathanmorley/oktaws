//! The Credentials Provider for Credentials stored in a profile inside of a Credentials file.
//! Adapted from https://raw.githubusercontent.com/rusoto/rusoto/master/rusoto/credential/src/profile.rs

use std::collections::HashMap;
use std::env::var as env_var;
use std::fs;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use dirs::home_dir;
use regex::Regex;

use rusoto_credential::CredentialsError;

const AWS_CONFIG_FILE: &str = "AWS_CONFIG_FILE";
const AWS_PROFILE: &str = "AWS_PROFILE";
const AWS_SHARED_CREDENTIALS_FILE: &str = "AWS_SHARED_CREDENTIALS_FILE";
const DEFAULT: &str = "default";
const REGION: &str = "region";

/// Default config file location:
/// 1: if set and not empty, use the value from environment variable ```AWS_CONFIG_FILE```
/// 2. otherwise return `~/.aws/config` (Linux/Mac) resp. `%USERPROFILE%\.aws\config` (Windows)
pub fn default_location() -> Result<PathBuf, CredentialsError> {
    let env = env_var(AWS_CONFIG_FILE).ok().filter(|e| !e.is_empty());
    match env {
        Some(path) => Ok(PathBuf::from(path)),
        None => hardcoded_location(),
    }
}

fn hardcoded_location() -> Result<PathBuf, CredentialsError> {
    match home_dir() {
        Some(mut home_path) => {
            home_path.push(".aws");
            home_path.push("config");
            Ok(home_path)
        }
        None => Err(CredentialsError::new("Failed to determine home directory.")),
    }
}

// should probably constantize with lazy_static!
fn new_profile_regex() -> Regex {
    Regex::new(r"^\[profile ([^\]]+)\]$").expect("Failed to compile regex")
}

fn parse_config_file(file_path: &Path) -> Option<HashMap<String, HashMap<String, String>>> {
    match fs::metadata(file_path) {
        Err(_) => return None,
        Ok(metadata) => {
            if !metadata.is_file() {
                return None;
            }
        }
    };
    let profile_regex = new_profile_regex();
    let file = File::open(file_path).expect("expected file");
    let file_lines = BufReader::new(&file);
    let result: (HashMap<String, HashMap<String, String>>, Option<String>) = file_lines
        .lines()
        .filter_map(|line| {
            line.ok()
                .map(|l| l.trim_matches(' ').to_owned())
                .into_iter()
                .find(|l| !l.starts_with('#') || !l.is_empty())
        })
        .fold(Default::default(), |(mut result, profile), line| {
            if profile_regex.is_match(&line) {
                let caps = profile_regex.captures(&line).unwrap();
                let next_profile = caps.get(2).map(|value| value.as_str().to_string());
                (result, next_profile)
            } else {
                match &line
                    .splitn(2, '=')
                    .map(|value| value.trim_matches(' '))
                    .collect::<Vec<&str>>()[..]
                {
                    [key, value] if !key.is_empty() && !value.is_empty() => {
                        if let Some(current) = profile.clone() {
                            let values = result.entry(current).or_insert_with(HashMap::new);
                            (*values).insert(key.to_string(), value.to_string());
                        }
                        (result, profile)
                    }
                    _ => (result, profile),
                }
            }
        });
    Some(result.0)
}
