mod aws;
mod config;
mod okta;
mod profile;

use crate::aws::credentials::CredentialsFile;
use crate::config::Config;
use clap_verbosity_flag::Verbosity;
use exitfailure::ExitFailure;
use failure::Error;
use failure::*;
use log::*;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Args {
    /// Okta profiles to update
    #[structopt(short = "p", long = "profiles", default_value = "")]
    profile_prefixes: Vec<String>,

    #[structopt(flatten)]
    verbosity: Verbosity,
}

impl Args {
    /// Get the log level.
    fn log_level(&self) -> usize {
        match self.verbosity.log_level() {
            Level::Error => 1,
            Level::Warn => 2,
            Level::Info => 3,
            Level::Debug => 4,
            Level::Trace => 5,
        }
    }

    /// Check if a given ID matches with any of the profile_prefixes
    fn profile_match<T: fmt::Display>(&self, profile_id: &T) -> bool {
        self.profile_prefixes
            .iter()
            .any(|prefix| profile_id.to_string().starts_with(prefix))
    }
}

fn main() -> Result<(), ExitFailure> {
    //human_panic::setup_panic!();

    let args = Args::from_args();

    stderrlog::new()
        .module(module_path!())
        .verbosity(args.log_level())
        .init()?;

    debug!("log level: {}", log::max_level());

    let config = Config::new()?;

    // No need to fetch profiles from organizations that would be filtered out.

    // All profiles
    let profiles = config.into_profiles();

    // Selected profiles
    let profiles: HashMap<_, _> = profiles.filter(|(id, _)| args.profile_match(id)).collect();

    // Break early if there are no profiles to do anything with
    if profiles.is_empty() {
        return Err(format_err!("No profiles found matching {:?}", args.profile_prefixes).into());
    }

    // List out profiles
    for profile in &profiles {
        info!("Profile {} -> {}", profile.0, profile.1);
    }

    let credentials_store = Arc::new(Mutex::new(CredentialsFile::new(None)?));

    for (profile_id, profile) in profiles {
        let credentials = profile
            .assume_role()?
            .credentials
            .ok_or_else(|| format_err!("Error fetching credentials from assumed AWS role"))?;

        credentials_store
            .lock()
            .unwrap()
            .set_profile(profile_id.to_string(), credentials)?;
    }

    Arc::try_unwrap(credentials_store)
        .map_err(|_| format_err!("Failed to un-reference-count the credentials store"))?
        .into_inner()
        .map_err(|_| format_err!("Failed to un-mutex the credentials store"))?
        .save()
        .map_err(Error::from)?;

    Ok(())
}
