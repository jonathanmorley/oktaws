mod aws;
mod config;
mod okta;
mod profile;

use crate::aws::credentials::CredentialsFile;
use crate::aws::role::Role;
use crate::config::Config;
use crate::profile::Profile;
use clap_verbosity_flag::Verbosity;
use exitfailure::ExitFailure;
use failure::Error;
use failure::*;
use glob::Pattern;
use log::*;
use log_derive::{logfn, logfn_inputs};
use std::sync::{Arc, Mutex};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Args {
    /// Okta profiles to update
    #[structopt(short = "p", long = "profiles", default_value = "*/*")]
    profile_patterns: Vec<Pattern>,

    #[structopt(flatten)]
    verbosity: Verbosity,
}

fn main() -> Result<(), ExitFailure> {
    //human_panic::setup_panic!();

    let args = Args::from_args();

    stderrlog::new()
        .module(module_path!())
        .verbosity(log_level(&args.verbosity))
        .init()?;

    debug!("log level: {}", log::max_level());

    // Get all organizations

    let config = Config::new()?;

    let organizations = config
        .clone()
        .into_organizations()
        .map(|org| org.with_session());

    // Get all profiles

    let mut profiles = config
        .into_profiles()
        .filter(|profile| {
            args.profile_patterns
                .iter()
                .any(|profile_pattern| profile_pattern.matches(&profile.to_string()))
        })
        .peekable();

    for profile in profiles {
        info!("{:?}", profile);
    }

    unimplemented!()

    /*if profiles.peek().is_none() {
        let patterns = args
            .profile_patterns
            .iter()
            .map(Pattern::as_str)
            .collect::<Vec<_>>();
        return Err(format_err!("No profiles found matching {:?}", patterns).into());
    }

    let credentials_store = Arc::new(Mutex::new(CredentialsFile::new(None)?));

    for mut profile in profiles {
        let org = profile.clone().application.organization.with_session()?;

        let credentials = fetch_credentials(&mut profile)?;

        credentials_store
            .lock()
            .unwrap()
            .set_profile_sts(profile.to_string(), credentials)?;
    }

    Arc::try_unwrap(credentials_store)
        .map_err(|_| format_err!("Failed to un-reference-count the credentials store"))?
        .into_inner()
        .map_err(|_| format_err!("Failed to un-mutex the credentials store"))?
        .save()
        .map_err(Into::into)*/
}

#[logfn_inputs(Info, fmt = "requesting tokens for {}")]
#[logfn(Trace)]
fn fetch_credentials(profile: &mut Profile) -> Result<rusoto_sts::Credentials, Error> {
    let saml = profile.application.saml_response()?;
    let roles = saml.roles;

    let role: Role = roles
        .into_iter()
        .find(|r| {
            r.role_name()
                .map(|r| Some(r.to_owned()) == profile.role)
                .unwrap_or(false)
        })
        .ok_or_else(|| OktawsError::UnknownRole {
            role: profile.role.clone(),
            profile: profile.name.clone(),
        })?;

    trace!(
        "Found role: {} for profile {}",
        role.role_arn,
        &profile.name
    );

    let assumption_response = aws::role::assume_role(role, saml.raw)
        .map_err(|e| format_err!("Error assuming role for profile {} ({})", profile.name, e))?;

    let credentials = assumption_response
        .credentials
        .ok_or_else(|| format_err!("Error fetching credentials from assumed AWS role"))?;

    Ok(credentials)
}

/// Get the log level.
pub fn log_level(verbosity: &Verbosity) -> usize {
    match verbosity.log_level() {
        Level::Error => 1,
        Level::Warn => 2,
        Level::Info => 3,
        Level::Debug => 4,
        Level::Trace => 5,
    }
}

#[derive(Debug, Fail)]
enum OktawsError {
    #[fail(
        display = "no matching role ({:?}) found for profile {}",
        role, profile
    )]
    UnknownRole {
        role: Option<String>,
        profile: String,
    },
}
