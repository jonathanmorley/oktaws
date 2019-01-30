#[macro_use]
extern crate failure;

mod aws;
mod okta;

use crate::aws::credentials::CredentialsFile;
use crate::aws::role::Role;
use crate::okta::organization::Organization;
use crate::okta::organization::Profile;
use exitfailure::ExitFailure;
use failure::Error;
use futures::future::Future;
use log::{info, trace, warn};
use std::env;
use std::ffi::OsStr;
use std::sync::{Arc, Mutex};
use structopt::StructOpt;
use walkdir::WalkDir;

#[derive(Clone, StructOpt, Debug)]
pub struct Args {
    /// Okta organizations to update
    #[structopt(short = "o", long = "organizations")]
    pub organizations: Option<String>,

    /// Okta profiles to update
    #[structopt(short = "p", long = "profiles")]
    pub profiles: Option<String>,

    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: usize,
}

fn main() -> Result<(), ExitFailure> {
    human_panic::setup_panic!();

    let args = Args::from_args();

    let log_level = match args.verbosity {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    env::set_var("RUST_LOG", format!("{}={}", module_path!(), log_level));
    pretty_env_logger::init();

    let credentials_store = Arc::new(Mutex::new(CredentialsFile::new(None)?));

    let oktaws_dir = oktaws::default_oktaws_location()?;
    let organizations = WalkDir::new(oktaws_dir)
        .follow_links(true)
        .into_iter()
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|f| f.path().extension() == Some(OsStr::new("toml")))
        .filter(|f| {
            if let Some(organizations) = args.organizations.as_ref() {
                f.path()
                    .file_stem()
                    .unwrap()
                    .to_string_lossy()
                    .contains(organizations)
            } else {
                true
            }
        })
        .map(|f| Organization::from_file_path(f.path()))
        .collect::<Result<Vec<_>, _>>()?;

    if organizations.is_empty() {
        return Err(format_err!(
            "No organizations found containing '{}'",
            args.organizations.unwrap_or_default()
        )
        .into());
    }

    for mut organization in organizations {
        let profiles = organization
            .profiles
            .clone()
            .into_iter()
            .filter(|p| {
                if let Some(profiles) = args.profiles.as_ref() {
                    p.name.contains(profiles)
                } else {
                    true
                }
            })
            .collect::<Vec<_>>();

        info!("Okta profiles: {:?}", profiles);

        if profiles.is_empty() {
            warn!(
                "No profiles found containing '{}'",
                args.profiles.clone().unwrap_or_default()
            );
            continue;
        }

        organization.store_dt_token()?;
        let auth_transaction = organization.auth_with_credentials()?;
        if let Some(session_token) = auth_transaction.session_token() {
            organization.create_session(session_token)?;
        }

        //let session_id = okta_client.new_session(session_token, &HashSet::new())?.id;
        //okta_client.set_session_id(session_id.clone());
        for profile in profiles {
            credentials_store.lock().unwrap().set_profile_sts(
                format!("{}/{}", organization.name, profile.name),
                fetch_credentials(&mut organization, &profile)?,
            )?;
        }
    }

    Arc::try_unwrap(credentials_store)
        .map_err(|_| format_err!("Failed to un-reference-count the credentials store"))?
        .into_inner()
        .map_err(|_| format_err!("Failed to un-mutex the credentials store"))?
        .save()
        .map_err(|e| e.into())
}

fn fetch_credentials(
    organization: &mut Organization,
    profile: &Profile,
) -> Result<rusoto_sts::Credentials, Error> {
    info!(
        "Requesting tokens for {}/{}",
        &organization.name, profile.name
    );

    let app_link = organization
        .client
        .user_api()
        .list_app_links("me", true)
        .wait()
        .map_err(|e| format_err!("{:?}", e))?
        .into_iter()
        .filter(|app_link| app_link.app_name() == Some(&String::from("amazon_aws")))
        .find(|app_link| app_link.label() == Some(&profile.application_name))
        .ok_or_else(|| {
            format_err!(
                "No profile '{}' in Okta organization '{}'",
                profile.name,
                organization.name,
            )
        })?;

    if let Some(app_url) = app_link.link_url() {
        let saml = organization.get_saml_response(app_url)?;

        let roles = saml.roles;

        let role: Role = roles
            .into_iter()
            .find(|r| r.role_name().map(|r| r == profile.role).unwrap_or(false))
            .ok_or_else(|| {
                format_err!(
                    "No matching role ({}) found for profile {}",
                    profile.role,
                    &profile.name
                )
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

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    } else {
        bail!("No App URL found")
    }
}
