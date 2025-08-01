#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use oktaws::aws::profile::Store as ProfileStore;
use oktaws::config::oktaws_home;
use oktaws::config::organization::{Config as OrganizationConfig, Pattern as OrganizationPattern};
use oktaws::okta::client::Client as OktaClient;

use std::convert::{TryFrom, TryInto};

use clap::Parser;
use clap_verbosity_flag::Verbosity;
use color_eyre::eyre::{eyre, Result};
use glob::Pattern;
use tracing::instrument;
use tracing_log::AsTrace;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{prelude::*, Registry};
use tracing_tree::HierarchicalLayer;
use whoami::username;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(flatten)]
    verbosity: Verbosity,

    #[clap(subcommand)]
    cmd: Option<Command>,

    #[clap(flatten)]
    default: RefreshArgs,
}

#[derive(Parser, Debug)]
enum Command {
    /// Refresh credentials from okta
    Refresh(RefreshArgs),

    /// Generate an organization.toml configuration
    Init(InitArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    let filter =
        Targets::new().with_target(module_path!(), args.verbosity.log_level_filter().as_trace());

    let subscriber = Registry::default()
        .with(filter)
        .with(HierarchicalLayer::new(2).with_targets(true));
    tracing::subscriber::set_global_default(subscriber)?;

    match args.cmd {
        Some(Command::Refresh(args)) => refresh(args).await,
        Some(Command::Init(args)) => init(args.try_into()?).await,
        None => refresh(args.default).await,
    }
}

#[derive(Parser, Debug)]
struct RefreshArgs {
    /// Okta organizations to use
    #[clap(short, long, default_value = "*")]
    pub organizations: OrganizationPattern,

    /// Profiles to update
    #[clap(default_value = "*")]
    pub profiles: Pattern,

    /// Role to override toml file with
    #[clap(short, long = "role-override")]
    pub role_override: Option<String>,

    /// Forces new credentials
    #[clap(short, long = "force-new")]
    pub force_new: bool,
}

#[instrument(skip_all, fields(organizations=%args.organizations,profiles=%args.profiles))]
async fn refresh(args: RefreshArgs) -> Result<()> {
    // Set up a store for AWS profiles
    let mut aws_credentials = ProfileStore::load(None)?;

    let organizations = args.organizations.organizations()?;

    if organizations.is_empty() {
        return Err(eyre!(
            "No organizations found matching {}",
            args.organizations
        ));
    }

    for organization in organizations {
        let okta_client = OktaClient::new(
            organization.name.clone(),
            organization.username.clone(),
            args.force_new,
        )
        .await?;

        let credentials_map = organization
            .into_credentials(
                &okta_client,
                args.profiles.clone(),
                args.role_override.as_ref(),
            )
            .await;

        for (name, creds) in credentials_map {
            aws_credentials.upsert_credential(&name, &creds)?;
        }
    }

    aws_credentials.save()
}

#[derive(Parser, Debug)]
struct InitArgs {
    /// Okta organization to use
    organization: Option<String>,

    /// Okta username
    #[structopt(short)]
    username: Option<String>,

    /// Forces new credentials
    #[structopt(short, long = "force-new")]
    force_new: bool,
}

struct Init {
    organization: String,
    username: String,
    force_new: bool,
}

impl TryFrom<InitArgs> for Init {
    type Error = eyre::Error;

    fn try_from(args: InitArgs) -> Result<Self, Self::Error> {
        let organization = args.organization.map_or_else(
            || {
                dialoguer::Input::new()
                    .with_prompt("Okta Organization Name")
                    .interact_text()
            },
            Ok,
        )?;

        let username = args.username.map_or_else(
            || {
                dialoguer::Input::<String>::new()
                    .with_prompt(format!("Username for {organization}"))
                    .default(username())
                    .interact_text()
            },
            Ok,
        )?;

        Ok(Self {
            organization,
            username,
            force_new: args.force_new,
        })
    }
}

/// Output a config toml for a given organization
async fn init(options: Init) -> Result<()> {
    let okta_client = OktaClient::new(
        options.organization.clone(),
        options.username.clone(),
        options.force_new,
    )
    .await?;

    let organization_config =
        OrganizationConfig::from_organization(&okta_client, options.username).await?;

    let org_toml = toml::to_string_pretty(&organization_config)?;

    println!("{}", &org_toml);

    let oktaws_home = oktaws_home()?;
    let oktaws_config_path = oktaws_home.join(format!("{}.toml", options.organization));

    let write_to_file = dialoguer::Confirm::new()
        .with_prompt(format!("Write config to {}?", oktaws_config_path.display()))
        .interact()?;

    if write_to_file {
        std::fs::create_dir_all(oktaws_home)?;
        std::fs::write(oktaws_config_path, org_toml)?;
    }

    Ok(())
}
