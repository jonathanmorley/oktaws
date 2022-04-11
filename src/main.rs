use clap_verbosity_flag::Verbosity;
use oktaws::aws::credentials::CredentialsStore;
use oktaws::config::oktaws_home;
use oktaws::config::organization::{OrganizationConfig, OrganizationPattern};
use oktaws::okta::client::Client as OktaClient;
use tracing::instrument;
use tracing_log::AsTrace;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{prelude::*, Registry};
use tracing_tree::HierarchicalLayer;

use std::convert::{TryFrom, TryInto};
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Error, Result};
use clap::Parser;
use glob::Pattern;

#[derive(Parser, Debug)]
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
    let args = Args::parse();

    let filter = Targets::new()
        .with_target(module_path!(), args.verbosity.log_level_filter().as_trace());

    // Tree formatter
    let formatter = HierarchicalLayer::new(2).with_targets(true);

    // Custom Tree formatter
    // let formatter = tracing::HierarchicalLayer::new(2)
    //     .with_targets(true)
    //     .with_verbose_exit(false)
    //     .with_verbose_entry(false);

    // Default formatter
    // let formatter = tracing_subscriber::fmt::Layer::default()
    //     .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
    //     .without_time();

    let subscriber = Registry::default()
        .with(filter)
        .with(formatter);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    match args.cmd {
        Some(Command::Refresh(args)) => refresh(args).await,
        Some(Command::Init(args)) => init(args.try_into()?).await,
        None => refresh(args.default).await,
    }
}

#[derive(Parser, Debug)]
struct RefreshArgs {
    /// Okta organizations to use
    #[clap(
        short,
        long,
        default_value = "*",
        parse(try_from_str)
    )]
    pub organizations: OrganizationPattern,

    /// Profiles to update
    #[clap(default_value = "*", parse(try_from_str))]
    pub profiles: Pattern,

    /// Forces new credentials
    #[clap(short, long = "force-new")]
    pub force_new: bool,
}

#[instrument(skip_all, fields(organizations=%args.organizations,profiles=%args.profiles))]
async fn refresh(args: RefreshArgs) -> Result<()> {
    // Set up a store for AWS credentials
    let aws_credentials = Arc::new(Mutex::new(CredentialsStore::new()?));

    let organizations = args.organizations.organizations()?;

    if organizations.is_empty() {
        return Err(anyhow!(
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
            .into_credentials(&okta_client, args.profiles.clone())
            .await;

        for (name, creds) in credentials_map {
            aws_credentials
                .lock()
                .unwrap()
                .profiles
                .set_sts_credentials(name.clone(), creds?.into())?;
        }
    }

    let mut store = aws_credentials.lock().unwrap();
    store.save()
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
    type Error = Error;

    fn try_from(args: InitArgs) -> Result<Self, Self::Error> {
        let organization = match args.organization {
            Some(organization) => Ok(organization),
            None => dialoguer::Input::new()
                .with_prompt("Okta Organization Name")
                .interact_text(),
        }?;

        let username = match args.username {
            Some(username) => Ok(username),
            None => {
                let mut input = dialoguer::Input::new();
                input.with_prompt(format!("Username for {}", &organization));

                if let Ok(system_user) = username::get_user_name() {
                    input.default(system_user);
                }

                input.interact_text()
            }
        }?;

        Ok(Init {
            organization,
            username,
            force_new: args.force_new,
        })
    }
}

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
        .with_prompt(format!("Write config to {:?}?", oktaws_config_path))
        .interact()?;

    if write_to_file {
        std::fs::create_dir_all(oktaws_home)?;
        std::fs::write(oktaws_config_path, org_toml)?;
    }

    Ok(())
}
