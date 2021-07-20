use oktaws::aws::credentials::CredentialsStore;
use oktaws::config::organization::OrganizationConfig;
use oktaws::config::{oktaws_home, Config};
use oktaws::okta::client::Client as OktaClient;

use std::env;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use glob::Pattern;
use log::{debug, info};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Args {
    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", global = true, parse(from_occurrences))]
    pub verbosity: usize,

    #[structopt(subcommand)]
    cmd: Command,
}

#[derive(StructOpt, Debug)]
pub enum Command {
    Refresh(RefreshArgs),
    Init(InitArgs),
}

#[derive(StructOpt, Debug)]
pub struct RefreshArgs {
    /// Okta organization(s) to use
    #[structopt(
        short = "o",
        long = "organizations",
        default_value = "*",
        parse(try_from_str)
    )]
    pub organizations: Pattern,

    /// Profile(s) to update
    #[structopt(
        short = "p",
        long = "profiles",
        default_value = "*",
        parse(try_from_str)
    )]
    pub profiles: Pattern,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    #[cfg(not(target_os = "linux"))]
    pub force_new: bool,
}

#[derive(StructOpt, Debug)]
pub struct InitArgs {
    /// Okta organization to use
    pub organization: String,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    #[cfg(not(target_os = "linux"))]
    pub force_new: bool,
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> Result<()> {
    debug!("Args: {:?}", args);

    // Set Log Level
    let log_level = match args.verbosity {
        0 => "info",
        1 => "debug",
        _ => "trace",
    };
    env::set_var("RUST_LOG", format!("{}={}", module_path!(), log_level));
    pretty_env_logger::init();

    match args.cmd {
        Command::Refresh(args) => refresh(args).await,
        Command::Init(args) => init(args).await,
    }
}

async fn refresh(args: RefreshArgs) -> Result<()> {
    // Fetch config from files
    let config = Config::new()?;
    debug!("Config: {:?}", config);

    // Set up a store for AWS credentials
    let credentials_store = Arc::new(Mutex::new(CredentialsStore::new()?));

    let mut organizations = config
        .into_organizations(args.organizations.clone())
        .peekable();

    if organizations.peek().is_none() {
        return Err(anyhow!(
            "No organizations found called {}",
            args.organizations
        ));
    }

    for organization in organizations {
        info!("Evaluating profiles in {}", organization.name);

        let okta_client = OktaClient::new(
            organization.name.clone(),
            organization.username.clone(),
            #[cfg(not(target_os = "linux"))]
            args.force_new,
        )
        .await?;

        let credentials_map = organization
            .into_credentials(&okta_client, args.profiles.clone())
            .await;

        for (name, creds) in credentials_map {
            credentials_store
                .lock()
                .unwrap()
                .profiles
                .set_sts_credentials(name.clone(), creds.into())?;
        }
    }

    let mut store = credentials_store.lock().unwrap();
    store.save()
}

async fn init(args: InitArgs) -> Result<()> {
    let username: String = dialoguer::Input::new()
        .with_prompt(format!("Username for {}", &args.organization))
        .interact()?;

    let okta_client = OktaClient::new(
        args.organization.clone(),
        username.clone(),
        #[cfg(not(target_os = "linux"))]
        args.force_new,
    )
    .await?;

    let organization_config = OrganizationConfig::from_organization(&okta_client, username).await?;

    let org_toml = toml::to_string_pretty(&organization_config)?;

    println!("{}", &org_toml);

    let oktaws_home = oktaws_home()?;
    let oktaws_config_path = oktaws_home.join(format!("{}.toml", args.organization));

    let write_to_file = dialoguer::Confirm::new()
        .with_prompt(format!("Write config to {:?}?", oktaws_config_path))
        .interact()?;

    if write_to_file {
        std::fs::create_dir_all(oktaws_home)?;
        std::fs::write(oktaws_config_path, org_toml)?;
    }

    Ok(())
}
