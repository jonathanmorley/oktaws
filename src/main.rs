use oktaws::aws::credentials::CredentialsStore;
use oktaws::config::organization::OrganizationConfig;
use oktaws::config::{oktaws_home, Config};
use oktaws::okta::client::Client as OktaClient;

use std::convert::{TryFrom, TryInto};
use std::env;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Error, Result};
use glob::Pattern;
use log::{debug, info, trace};
use structopt::{paw, StructOpt};
use tracing_subscriber::fmt::Subscriber;

#[derive(StructOpt, Debug)]
struct Args {
    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", global = true, parse(from_occurrences))]
    verbosity: usize,

    #[structopt(subcommand)]
    cmd: Option<Command>,

    #[structopt(flatten)]
    default: RefreshArgs,
}

#[derive(StructOpt, Debug)]
enum Command {
    /// Refresh credentials from okta
    Refresh(RefreshArgs),

    /// Generate an organization.toml configuration
    Init(InitArgs),
}

#[paw::main]
#[tokio::main]
async fn main(args: Args) -> Result<()> {
    trace!("Args: {:?}", args);

    // Set Log Level
    let log_env_var = env::var("RUST_LOG");

    let log_filter = log_env_var
        .clone()
        .unwrap_or_else(|_| match args.verbosity {
            0 => format!("{}=warn", module_path!()),
            1 => format!("{}=info", module_path!()),
            2 => format!("{}=debug", module_path!()),
            _ => format!("{}=trace", module_path!()),
        });

    Subscriber::builder()
        .with_env_filter(log_filter)
        .without_time()
        .with_target(log_env_var.is_ok())
        .init();

    match args.cmd {
        Some(Command::Refresh(args)) => refresh(args).await,
        Some(Command::Init(args)) => init(args.try_into()?).await,
        None => refresh(args.default).await,
    }
}

#[derive(StructOpt, Debug)]
struct RefreshArgs {
    /// Okta organization(s) to use
    #[structopt(
        short = "o",
        long = "organization",
        default_value = "*",
        parse(try_from_str)
    )]
    pub organizations: Pattern,

    /// Profile(s) to update
    #[structopt(default_value = "*", parse(try_from_str))]
    pub profiles: Pattern,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
    pub force_new: bool,
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
                .set_sts_credentials(name.clone(), creds?.into())?;
        }
    }

    let mut store = credentials_store.lock().unwrap();
    store.save()
}

#[derive(StructOpt, Debug)]
struct InitArgs {
    /// Okta organization to use
    organization: Option<String>,

    /// Okta username
    #[structopt(short = "u")]
    username: Option<String>,

    /// Forces new credentials
    #[structopt(short = "f", long = "force-new")]
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
