use oktaws::aws::credentials::credential_process::CredentialProcessCredentials;
use oktaws::aws::credentials::ini::CredentialsStore;
use oktaws::config::organization::OrganizationConfig;
use oktaws::config::{oktaws_home, Config};
use oktaws::okta::client::Client as OktaClient;

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use clap::{AppSettings, ArgEnum, Clap};
use glob::Pattern;
use rusoto_sts::Credentials;
use serde_json;
use tracing_subscriber::prelude::*;
use tracing::{debug, info, trace, Level};

#[derive(Clap, Debug)]
#[clap(
    version,
    global_setting = AppSettings::UnifiedHelpMessage
)]
struct Args {
    /// Sets the level of verbosity
    #[clap(short, long, global = true, parse(from_occurrences))]
    verbose: usize,

    #[clap(subcommand)]
    cmd: Option<Command>,

    #[clap(flatten)]
    default: RefreshArgs,
}

#[derive(Clap, Debug)]
enum Command {
    /// Fetch new credentials from Okta
    Refresh(RefreshArgs),

    /// Generate an organization.toml configuration
    Init(InitArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let filter_layer = tracing_subscriber::filter::Targets::new()
        .with_target(module_path!(), match args.verbose {
            0 => Level::WARN,
            1 => Level::INFO,
            2 => Level::DEBUG,
            _ => Level::TRACE
        });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .without_time();

    tracing_subscriber::registry()
        .with(filter_layer)
        .with(fmt_layer)
        .init();

    trace!("Args: {:?}", args);

    match args.cmd {
        Some(Command::Refresh(args)) => refresh(args).await,
        Some(Command::Init(args)) => init(args).await,
        None => refresh(args.default).await,
    }
}

#[derive(Clap, Debug)]
struct RefreshArgs {
    /// Okta organization(s) to use
    #[clap(long = "organization", default_value = "*", parse(try_from_str))]
    pub organizations: Pattern,

    /// Profile(s) to update
    #[clap(default_value = "*", parse(try_from_str))]
    pub profiles: Pattern,

    /// Forces new credentials
    #[clap(short, long = "force-new")]
    #[cfg(not(target_os = "linux"))]
    pub force_new: bool,

    /// Output format
    ///
    /// - `ini` will not output anything, but will store credentials in the AWS credentials file.
    /// - `credential_process` will output credentials that are compatible with `credential_process`.
    #[clap(long, arg_enum, default_value = "ini", long_about = "Output format

- `ini` will not output anything, but will store credentials in the AWS credentials file.
- `credential_process` will output credentials that are compatible with `credential_process`.
")]
    pub format: Format,
}

#[derive(ArgEnum, Debug)]
enum Format {
    Ini,
    CredentialProcess,
}

async fn refresh(args: RefreshArgs) -> Result<()> {
    // Fetch config from files
    let config = Config::new()?;
    debug!("Config: {:?}", config);

    let mut organizations = config
        .into_organizations(args.organizations.clone())
        .peekable();

    if organizations.peek().is_none() {
        return Err(anyhow!(
            "No organizations found called {}",
            args.organizations
        ));
    }

    let mut credentials: HashMap<String, Credentials> = HashMap::new();

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
            credentials.insert(name, creds?);
        }
    }

    match args.format {
        Format::Ini => {
            // Set up a store for AWS credentials
            let mut store = CredentialsStore::new()?;

            for (name, creds) in credentials {
                store.profiles.set_credentials(name, creds)?;
            }

            store.save()
        }
        Format::CredentialProcess => {
            if credentials.len() > 1 {
                return Err(anyhow!(
                    "Too many credentials found ({} > 1)",
                    credentials.len()
                ));
            }

            if let Some(credentials) = credentials.into_values().next() {
                let json_creds: CredentialProcessCredentials = credentials.into();
                println!("{}", serde_json::to_string_pretty(&json_creds)?);
                Ok(())
            } else {
                Err(anyhow!("No credentials found"))
            }
        }
    }
}

#[derive(Clap, Debug)]
struct InitArgs {
    /// Okta organization to use
    organization: Option<String>,

    /// Okta username
    #[clap(short)]
    username: Option<String>,

    /// Forces new credentials
    #[clap(short, long = "force-new")]
    #[cfg(not(target_os = "linux"))]
    force_new: bool,
}

async fn init(args: InitArgs) -> Result<()> {
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

    let oktaws_home = oktaws_home()?;
    let oktaws_config_path = oktaws_home.join(format!("{}.toml", organization));

    let okta_client = OktaClient::new(
        organization.clone(),
        username.clone(),
        #[cfg(not(target_os = "linux"))]
        args.force_new,
    )
    .await?;

    let organization_config = OrganizationConfig::from_organization(&okta_client, username).await?;

    let org_toml = toml::to_string_pretty(&organization_config)?;

    println!("{}", &org_toml);

    let write_to_file = dialoguer::Confirm::new()
        .with_prompt(format!("Write config to {:?}?", oktaws_config_path))
        .interact()?;

    if write_to_file {
        std::fs::create_dir_all(oktaws_home)?;
        std::fs::write(oktaws_config_path, org_toml)?;
    }

    Ok(())
}
