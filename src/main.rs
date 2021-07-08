#[macro_use]
extern crate failure;
#[macro_use]
extern crate log;

mod aws;
mod config;
mod okta;
mod saml;

use crate::aws::credentials::CredentialsStore;
use crate::aws::role::assume_role;
use crate::config::Config;
use crate::config::organization::OrganizationConfig;
use crate::config::profile::{FullProfileConfig, ProfileConfig};
use crate::okta::client::Client as OktaClient;

use std::collections::HashMap;
use std::env;
use std::sync::{Arc, Mutex};

use failure::Error;
use glob::Pattern;
use indexmap::IndexMap;
use rusoto_core::{HttpClient, Region};
use rusoto_credential::{ProvideAwsCredentials, StaticProvider};
use rusoto_iam::{Iam, IamClient, ListAccountAliasesRequest};
use rusoto_sts::{GetCallerIdentityRequest, Sts, StsClient};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
pub struct Args {
    /// Sets the level of verbosity
    #[structopt(short = "v", long = "verbose", global = true, parse(from_occurrences))]
    pub verbosity: usize,

    #[structopt(subcommand)]
    cmd: Command
}

#[derive(StructOpt, Debug)]
pub enum Command {
    #[structopt(flatten)]
    Refresh(RefreshArgs),
    Init(InitArgs)
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

    /// Fetch profiles asynchronously
    #[structopt(short = "a", long = "async")]
    pub asynchronous: bool,
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
async fn main(args: Args) -> Result<(), Error> {
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
        Command::Init(args) => init(args).await
    }
}

async fn refresh(args: RefreshArgs) -> Result<(), Error> {
    // Fetch config from files
    let config = Config::new()?;
    debug!("Config: {:?}", config);

    // Set up a store for AWS credentials
    let credentials_store = Arc::new(Mutex::new(CredentialsStore::new()?));

    let mut organizations = config
        .into_organizations(args.organizations.clone())
        .peekable();

    if organizations.peek().is_none() {
        bail!("No organizations found called {}", args.organizations);
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

        let credentials_map = if args.asynchronous {
            organization
                .into_credentials(&okta_client, args.profiles.clone())
                .await
                .collect()
        } else {
            let profiles = organization.into_profiles(args.profiles.clone());

            let mut credentials_map = HashMap::new();
            for profile in profiles {
                let name = profile.name.clone();

                info!("Requesting tokens for {}", profile.name);

                let credentials = profile.into_credentials(&okta_client).await.unwrap();

                credentials_map.insert(name, credentials);
            }

            credentials_map
        };

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

async fn init(args: InitArgs) -> Result<(), Error> {
    let username: String = dialoguer::Input::new().with_prompt(format!("Username for {}", &args.organization)).interact()?;

    let okta_client = OktaClient::new(
        args.organization.clone(),
        username.clone(),
        #[cfg(not(target_os = "linux"))]
        args.force_new,
    )
    .await?;

    let app_links = okta_client.app_links(None).await?;
    let aws_links = app_links.into_iter().filter(|link| link.app_name == "amazon_aws");

    let mut organization_config = OrganizationConfig {
        username: Some(username),
        duration_seconds: None,
        role: None,
        profiles: IndexMap::new()
    };

    for link in aws_links {
        let mut response = okta_client.get_saml_response(link.link_url.clone()).await?;
        let role_arns = response.roles.iter().map(|role| role.role_arn.as_str()).collect::<Vec<_>>();

        let selection = dialoguer::Select::new()
            .with_prompt(format!("Choose Role for {}. Esc/q to skip this account", link.label))
            .items(&role_arns)
            .default(0)
            .interact_opt()?;

        let role = match selection {
            Some(index) => response.roles.remove(index),
            None => continue
        };

        let role_name = role.role_name()?.to_string();

        let assumption_response = assume_role(role, response.raw, None)
                .await
                .map_err(|e| format_err!("Error assuming role ({})", e))?;

        let credentials = assumption_response.credentials.ok_or_else(|| format_err!("No creds"))?;
        let provider = StaticProvider::new(credentials.access_key_id, credentials.secret_access_key, Some(credentials.session_token), None);
        let client = IamClient::new_with(HttpClient::new()?, provider, Region::default());

        let mut aliases = client.list_account_aliases(ListAccountAliasesRequest { marker: None, max_items: None }).await?;
        let alias = aliases.account_aliases.remove(0);

        organization_config.profiles.insert(alias, ProfileConfig::Detailed(FullProfileConfig {
            application: link.label,
            role: Some(role_name),
            duration_seconds: None
        }));
    }

    let org_toml = toml::to_string_pretty(&organization_config)?;

    println!("{}", &org_toml);

    let write_to_file = dialoguer::Confirm::new().with_prompt(format!("Write config to {}.toml ?", args.organization)).interact()?;

    if write_to_file {
        dbg!(org_toml);
    }

    Ok(())
}