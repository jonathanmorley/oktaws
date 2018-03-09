extern crate base64;
extern crate failure;
extern crate ini;
extern crate keyring;
#[macro_use]
extern crate log;
extern crate loggerv;
extern crate quick_xml;
extern crate reqwest;
extern crate rpassword;
extern crate rusoto_core;
extern crate rusoto_credential;
extern crate rusoto_sts;
extern crate scraper;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_ini;
extern crate serde_json;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;
#[macro_use]
extern crate text_io;
extern crate toml;
extern crate username;

mod okta;
mod aws;
mod config;
mod credentials;

use config::Profile;

use structopt::StructOpt;
use failure::Error;

use std::env;
use std::process;

fn main() {
    fn run() -> Result<(), Error> {
        let args_opts = config::Config::from_args();

        loggerv::Logger::new()
            .verbosity(args_opts.verbosity)
            .level(true)
            .module_path(false)
            .init()?;

        let config_file_path = env::home_dir().unwrap().join(".oktaws/config.toml");
        let config_opts = config::Config::from_file(&config_file_path)?;

        let opts = args_opts.merge(config_opts);
        debug!("Options: {:?}", opts);

        let username = opts.username
            .clone()
            .unwrap_or_else(|| credentials::get_username());
        let password = credentials::get_password(&username, opts.force_new);

        let profiles = opts.into_profiles();

        for (
            name,
            Profile {
                organization,
                app_id,
                role,
            },
        ) in profiles
        {
            info!("Generating tokens for {}", name);

            let session_token = okta::login(&organization, &username, &password)?.session_token;
            debug!("Session Token: {}", session_token);

            let saml_assertion = okta::fetch_saml(&organization, &app_id, &session_token)?;
            debug!("SAML assertion: {}", saml_assertion);

            let saml_attributes = aws::find_saml_attributes(&saml_assertion)?;
            debug!("SAML attributes: {:?}", saml_attributes);

            let principal_arn = saml_attributes
                .get(&role)
                .expect("Error getting the principal ARN from SAML attributes");
            debug!("Principal ARN: {}", principal_arn);

            let credentials = aws::assume_role(principal_arn, &role, &saml_assertion)?
                .credentials
                .expect("Error fetching credentials from assumed AWS role");
            debug!("Credentials: {:?}", credentials);

            aws::set_credentials(&name, &credentials)?;
        }

        credentials::set_credentials(&username, &password);

        Ok(())
    }

    if let Err(e) = run() {
        error!("{:?}", e);
        process::exit(1);
    }
}
