use crate::aws::saml::SamlResponse;
use crate::aws::RoleProviderPair;
use crate::okta::application::Application;
use failure::{bail, format_err, Error};
use log_derive::logfn;
use rusoto_sts::AssumeRoleWithSAMLResponse;
use std::convert::From;
use std::fmt;

#[derive(Debug)]
pub struct Profile {
    pub role: Option<String>,
    pub application: Application,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} ({:?})", self.application, self.role)
    }
}

impl From<Application> for Profile {
    fn from(application: Application) -> Self {
        Profile {
            role: None,
            application,
        }
    }
}

impl Profile {
    fn saml(&self) -> Result<SamlResponse, Error> {
        self.application.saml_response()
    }

    #[logfn(Trace)]
    fn role_provider_pair(&self) -> Result<RoleProviderPair, Error> {
        let mut role_provider_pairs = self.saml()?.role_provider_pairs()?;

        match role_provider_pairs.len() {
            0 => bail!("No role/provider pairs for profile {}", self),
            1 => role_provider_pairs.pop().ok_or_else(|| {
                format_err!(
                    "role/provider pairs unexpectedly empty for profile {}",
                    self
                )
            }),
            _ => match &self.role {
                Some(role) => {
                    let err_msg = format_err!(
                        "Role {} not found for profile {}. Available roles: {:?}",
                        role,
                        self,
                        role_provider_pairs
                            .iter()
                            .map(|pair| pair.role_arn.to_owned())
                            .collect::<Vec<_>>()
                    );

                    role_provider_pairs
                        .into_iter()
                        .find(|r| r.role_name().map(|r| r == role).unwrap_or(false))
                        .ok_or_else(|| err_msg)
                }
                None => bail!(
                    "More than 1 role/provider pairs for profile {} and no role supplied",
                    self
                ),
            },
        }
    }

    pub fn assume_role(&self) -> Result<AssumeRoleWithSAMLResponse, Error> {
        self.role_provider_pair()?.assume_role(self.saml()?.raw)
    }
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct ProfileId {
    pub org_name: String,
    pub profile_name: String,
}

impl fmt::Display for ProfileId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.org_name, self.profile_name)
    }
}
