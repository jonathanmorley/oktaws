use mockall_double::double;

#[double]
use crate::okta::client::Client as OktaClient;
use crate::{
    aws::sts_client,
    okta::applications::{AppLink, AppLinkAccountRoleMapping},
    select,
};

use aws_credential_types::Credentials;
use eyre::{Result, eyre};
use serde::{Deserialize, Serialize};
use tracing::{instrument, trace};

/// This is an intentionally 'loose' struct,
/// representing the potential various ways of providing a profile.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Config {
    Name(String),
    Detailed {
        application: String,
        account: Option<String>,
        role: Option<String>,
        duration_seconds: Option<i32>,
        #[serde(skip_serializing, skip_deserializing)]
        account_id: Option<String>,
    },
}

impl Config {
    /// # Errors
    ///
    /// Will return `Err` if no profiles are found for the application.
    /// Will return `Err` if the user fails to select a role.
    ///
    /// # Panics
    ///
    /// Panics if the `role_names` vector has exactly 1 element but `first()` returns `None`.
    #[instrument(skip(mapping, default_roles))]
    pub fn from_account_mapping(
        mapping: AppLinkAccountRoleMapping,
        default_roles: &[String],
    ) -> Result<(String, Self)> {
        let default_roles_available = mapping
            .role_names
            .clone()
            .into_iter()
            .filter(|name| default_roles.contains(name))
            .collect::<Vec<_>>();

        let role_name = match mapping.role_names.len() {
            0 => Err(eyre!(
                "No profiles found for application {}",
                mapping.account_name
            )),
            1 => Ok(mapping.role_names.first().unwrap().clone()),
            _ if default_roles_available.len() == 1 => {
                Ok(default_roles_available.first().unwrap().clone())
            }
            _ if default_roles_available.len() > 1 => Ok(select(
                default_roles_available.clone(),
                format!("Choose Role for {}", mapping.account_name),
                std::clone::Clone::clone,
            )?),
            _ => Ok(select(
                mapping.role_names.clone(),
                format!("Choose Role for {}", mapping.account_name),
                std::clone::Clone::clone,
            )?),
        }?;
        let profile_config = if default_roles_available.contains(&role_name)
            && default_roles_available.len() == 1
            && mapping.account_id.is_none()
        {
            // Federated profile with single default role - use simplified format
            Self::Name(mapping.application_name)
        } else if default_roles_available.contains(&role_name)
            && default_roles_available.len() == 1
            && mapping.account_id.is_some()
        {
            // Identity Center profile with single default role - use detailed format without explicit role
            Self::Detailed {
                application: mapping.application_name.clone(),
                account: Some(mapping.account_name.clone()),
                role: None,
                duration_seconds: None,
                account_id: mapping.account_id.clone(),
            }
        } else {
            // Multiple roles or no default role - use detailed format with explicit role
            Self::Detailed {
                application: mapping.application_name.clone(),
                account: Some(mapping.account_name.clone()),
                role: Some(role_name),
                duration_seconds: None,
                account_id: mapping.account_id.clone(),
            }
        };

        Ok((mapping.account_name, profile_config))
    }
}

/// This is a canonical representation of the Profile,
/// with required values resolved and defaults propagated.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub account: Option<String>,
    pub roles: Vec<String>,
    pub duration_seconds: Option<i32>,
}

impl Profile {
    /// Parse profiles from an organization config section
    ///
    /// # Errors
    ///
    /// Will return `Err` if a role for the profile cannot be found
    pub fn try_from_spec(
        profile_config: &Config,
        name: String,
        default_roles: Option<Vec<String>>,
        default_duration_seconds: Option<i32>,
    ) -> Result<Self> {
        Ok(Self {
            name,
            application_name: match profile_config {
                Config::Name(name) => name,
                Config::Detailed { application, .. } => application,
            }
            .clone(),
            account: match profile_config {
                Config::Name(_) => None,
                Config::Detailed { account, .. } => account.clone(),
            },
            roles: match profile_config {
                Config::Name(_) => None,
                Config::Detailed { role, .. } => role.clone().map(|r| vec![r]),
            }
            .or(default_roles)
            .ok_or_else(|| eyre!("No role found"))?,
            duration_seconds: match profile_config {
                Config::Name(_) => None,
                Config::Detailed {
                    duration_seconds, ..
                } => *duration_seconds,
            }
            .or(default_duration_seconds),
        })
    }

    /// # Errors
    ///
    /// Will return `Err` if the Okta application for the profile cannot be found.
    /// Will return `Err` if the SAML response or SSO credentials cannot be obtained.
    /// Will return `Err` if the role cannot be assumed.
    #[instrument(skip(self, client), fields(organization=%client.base_url(), profile=%self.name))]
    pub async fn into_credentials(
        self,
        client: &OktaClient,
        role_override: Option<&String>,
    ) -> Result<Credentials> {
        let saml_app_link = client.app_links(None).await?.into_iter().find(|app_link| {
            app_link.app_name == "amazon_aws" && app_link.label == self.application_name
        });

        if let Some(app_link) = saml_app_link {
            return self
                .into_saml_credentials(client, app_link, role_override)
                .await;
        }

        Err(eyre!(
            "Could not find Okta application for profile {}",
            self.name
        ))
    }

    async fn into_saml_credentials(
        self,
        client: &OktaClient,
        app_link: AppLink,
        role_override: Option<&String>,
    ) -> Result<Credentials> {
        let response = client
            .get_saml_response(app_link.link_url)
            .await
            .map_err(|e| {
                eyre!(
                    "Error getting SAML response for profile {} ({})",
                    self.name,
                    e
                )
            })?;

        let saml_roles = response.roles()?;

        let saml_roles_available = if let Some(role_override) = role_override {
            saml_roles
                .into_iter()
                .filter(|r| r.role_name().unwrap() == *role_override)
                .collect::<Vec<_>>()
        } else {
            saml_roles
                .into_iter()
                .filter(|r| self.roles.contains(&r.role_name().unwrap()))
                .collect::<Vec<_>>()
        };

        let saml_role = match saml_roles_available.len() {
            0 => {
                if let Some(role_override) = role_override {
                    Err(eyre!(
                        "Role override, {}, does not exist for profile {}",
                        role_override,
                        self.name
                    ))
                } else {
                    Err(eyre!(
                        "No roles found for profile {} in SAML response",
                        self.name
                    ))
                }
            }
            1 => Ok(saml_roles_available[0].clone()),
            _ => {
                let selected = select(
                    saml_roles_available,
                    format!("Choose Role for profile {}", self.name),
                    |role| role.role_name().unwrap(),
                )?;
                Ok(selected)
            }
        }?;

        trace!("Found role: {} for profile {}", saml_role.role, &self.name);

        let credentials = saml_role
            .assume(sts_client(), response.saml, self.duration_seconds)
            .await
            .map_err(|e| eyre!("Error assuming role for profile {} ({})", self.name, e))?;

        trace!("Credentials: {:?}", credentials);

        Ok(credentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to create test mapping
    fn create_test_mapping(
        account_name: &str,
        application_name: &str,
        role_names: Vec<String>,
        account_id: Option<String>,
    ) -> AppLinkAccountRoleMapping {
        AppLinkAccountRoleMapping {
            account_name: account_name.to_string(),
            role_names,
            application_name: application_name.to_string(),
            account_id,
        }
    }

    // Tests for Config::from_account_mapping()
    #[test]
    fn test_single_role_federated() -> Result<()> {
        let mapping = create_test_mapping(
            "prod-account",
            "Production",
            vec!["AdminRole".to_string()],
            None,
        );
        let (account, config) = Config::from_account_mapping(mapping, &[])?;

        assert_eq!(account, "prod-account");
        match config {
            Config::Detailed {
                application,
                account: acc,
                role,
                ..
            } => {
                assert_eq!(application, "Production");
                assert_eq!(acc, Some("prod-account".to_string()));
                assert_eq!(role, Some("AdminRole".to_string()));
            }
            _ => panic!("Expected Detailed variant"),
        }
        Ok(())
    }

    #[test]
    fn test_single_role_with_default_federated() -> Result<()> {
        let mapping = create_test_mapping(
            "prod-account",
            "Production",
            vec!["AdminRole".to_string()],
            None,
        );
        let (account, config) = Config::from_account_mapping(mapping, &["AdminRole".to_string()])?;

        assert_eq!(account, "prod-account");
        match config {
            Config::Name(name) => {
                assert_eq!(name, "Production");
            }
            _ => panic!("Expected Name variant for single default role"),
        }
        Ok(())
    }

    #[test]
    fn test_single_role_with_default_identity_center() -> Result<()> {
        let mapping = create_test_mapping(
            "prod-account",
            "Production",
            vec!["AdminRole".to_string()],
            Some("123456789012".to_string()),
        );
        let (account, config) = Config::from_account_mapping(mapping, &["AdminRole".to_string()])?;

        assert_eq!(account, "prod-account");
        match config {
            Config::Detailed {
                application,
                account: acc,
                role,
                account_id,
                ..
            } => {
                assert_eq!(application, "Production");
                assert_eq!(acc, Some("prod-account".to_string()));
                assert_eq!(role, None);
                assert_eq!(account_id, Some("123456789012".to_string()));
            }
            _ => panic!("Expected Detailed variant without explicit role"),
        }
        Ok(())
    }

    #[test]
    fn test_no_roles_returns_error() {
        let mapping = create_test_mapping("prod-account", "Production", vec![], None);
        let result = Config::from_account_mapping(mapping, &[]);

        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("No profiles found")
        );
    }

    #[test]
    fn test_account_id_field_preserved() -> Result<()> {
        let mapping = create_test_mapping(
            "prod-account",
            "Production",
            vec!["Role1".to_string(), "Role2".to_string()],
            Some("999888777666".to_string()),
        );
        let (_account, config) = Config::from_account_mapping(mapping, &["Role1".to_string()])?;

        match config {
            Config::Detailed { account_id, .. } => {
                assert_eq!(account_id, Some("999888777666".to_string()));
            }
            _ => panic!("Expected Detailed variant"),
        }
        Ok(())
    }

    #[test]
    fn test_account_id_none_for_federated() -> Result<()> {
        let mapping = create_test_mapping(
            "prod-account",
            "Production",
            vec!["Role1".to_string()],
            None,
        );
        let (_account, config) = Config::from_account_mapping(mapping, &[])?;

        match config {
            Config::Detailed { account_id, .. } => {
                assert_eq!(account_id, None);
            }
            _ => panic!("Expected Detailed variant"),
        }
        Ok(())
    }

    // Tests for Profile::try_from_spec()
    #[test]
    fn test_try_from_spec_name_variant() -> Result<()> {
        let config = Config::Name("Production".to_string());
        let profile = Profile::try_from_spec(
            &config,
            "my-profile".to_string(),
            Some(vec!["AdminRole".to_string()]),
            None,
        )?;

        assert_eq!(profile.name, "my-profile");
        assert_eq!(profile.application_name, "Production");
        assert_eq!(profile.account, None);
        assert_eq!(profile.roles, vec!["AdminRole".to_string()]);
        assert_eq!(profile.duration_seconds, None);
        Ok(())
    }

    #[test]
    fn test_try_from_spec_detailed_variant() -> Result<()> {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: Some("AdminRole".to_string()),
            duration_seconds: Some(3600),
            account_id: None,
        };
        let profile = Profile::try_from_spec(&config, "my-profile".to_string(), None, None)?;

        assert_eq!(profile.name, "my-profile");
        assert_eq!(profile.application_name, "Production");
        assert_eq!(profile.account, Some("prod-account".to_string()));
        assert_eq!(profile.roles, vec!["AdminRole".to_string()]);
        assert_eq!(profile.duration_seconds, Some(3600));
        Ok(())
    }

    #[test]
    fn test_try_from_spec_uses_default_role() -> Result<()> {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: None,
            duration_seconds: None,
            account_id: None,
        };
        let profile = Profile::try_from_spec(
            &config,
            "my-profile".to_string(),
            Some(vec!["DefaultRole".to_string()]),
            None,
        )?;

        assert_eq!(profile.roles, vec!["DefaultRole".to_string()]);
        Ok(())
    }

    #[test]
    fn test_try_from_spec_uses_default_duration() -> Result<()> {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: Some("AdminRole".to_string()),
            duration_seconds: None,
            account_id: None,
        };
        let profile = Profile::try_from_spec(&config, "my-profile".to_string(), None, Some(7200))?;

        assert_eq!(profile.duration_seconds, Some(7200));
        Ok(())
    }

    #[test]
    fn test_try_from_spec_no_role_returns_error() {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: None,
            duration_seconds: None,
            account_id: None,
        };
        let result = Profile::try_from_spec(&config, "my-profile".to_string(), None, None);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No role found"));
    }

    #[test]
    fn test_try_from_spec_explicit_role_overrides_default() -> Result<()> {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: Some("ExplicitRole".to_string()),
            duration_seconds: None,
            account_id: None,
        };
        let profile = Profile::try_from_spec(
            &config,
            "my-profile".to_string(),
            Some(vec!["DefaultRole".to_string()]),
            None,
        )?;

        assert_eq!(profile.roles, vec!["ExplicitRole".to_string()]);
        Ok(())
    }

    #[test]
    fn test_try_from_spec_explicit_duration_overrides_default() -> Result<()> {
        let config = Config::Detailed {
            application: "Production".to_string(),
            account: Some("prod-account".to_string()),
            role: Some("AdminRole".to_string()),
            duration_seconds: Some(1800),
            account_id: None,
        };
        let profile = Profile::try_from_spec(&config, "my-profile".to_string(), None, Some(7200))?;

        assert_eq!(profile.duration_seconds, Some(1800));
        Ok(())
    }

    #[test]
    fn test_profile_equality() {
        let profile1 = Profile {
            name: "test".to_string(),
            application_name: "App".to_string(),
            account: Some("account".to_string()),
            roles: vec!["Role1".to_string()],
            duration_seconds: Some(3600),
        };
        let profile2 = Profile {
            name: "test".to_string(),
            application_name: "App".to_string(),
            account: Some("account".to_string()),
            roles: vec!["Role1".to_string()],
            duration_seconds: Some(3600),
        };
        let profile3 = Profile {
            name: "different".to_string(),
            application_name: "App".to_string(),
            account: Some("account".to_string()),
            roles: vec!["Role1".to_string()],
            duration_seconds: Some(3600),
        };

        assert_eq!(profile1, profile2);
        assert_ne!(profile1, profile3);
    }
}
