use crate::config::credentials;
use crate::okta::Organization as OktaOrganization;

use std::{convert::TryFrom, fs::File};
use std::io::Read;
use std::path::Path;

use failure::Error;
use toml;

#[derive(Clone, Debug)]
pub struct Profile {
    pub name: String,
    pub application_name: String,
    pub role: String,
    pub duration_seconds: Option<i64>,
}

impl Profile {
    fn from_entry(
        entry: (String, &toml::value::Value),
        default_role: Option<String>,
    ) -> Result<Profile, Error> {
        let application_name = if entry.1.is_table() {
            entry.1.get("application")
        } else {
            Some(entry.1)
        }
        .and_then(|a| toml_to_string(a))
        .unwrap();

        let role = if entry.1.is_table() {
            entry.1.get("role").and_then(|r| toml_to_string(r))
        } else {
            default_role
        }
        .ok_or_else(|| format_err!("No profile role or default role specified"))?;

        let duration_seconds = if entry.1.is_table() {
            entry.1.get("duration")
        } else {
            None
        }
        .and_then(|d| d.as_integer());

        Ok(Profile {
            name: entry.0,
            application_name,
            duration_seconds,
            role,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Organization {
    pub okta_organization: OktaOrganization,
    pub username: String,
    pub duration_seconds: Option<i64>,
    pub profiles: Vec<Profile>,
}

impl TryFrom<&Path> for Organization
{
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self, Self::Error> {
        let filename = path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .ok_or_else(|| {
                format_err!("Organization name not parseable from {:?}", path)
            })?;

        let file_contents = File::open(path)?
            .bytes()
            .map(|b| b.map_err(|e| e.into()))
            .collect::<Result<Vec<u8>, Error>>()?;

        let file_toml: toml::Value = toml::from_slice(&file_contents)?;

        let default_role: Option<String> = file_toml.get("role").and_then(|r| toml_to_string(r));

        let profiles = file_toml
            .get("profiles")
            .and_then(|p| p.as_table())
            .ok_or_else(|| format_err!("No profiles table found"))?
            .iter()
            .map(|(k, v)| Profile::from_entry((k.to_owned(), v), default_role.clone()))
            .collect::<Result<Vec<Profile>, Error>>()?;

        let okta_organization = filename.parse()?;

        let username = match file_toml.get("username").and_then(|u| toml_to_string(u)) {
            Some(username) => username,
            None => credentials::get_username(&okta_organization)?,
        };

        let duration_seconds = file_toml.get("duration_seconds").and_then(|u| u.as_integer());

        Ok(Organization {
            username,
            profiles,
            duration_seconds,
            okta_organization,
        })
    }
}

fn toml_to_string(value: &toml::value::Value) -> Option<String> {
    value.as_str().map(|r| r.to_owned())
}
