use crate::okta::application::Application;
use failure;
use std::convert::TryFrom;
use std::fmt;

#[derive(Debug)]
pub struct Profile {
    pub name: String,
    pub role: Option<String>,
    pub application: Application,
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} -> {} ({:?})", self.name, self.application, self.role)
    }
}

impl TryFrom<Application> for Profile {
    type Error = failure::Error;

    fn try_from(application: Application) -> Result<Self, Self::Error> {
        Ok(Profile {
            name: application.to_string(),
            role: None,
            application,
        })
    }
}
