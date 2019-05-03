use failure::Fail;

#[derive(Debug, Fail)]
pub enum OktaError {
    #[fail(
        display = "no profile '{}' in Okta organization '{}'",
        profile, organization
    )]
    UnknownProfile {
        profile: String,
        organization: String,
    },
    #[fail(
        display = "no matching role ({:?}) found for profile {}",
        role, profile
    )]
    UnknownRole {
        role: Option<String>,
        profile: String,
    },
}
