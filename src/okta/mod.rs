pub mod applications;
pub mod auth;
pub mod client;
pub mod factors;
pub mod saml;
pub mod sessions;

use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum Links {
    Single(Link),
    Multi(Vec<Link>),
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Link {
    pub href: Url,
}
