use crate::okta::client::Client;

use failure::Error;
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppLink {
    id: String,
    pub label: String,
    pub link_url: Url,
    pub app_name: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct User {
    id: String,
    profile: UserProfile,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct UserProfile {
    login: String,
    first_name: String,
    last_name: String,
    locale: String,
    time_zone: String,
}

impl Client {
    pub async fn app_links(&self, user_id: Option<&str>) -> Result<Vec<AppLink>, Error> {
        self.get(&format!(
            "api/v1/users/{}/appLinks",
            user_id.unwrap_or("me")
        ))
        .await
    }
}
