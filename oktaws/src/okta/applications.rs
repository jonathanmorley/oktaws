use crate::{aws::role::SamlRole, okta::client::Client};

use eyre::Result;
use futures::future::join_all;
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AppLink {
    pub label: String,
    pub link_url: Url,
    pub app_name: String,
}

impl Client {
    /// Return all the `AppLink`s for a given user.
    /// If `user_id` is None, assume the current user.
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any network errors encountered
    pub async fn app_links(&self, user_id: Option<&str>) -> Result<Vec<AppLink>> {
        self.get(&format!(
            "api/v1/users/{}/appLinks",
            user_id.unwrap_or("me")
        ))
        .await
    }

    /// Given an `AppLink`, visit it to get the AWS roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn roles(&self, link: AppLink) -> Result<Vec<SamlRole>> {
        self.get_saml_response(link.link_url).await?.roles()
    }

    /// Given a list of `AppLink`s, visit each of them to get the AWS roles that can be assumed
    ///
    /// # Errors
    ///
    /// Will return `Err` if there are any errors while fetching the roles.
    pub async fn all_roles(&self, links: Vec<AppLink>) -> Result<Vec<SamlRole>> {
        let role_futures = links.into_iter().map(|link| self.roles(link));
        let roles = join_all(role_futures)
            .await
            .into_iter()
            .collect::<Result<Vec<Vec<SamlRole>>, _>>()?;

        Ok(roles.into_iter().flatten().collect())
    }
}
