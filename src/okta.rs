use failure::Error;
use reqwest;
use kuchiki;
use kuchiki::traits::TendrilSink;

use saml::Response as SamlResponse;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OktaLoginRequest {
    username: Option<String>,
    password: Option<String>,
    relay_state: Option<String>,
    options: Option<OktaOptions>,
    token: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OktaOptions {
    multi_optional_factor_enroll: bool,
    warn_before_password_expired: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct OktaLoginResponse {
    state_token: Option<String>,
    pub session_token: String,
    expires_at: String,
    status: String,
    relay_state: Option<String>,
}

pub fn login(org: &str, user: &str, password: &str) -> Result<OktaLoginResponse, Error> {
    let req = OktaLoginRequest {
        username: Some(String::from(user)),
        password: Some(String::from(password)),
        relay_state: None,
        options: None,
        token: None,
    };

    let resp: Result<OktaLoginResponse, Error> = reqwest::Client::new()
        .post(&format!("https://{}.okta.com/api/v1/authn", org))
        .json(&req)
        .send()?
        .error_for_status()?
        .json()
        .map_err(|e| e.into());

    println!("{:?}", resp);

    resp

    //bail!("Test");
}

impl SamlResponse {
    pub fn from_okta(org: &str, app_id: &str, session_token: &str) -> Result<Self, Error> {
        let url = format!(
            "https://{}.okta.com/app/{}/sso/saml?onetimetoken={}",
            org, app_id, session_token
        );

        let response = reqwest::Client::new()
            .get(&url)
            .send()?
            .error_for_status()?
            .text()?;

        warn!("Response: {}", response);

        let doc = kuchiki::parse_html().one(response);

        if let Some(input_node) = doc.select("input[name='SAMLResponse']").unwrap().next() {
            if let Some(saml) = input_node.attributes.borrow().get("value") {
                debug!("SAML: {}", saml);
                return Ok(saml.parse()?);
            }
        }

        bail!("No SAML block found")
    }
}
