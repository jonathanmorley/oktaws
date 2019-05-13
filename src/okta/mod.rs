use kuchiki;
use kuchiki::traits::TendrilSink;
use lazy_static::lazy_static;
use log_derive::logfn;
use regex::Regex;
use std::str;

pub mod application;
pub mod organization;

pub use application::Application;
pub use organization::Organization;

#[logfn(Trace)]
fn extract_state_token(source: &str) -> Option<String> {
    lazy_static! {
        static ref RE: Regex = Regex::new(r#"var stateToken = '(.+)';"#).unwrap();
    }

    RE.captures(source).map(|cap| cap[1].replace("\\x2D", "-"))
}

#[logfn(Trace)]
pub fn extract_saml_response(source: &str) -> Option<String> {
    let input = kuchiki::parse_html()
        .one(source)
        .select_first("input[name='SAMLResponse']")
        .ok()?;

    let attributes = input.attributes.borrow();

    attributes.get("value").map(String::from)
}
