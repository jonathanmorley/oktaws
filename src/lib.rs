#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

pub mod aws;
pub mod config;
pub mod okta;
pub mod saml;

use anyhow::{anyhow, Result};

fn select<T, P, F, S>(mut items: Vec<T>, prompt: P, displayer: F) -> Result<T>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let index = match items.len() {
        0 => Err(anyhow!("No items found")),
        1 => Ok(0_usize),
        _ => dialoguer::Select::new()
            .with_prompt(prompt)
            .items(&items.iter().map(displayer).collect::<Vec<_>>())
            .default(0)
            .interact()
            .map_err(Into::into),
    }?;

    Ok(items.remove(index))
}

fn select_opt<T, P, F, S>(mut items: Vec<T>, prompt: P, displayer: F) -> Result<Option<T>>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let index = match items.len() {
        0 => Err(anyhow!("No items found")),
        _ => dialoguer::Select::new()
            .with_prompt(prompt)
            .items(&items.iter().map(displayer).collect::<Vec<_>>())
            .default(0)
            .interact_opt()
            .map_err(Into::into),
    }?;

    Ok(index.map(|index| items.remove(index)))
}
