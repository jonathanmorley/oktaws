#[macro_use]
extern crate log;

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
            .paged(true)
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
            .paged(true)
            .interact_opt()
            .map_err(Into::into),
    }?;

    if let Some(index) = index {
        Ok(Some(items.remove(index)))
    } else {
        Ok(None)
    }
}
