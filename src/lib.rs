#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

pub mod aws;
pub mod config;
pub mod okta;

use eyre::{eyre, Result};

fn select<T, P, F, S>(mut items: Vec<T>, prompt: P, displayer: F) -> Result<T>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let index = match items.len() {
        0 => Err(eyre!("No items found")),
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

fn select_multiple_opt<T, P, F, S>(mut items: Vec<T>, prompt: P, displayer: F) -> Result<Vec<T>>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let indices = match items.len() {
        0 => Err(eyre!("No items found")),
        _ => dialoguer::MultiSelect::new()
            .with_prompt(prompt)
            .items(&items.iter().map(displayer).collect::<Vec<_>>())
            .interact()
            .map_err(Into::into),
    }?;

    // Remove selected items by index, highest index first to avoid shifting
    let mut selected = Vec::new();
    for &i in indices.iter().rev() {
        selected.push(items.remove(i));
    }
    selected.reverse();
    Ok(selected)
}
