#[macro_use]
extern crate log;

pub mod aws;
pub mod config;
pub mod okta;
pub mod saml;

fn select<T, P, F, S>(mut items: Vec<T>, prompt: P, displayer: F) -> std::io::Result<T>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let index = dialoguer::Select::new()
        .with_prompt(prompt)
        .items(&items.iter().map(displayer).collect::<Vec<_>>())
        .default(0)
        .paged(true)
        .interact()?;

    Ok(items.remove(index))
}
