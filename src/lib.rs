#[macro_use]
extern crate failure;
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

fn multi_select<T, P, F, S>(items: Vec<T>, prompt: P, displayer: F) -> std::io::Result<Vec<T>>
where
    P: Into<String>,
    F: FnMut(&T) -> S,
    S: ToString,
{
    let indices = dialoguer::MultiSelect::new()
        .with_prompt(prompt)
        .items_checked(
            &items
                .iter()
                .map(displayer)
                .map(|s| (s, true))
                .collect::<Vec<_>>(),
        )
        .paged(true)
        .interact()?;

    Ok(items
        .into_iter()
        .enumerate()
        .filter(|(i, _)| indices.contains(i))
        .map(|(_, v)| v)
        .collect())
}
