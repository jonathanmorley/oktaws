#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![warn(clippy::cargo)]
#![allow(clippy::multiple_crate_versions)]

use oktaws::aws::config::ConfigStore;
use oktaws::aws::profile::Store as ProfileStore;
use oktaws::config::oktaws_home;
use oktaws::config::organization::{Config as OrganizationConfig, Pattern as OrganizationPattern};
use oktaws::okta::client::Client as OktaClient;
// Import sso module to make its Client impl methods available
#[allow(unused_imports)]
use oktaws::okta::sso;

use std::convert::{TryFrom, TryInto};

use clap::Parser;
use clap_verbosity_flag::Verbosity;
use color_eyre::eyre::{Result, eyre};
use glob::Pattern;
use tracing::instrument;
use tracing_log::AsTrace;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::{Registry, prelude::*};
use tracing_tree::HierarchicalLayer;
use whoami::username;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Args {
    #[clap(flatten)]
    verbosity: Verbosity,

    #[clap(subcommand)]
    cmd: Option<Command>,

    #[clap(flatten)]
    default: RefreshArgs,
}

#[derive(Parser, Debug)]
enum Command {
    /// Refresh credentials from okta
    Refresh(RefreshArgs),

    /// Generate an organization.toml configuration
    Init(InitArgs),

    /// Generate AWS SSO configuration in ~/.aws/config
    InitSso(InitSsoArgs),
}

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    let args = Args::parse();

    let filter =
        Targets::new().with_target(module_path!(), args.verbosity.log_level_filter().as_trace());

    let subscriber = Registry::default()
        .with(filter)
        .with(HierarchicalLayer::new(2).with_targets(true));
    tracing::subscriber::set_global_default(subscriber)?;

    match args.cmd {
        Some(Command::Refresh(args)) => refresh(args).await,
        Some(Command::Init(args)) => init(args.try_into()?).await,
        Some(Command::InitSso(args)) => init_sso(args.try_into()?).await,
        None => refresh(args.default).await,
    }
}

#[derive(Parser, Debug)]
struct RefreshArgs {
    /// Okta organizations to use
    #[clap(short, long, default_value = "*")]
    pub organizations: OrganizationPattern,

    /// Profiles to update
    #[clap(default_value = "*")]
    pub profiles: Pattern,

    /// Role to override toml file with
    #[clap(short, long = "role-override")]
    pub role_override: Option<String>,

    /// Forces new credentials
    #[clap(short, long = "force-new")]
    pub force_new: bool,
}

#[instrument(skip_all, fields(organizations=%args.organizations,profiles=%args.profiles))]
async fn refresh(args: RefreshArgs) -> Result<()> {
    // Set up a store for AWS profiles
    let mut aws_credentials = ProfileStore::load(None)?;

    // Load AWS config to check for SSO profile conflicts
    let aws_config = ConfigStore::load(None)?;

    let organizations = args.organizations.organizations()?;

    if organizations.is_empty() {
        return Err(eyre!(
            "No organizations found matching {}",
            args.organizations
        ));
    }

    for organization in organizations {
        // Collect profiles that conflict with SSO profiles before fetching credentials
        let mut conflicting_profiles = Vec::new();
        for profile in &organization.profiles {
            if args.profiles.matches(&profile.name) && aws_config.is_sso_profile(&profile.name) {
                conflicting_profiles.push(profile.name.clone());
            }
        }

        // Warn about conflicts but continue with non-conflicting profiles
        for profile_name in &conflicting_profiles {
            eprintln!(
                "Warning: Skipping profile '{}' - already exists as an SSO profile in ~/.aws/config. \
                Please rename one of the profiles to avoid the conflict.",
                profile_name
            );
        }

        let okta_client = OktaClient::new(
            organization.name.clone(),
            organization.username.clone(),
            args.force_new,
        )
        .await?;

        let credentials_map = organization
            .into_credentials(
                &okta_client,
                args.profiles.clone(),
                args.role_override.as_ref(),
            )
            .await;

        for (name, creds) in credentials_map {
            // Skip profiles that have SSO conflicts
            if conflicting_profiles.contains(&name) {
                continue;
            }
            aws_credentials.upsert_credential(&name, &creds)?;
        }
    }

    aws_credentials.save()
}

#[derive(Parser, Debug)]
struct InitArgs {
    /// Okta organization to use
    organization: Option<String>,

    /// Okta username
    #[structopt(short)]
    username: Option<String>,

    /// Forces new credentials
    #[structopt(short, long = "force-new")]
    force_new: bool,
}

#[derive(Parser, Debug)]
struct InitSsoArgs {
    /// Okta organization to use
    organization: Option<String>,

    /// Okta username
    #[structopt(short)]
    username: Option<String>,

    /// Forces new credentials
    #[structopt(short, long = "force-new")]
    force_new: bool,
}

struct Init {
    organization: String,
    username: String,
    force_new: bool,
}

struct InitSso {
    organization: String,
    username: String,
    force_new: bool,
}

impl TryFrom<InitArgs> for Init {
    type Error = eyre::Error;

    fn try_from(args: InitArgs) -> Result<Self, Self::Error> {
        let organization = args.organization.map_or_else(
            || {
                dialoguer::Input::new()
                    .with_prompt("Okta Organization Name")
                    .interact_text()
            },
            Ok,
        )?;

        let username = args.username.map_or_else(
            || {
                dialoguer::Input::<String>::new()
                    .with_prompt(format!("Username for {organization}"))
                    .default(username())
                    .interact_text()
            },
            Ok,
        )?;

        Ok(Self {
            organization,
            username,
            force_new: args.force_new,
        })
    }
}

impl TryFrom<InitSsoArgs> for InitSso {
    type Error = eyre::Error;

    fn try_from(args: InitSsoArgs) -> Result<Self, Self::Error> {
        let organization = args.organization.map_or_else(
            || {
                dialoguer::Input::new()
                    .with_prompt("Okta Organization Name")
                    .interact_text()
            },
            Ok,
        )?;

        let username = args.username.map_or_else(
            || {
                dialoguer::Input::<String>::new()
                    .with_prompt(format!("Username for {organization}"))
                    .default(username())
                    .interact_text()
            },
            Ok,
        )?;

        Ok(Self {
            organization,
            username,
            force_new: args.force_new,
        })
    }
}

/// Output a config toml for a given organization
async fn init(options: Init) -> Result<()> {
    let okta_client = OktaClient::new(
        options.organization.clone(),
        options.username.clone(),
        options.force_new,
    )
    .await?;

    let organization_config =
        OrganizationConfig::from_organization(&okta_client, options.username).await?;

    // Filter to only federated profiles
    let federated_profiles: indexmap::IndexMap<_, _> = organization_config
        .profiles
        .into_iter()
        .filter(|(_, profile_config)| match &profile_config {
            oktaws::config::profile::Config::Name(_) => true,
            oktaws::config::profile::Config::Detailed { account_id, .. } => account_id.is_none(),
        })
        .collect();

    // Create oktaws config with only federated profiles
    let federated_config = OrganizationConfig {
        username: organization_config.username.clone(),
        roles: organization_config.roles.clone(),
        role: organization_config.role.clone(),
        duration_seconds: organization_config.duration_seconds,
        profiles: federated_profiles,
    };

    let org_toml = toml::to_string_pretty(&federated_config)?;

    let oktaws_home = oktaws_home()?;
    let oktaws_config_path = oktaws_home.join(format!("{}.toml", options.organization));

    println!(
        "Federated profiles (will be written to {}):",
        oktaws_config_path.display()
    );
    println!("{}", &org_toml);

    let write_to_file = dialoguer::Confirm::new()
        .with_prompt(format!("Write config to {}?", oktaws_config_path.display()))
        .interact()?;

    if write_to_file {
        std::fs::create_dir_all(oktaws_home)?;
        std::fs::write(oktaws_config_path, org_toml)?;
    }

    Ok(())
}

/// Sanitize a session name to be safe for filesystem and CLI usage
/// Replaces spaces with hyphens, removes special chars, and converts to lowercase
fn sanitize_session_name(name: &str) -> String {
    let mut result = String::new();
    let mut last_was_hyphen = false;

    for c in name.chars() {
        match c {
            ' ' => {
                if !last_was_hyphen && !result.is_empty() {
                    result.push('-');
                    last_was_hyphen = true;
                }
            }
            'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => {
                result.push(c);
                last_was_hyphen = false;
            }
            '-' => {
                if !last_was_hyphen && !result.is_empty() {
                    result.push('-');
                    last_was_hyphen = true;
                }
            }
            _ => {
                // Skip special characters entirely
            }
        }
    }

    // Remove trailing hyphen if present
    if result.ends_with('-') {
        result.pop();
    }

    result.to_lowercase()
}

/// Determine the final profile name, adding session prefix if needed to avoid collisions
fn determine_final_profile_name(
    profile_name: &str,
    session_name: &str,
    needs_prefix: &std::collections::HashSet<String>,
) -> String {
    let sanitized = sanitize_session_name(profile_name);
    if needs_prefix.contains(&sanitized) {
        format!("{}-{}", session_name, sanitized)
    } else {
        sanitized
    }
}

/// Check if a profile needs role selection based on available roles and existing configuration
fn profile_needs_role_selection(available_roles: &[String], existing_role: Option<String>) -> bool {
    if available_roles.len() == 1 {
        false // Only one role, no selection needed
    } else if let Some(existing) = existing_role {
        !available_roles.contains(&existing) // Needs selection if existing role is invalid
    } else {
        true // No existing role, needs selection
    }
}

/// Select the appropriate role for a profile based on available options and defaults
fn select_role_for_profile(
    profile_name: &str,
    available_roles: &[String],
    existing_role: Option<String>,
    default_role: Option<&String>,
) -> Result<String> {
    if available_roles.len() == 1 {
        // Only one role available, use it
        return Ok(available_roles[0].clone());
    }

    if let Some(existing) = existing_role {
        // Profile exists, check if the existing role is still valid
        if available_roles.contains(&existing) {
            // Existing role is still valid, use it
            return Ok(existing);
        }
        // Existing role is no longer available, prompt user
        println!(
            "  Note: Previously selected role '{}' is no longer available for {}",
            existing, profile_name
        );
        let selection = dialoguer::Select::new()
            .with_prompt(format!("Choose Role for {}", profile_name))
            .items(available_roles)
            .interact()?;
        return Ok(available_roles[selection].clone());
    }

    if let Some(default) = default_role {
        // No existing profile, check if default role is available
        if available_roles.contains(default) {
            return Ok(default.clone());
        }
        // Default role not available, prompt user
        let selection = dialoguer::Select::new()
            .with_prompt(format!("Choose Role for {}", profile_name))
            .items(available_roles)
            .interact()?;
        return Ok(available_roles[selection].clone());
    }

    // No existing profile and no default role, prompt user
    let selection = dialoguer::Select::new()
        .with_prompt(format!("Choose Role for {}", profile_name))
        .items(available_roles)
        .interact()?;
    Ok(available_roles[selection].clone())
}

/// Generate AWS SSO configuration only
async fn init_sso(options: InitSso) -> Result<()> {
    let okta_client = OktaClient::new(
        options.organization.clone(),
        options.username.clone(),
        options.force_new,
    )
    .await?;

    // Get app links and filter to only SSO apps
    let app_links = okta_client.app_links(None).await?;
    let sso_links: Vec<_> = app_links
        .into_iter()
        .filter(|link| link.app_name == "amazon_aws_sso")
        .collect();

    if sso_links.is_empty() {
        return Err(eyre!("No AWS SSO applications found for this organization"));
    }

    let mut aws_config = ConfigStore::load(None)?;
    let mut total_profiles = 0;

    // First pass: collect all profile data from all sessions
    let mut sessions = Vec::new();

    // Process each SSO app as a separate SSO session
    for sso_link in sso_links {
        let display_name = sso_link.label.clone();
        let session_name = sanitize_session_name(&display_name);

        println!(
            "\n=== Processing SSO Application: {} (session: {}) ===",
            display_name, session_name
        );

        // Get SSO info for this app
        print!("Authenticating to AWS SSO... ");
        std::io::Write::flush(&mut std::io::stdout())?;
        let org_auth = okta_client
            .get_org_auth_for_app_link(sso_link.clone())
            .await?;
        println!("✓");

        let start_url = format!("https://{}.awsapps.com/start", org_auth.org_id);
        let region = "us-east-1".to_string();

        // Get all SSO account mappings for this app
        println!("Fetching accounts and roles...");
        let mut all_account_mappings = okta_client.get_all_account_mappings(vec![sso_link]).await?;
        println!(
            "✓ Found {} account{}",
            all_account_mappings.len(),
            if all_account_mappings.len() == 1 {
                ""
            } else {
                "s"
            }
        );
        all_account_mappings.sort_by(|a, b| a.account_name.cmp(&b.account_name));

        if all_account_mappings.is_empty() {
            println!("No accounts found for this SSO application, skipping.");
            continue;
        }

        // Collect SSO profiles with account IDs (don't select roles yet)
        let mut sso_profiles = indexmap::IndexMap::new();
        for mapping in all_account_mappings {
            if let Some(account_id) = mapping.account_id {
                // Skip profiles without roles
                if mapping.role_names.is_empty() {
                    continue;
                }

                sso_profiles.insert(
                    mapping.account_name.clone(),
                    (account_id, mapping.role_names),
                );
            }
        }

        if sso_profiles.is_empty() {
            println!(
                "No SSO profiles with account IDs found for {}, skipping.",
                display_name
            );
            continue;
        }

        // Store session data for second pass (we'll determine default_role later after collision detection)
        sessions.push((session_name, display_name, start_url, region, sso_profiles));
    }

    if sessions.is_empty() {
        return Err(eyre!("No SSO profiles were configured"));
    }

    // Second pass: detect collisions and write profiles
    let mut profile_name_sessions = std::collections::HashMap::new();

    // Count occurrences of each SANITIZED profile name across all sessions
    for (session_name, _, _, _, sso_profiles) in &sessions {
        for profile_name in sso_profiles.keys() {
            let sanitized = sanitize_session_name(profile_name);
            profile_name_sessions
                .entry(sanitized)
                .or_insert_with(Vec::new)
                .push(session_name.clone());
        }
    }

    // Determine which profiles need session prefix (those that appear in multiple sessions)
    let needs_prefix: std::collections::HashSet<String> = profile_name_sessions
        .iter()
        .filter(|(_, sessions)| sessions.len() > 1)
        .map(|(name, _)| name.clone())
        .collect();

    // Write sessions and profiles with appropriate names
    for (session_name, display_name, start_url, region, sso_profiles) in sessions {
        // Create SSO session
        aws_config.upsert_sso_session(&session_name, &start_url, &region)?;

        // First, check which profiles need role selection (don't have valid existing roles)
        let mut needs_selection_profiles = Vec::new();
        for (profile_name, (_, available_roles)) in &sso_profiles {
            let final_profile_name =
                determine_final_profile_name(profile_name, &session_name, &needs_prefix);
            let existing_role = aws_config.get_profile_role(&final_profile_name);

            if profile_needs_role_selection(available_roles, existing_role) {
                needs_selection_profiles.push(profile_name.clone());
            }
        }

        // Only prompt for default role if there are profiles that need selection
        let default_role = if !needs_selection_profiles.is_empty() {
            // Collect all unique role names and count how many accounts have each role
            let mut role_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for (_, (_, available_roles)) in &sso_profiles {
                for role in available_roles {
                    *role_counts.entry(role.clone()).or_insert(0) += 1;
                }
            }

            // Sort roles by count (descending) then alphabetically
            let mut role_list: Vec<(String, usize)> = role_counts.into_iter().collect();
            role_list.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

            // Prompt user to select default role (if there are multiple roles)
            if role_list.len() > 1 {
                let role_display: Vec<String> = role_list
                    .iter()
                    .map(|(role, count)| {
                        format!(
                            "{} ({} account{})",
                            role,
                            count,
                            if *count == 1 { "" } else { "s" }
                        )
                    })
                    .collect();

                // Add a "None" option
                let mut options = role_display.clone();
                options.push("None (prompt for each account)".to_string());

                let selection = dialoguer::Select::new()
                    .with_prompt(format!(
                        "Choose default role for {} ({} profile{} need role selection)",
                        display_name,
                        needs_selection_profiles.len(),
                        if needs_selection_profiles.len() == 1 {
                            ""
                        } else {
                            "s"
                        }
                    ))
                    .items(&options)
                    .default(0)
                    .interact()?;

                if selection < role_list.len() {
                    Some(role_list[selection].0.clone())
                } else {
                    None
                }
            } else if role_list.len() == 1 {
                Some(role_list[0].0.clone())
            } else {
                None
            }
        } else {
            None
        };

        // Create SSO profiles
        println!(
            "\nSSO profiles for {} (session: {}):",
            display_name, session_name
        );
        for (profile_name, (account_id, available_roles)) in &sso_profiles {
            let final_profile_name =
                determine_final_profile_name(profile_name, &session_name, &needs_prefix);
            let existing_role = aws_config.get_profile_role(&final_profile_name);

            // Determine which role to use
            let role = select_role_for_profile(
                profile_name,
                available_roles,
                existing_role,
                default_role.as_ref(),
            )?;

            aws_config.upsert_sso_profile(
                &final_profile_name,
                &session_name,
                account_id,
                &role,
                available_roles.clone(),
            )?;

            // Only show "renamed from" if we added a session prefix (collision resolution)
            // Don't show it for just sanitization
            let sanitized = sanitize_session_name(profile_name);
            if needs_prefix.contains(&sanitized) {
                println!(
                    "  - {} (prefixed due to collision with other session)",
                    final_profile_name
                );
            } else {
                println!("  - {}", final_profile_name);
            }
            total_profiles += 1;
        }
    }

    if total_profiles == 0 {
        return Err(eyre!("No SSO profiles were configured"));
    }

    println!("\n=== Summary ===");
    println!("Total profiles configured: {}", total_profiles);

    let write_sso = dialoguer::Confirm::new()
        .with_prompt("Write SSO configuration to ~/.aws/config?")
        .default(true)
        .interact()?;

    if write_sso {
        aws_config.save()?;
        println!("\nSSO configuration written successfully!");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_session_name_basic() {
        assert_eq!(sanitize_session_name("My Session"), "my-session");
    }

    #[test]
    fn test_sanitize_session_name_multiple_spaces() {
        assert_eq!(sanitize_session_name("My   Multi  Space"), "my-multi-space");
    }

    #[test]
    fn test_sanitize_session_name_special_chars() {
        assert_eq!(sanitize_session_name("Test@#$%Name"), "testname");
    }

    #[test]
    fn test_sanitize_session_name_leading_trailing_spaces() {
        assert_eq!(sanitize_session_name("  spaces  "), "spaces");
    }

    #[test]
    fn test_sanitize_session_name_mixed_case() {
        assert_eq!(sanitize_session_name("MixedCASE"), "mixedcase");
    }

    #[test]
    fn test_sanitize_session_name_hyphens() {
        assert_eq!(
            sanitize_session_name("already-hyphenated"),
            "already-hyphenated"
        );
    }

    #[test]
    fn test_sanitize_session_name_multiple_hyphens() {
        assert_eq!(sanitize_session_name("multi---hyphen"), "multi-hyphen");
    }

    #[test]
    fn test_sanitize_session_name_underscore() {
        assert_eq!(sanitize_session_name("with_underscore"), "with_underscore");
    }

    #[test]
    fn test_sanitize_session_name_numbers() {
        assert_eq!(sanitize_session_name("Test123Session"), "test123session");
    }

    #[test]
    fn test_sanitize_session_name_empty() {
        assert_eq!(sanitize_session_name(""), "");
    }

    #[test]
    fn test_sanitize_session_name_only_special_chars() {
        assert_eq!(sanitize_session_name("@#$%"), "");
    }

    #[test]
    fn test_sanitize_session_name_trailing_hyphen() {
        assert_eq!(sanitize_session_name("test-"), "test");
    }

    #[test]
    fn test_determine_final_profile_name_no_collision() {
        let needs_prefix = std::collections::HashSet::new();
        assert_eq!(
            determine_final_profile_name("My Profile", "session", &needs_prefix),
            "my-profile"
        );
    }

    #[test]
    fn test_determine_final_profile_name_with_collision() {
        let mut needs_prefix = std::collections::HashSet::new();
        needs_prefix.insert("my-profile".to_string());
        assert_eq!(
            determine_final_profile_name("My Profile", "session", &needs_prefix),
            "session-my-profile"
        );
    }

    #[test]
    fn test_determine_final_profile_name_already_sanitized() {
        let needs_prefix = std::collections::HashSet::new();
        assert_eq!(
            determine_final_profile_name("already-sanitized", "session", &needs_prefix),
            "already-sanitized"
        );
    }

    #[test]
    fn test_profile_needs_role_selection_single_role() {
        let roles = vec!["Admin".to_string()];
        assert!(!profile_needs_role_selection(&roles, None));
    }

    #[test]
    fn test_profile_needs_role_selection_multiple_roles_no_existing() {
        let roles = vec!["Admin".to_string(), "ReadOnly".to_string()];
        assert!(profile_needs_role_selection(&roles, None));
    }

    #[test]
    fn test_profile_needs_role_selection_multiple_roles_valid_existing() {
        let roles = vec!["Admin".to_string(), "ReadOnly".to_string()];
        assert!(!profile_needs_role_selection(
            &roles,
            Some("Admin".to_string())
        ));
    }

    #[test]
    fn test_profile_needs_role_selection_multiple_roles_invalid_existing() {
        let roles = vec!["Admin".to_string(), "ReadOnly".to_string()];
        assert!(profile_needs_role_selection(
            &roles,
            Some("OldRole".to_string())
        ));
    }

    #[test]
    fn test_profile_needs_role_selection_single_role_with_existing() {
        let roles = vec!["Admin".to_string()];
        assert!(!profile_needs_role_selection(
            &roles,
            Some("Admin".to_string())
        ));
    }

    #[test]
    fn test_profile_needs_role_selection_single_role_different_existing() {
        let roles = vec!["Admin".to_string()];
        // Even if existing is different, single role means no selection needed
        assert!(!profile_needs_role_selection(
            &roles,
            Some("OldRole".to_string())
        ));
    }
}
