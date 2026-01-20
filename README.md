[![Continuous Integration](https://github.com/jonathanmorley/oktaws/actions/workflows/ci.yml/badge.svg)](https://github.com/jonathanmorley/oktaws/actions/workflows/ci.yml)

# oktaws

This program authenticates with Okta to provide temporary AWS credentials. It supports both:
- **Federated AWS access** (SAML-based, using `amazon_aws` Okta apps)
- **AWS Identity Center/SSO** (using `amazon_aws_sso` Okta apps)

## Installation

Follow the instructions in the release for the version you want to install.
You should also ensure that the install location (usually `~/.cargo/bin`) is in your PATH.

## Setup

### For Federated AWS Access

Run `oktaws init` to generate a configuration file for federated profiles:

```sh
oktaws init
```

You will be prompted for various config items. Oktaws configuration resides in `~/.oktaws/<OKTA ACCOUNT>.toml` files with the following structure:

```toml
username = '<USERNAME>'
role = '<DEFAULT ROLE>'

[profiles]
profile1 = '<OKTA APPLICATION NAME>'
profile2 = { application = '<OKTA APPLICATION NAME>', role = '<ROLE OVERRIDE>' }
```

The `role` value is the name (not ARN) of the role you would like to assume. This can be found when logging into the AWS console through Okta.

### For AWS Identity Center/SSO

Run `oktaws init-sso` to automatically configure AWS SSO profiles in `~/.aws/config`:

```sh
oktaws init-sso
```

This command will:
1. Discover all AWS SSO applications in your Okta account
2. Fetch all available accounts and roles for each SSO application
3. Create SSO sessions in `~/.aws/config` for each application
4. Create SSO profiles for each account with intelligent role selection
5. Preserve your existing role selections when re-running

The command handles profile name collisions across multiple SSO applications by automatically prefixing profiles with the session name when needed.

**Note:** `~/.aws/config` is modified by `init-sso` but only read by other commands.

## Usage

### For Federated AWS Profiles

Use `oktaws refresh` to generate temporary credentials for federated profiles:

```sh
# Refresh a specific profile
$ oktaws refresh profile1

# Refresh all profiles in your oktaws config
$ oktaws refresh
```

Then use the AWS CLI with those credentials:

```sh
$ aws --profile profile1 ec2 describe-instances
```

### For AWS Identity Center/SSO Profiles

After running `oktaws init-sso`, use the native AWS CLI SSO login flow:

```sh
# Login to an SSO session
$ aws sso login --profile my-sso-profile

# Use AWS CLI commands
$ aws --profile my-sso-profile ec2 describe-instances
```

The SSO profiles created by `oktaws init-sso` work directly with the AWS CLI's built-in SSO support.

### Example: init-sso Output

```sh
$ oktaws init-sso

=== Processing SSO Application: My Company AWS (session: my-company-aws) ===
Authenticating to AWS SSO... ✓
Fetching accounts and roles...
  Processing accounts 1-10/50...
  Processing accounts 11-20/50...
  ...
  Processed 50/50 accounts
✓ Found 50 accounts

Choose default role for My Company AWS (45 profiles need role selection)
> PowerUserAccess (40 accounts)
  ReadOnlyAccess (50 accounts)
  AdministratorAccess (15 accounts)
  None (prompt for each account)

SSO profiles for My Company AWS (session: my-company-aws):
  - production
  - staging
  - development
  ...

Successfully configured 50 SSO profiles across 1 session(s)
Wrote config to ~/.aws/config
```

## Debugging

Login didn't work? Use the `-v` flag to emit more verbose logs. Add more `-v`s for increased verbosity:

```sh
$ oktaws refresh production -vv
$ oktaws init-sso -vv
```

## Contributors

- Jonathan Morley [@jonathanmorley]
