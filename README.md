[![Build and Test](https://github.com/jonathanmorley/oktaws/actions/workflows/build.yml/badge.svg)](https://github.com/jonathanmorley/oktaws/actions/workflows/build.yml)

# oktaws

This program authenticates with Okta, assumes a provided role, and pulls a temporary key with STS to support the role assumption built into the `aws` cli.

## Installation

Grab a binary for your OS from the [latest release](https://github.com/jonathanmorley/oktaws/releases/latest), and put it somewhere in your PATH. Linux, MacOS and Windows OSes are supported.

## Setup

Run `oktaws init` to have `oktaws` generate a config file for you.
You will be prompted for various config items.

Oktaws configuration resides in `~/.oktaws/<OKTA ACCOUNT>.toml` files, and have the following fields:

```
username = '<USERNAME>'
role = '<DEFAULT ROLE>'

[profiles]
profile1 = '<OKTA APPLICATION NAME>'
profile2 = { application = '<OKTA APPLICATION NAME>', role = '<ROLE OVERRIDE>' }
```

The `role` value above is the name (not ARN) of the role you would like to log in as. This can be found when logging into the AWS console through Okta.

The `~/.aws/config` file is read for information, but not modified.
See [Assuming a Role](https://docs.aws.amazon.com/cli/latest/userguide/cli-roles.html) for information on configuring the AWS CLI to assume a role.

## Usage

You can run `oktaws refresh --profile profile1` to generate keys for a single profile, or just `oktaws refresh` to generate keys for all profiles.

```sh
$ oktaws refresh --profile [AWS profile]
$ aws --profile [AWS profile] [command]
```

for example

```sh
$ oktaws refresh --profile production
$ aws --profile production ec2 describe-instances
```

## Debugging

Login didn't work? Use the `-v` flag to emit more verbose logs. Add more `-v`s for increased verbosity:

```sh
$ oktaws refresh --profile production -vv
```

## Upgrading

### v0.15

`oktaws v0.15` contains breaking changes to the interface.
Because of the addition of the `init` command, you must use `oktaws refresh` to generate credentials.
You will also need to pass profiles into the `refresh` command with `--profile`, rather than a positional argument.

You can approximate a pre-0.15 oktaws command with `alias oktaws=oktaws refresh --profile`

## Contributors

- Jonathan Morley [@jonathanmorley]
