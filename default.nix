{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "oktaws";
  version = "0.21.2";

  src = lib.cleanSource ./.;
  cargoLock = {
    lockFile = ./Cargo.lock;
    outputHashes = {
      "aws_config_mod-0.3.0" = "sha256-M+9IZWRG4oucZhKnJpJQlYtbkrSU/jwxVYtdTOopook=";
    };
  };

  meta = {
    description = "This program authenticates with Okta, assumes a provided role, and pulls a temporary key with STS to support the role assumption built into the `aws` cli.";
    mainProgram = "oktaws";
    homepage = "https://github.com/jonathanmorley/oktaws";
    license = lib.licenses.asl20;
  };
}
