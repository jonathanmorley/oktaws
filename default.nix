{ pkgs, lib, rustPlatform, perl }:
rustPlatform.buildRustPackage {
  pname = "oktaws";
  version = "0.19.0";

  src = lib.cleanSource ./.;

  cargoLock = {
    lockFile = ./Cargo.lock;
  };

  buildInputs = [
    # Add additional build inputs here
  ] ++ lib.optionals pkgs.stdenv.isDarwin [
    # Additional darwin specific inputs can be set here
    pkgs.libiconv
    pkgs.darwin.Security
  ];

  cargoBuildFlags = "--package=oktaws";

  useNextest = true;
  cargoTestFlags = "--package=oktaws";

  meta = with lib; {
    description = "AWS authentication via Okta";
    homepage = "https://github.com/jonathanmorley/oktaws";
    license = licenses.asl20;
  };
}