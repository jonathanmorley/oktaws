{
  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    crane.url = "github:ipetkov/crane";
    treefmt-nix.url = "github:numtide/treefmt-nix";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = inputs @ {
    crane,
    flake-parts,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      imports = [./treefmt.nix];
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
      ];

      perSystem = {
        pkgs,
        lib,
        system,
        inputs',
        ...
      }: let
        fenixLib = inputs'.fenix.packages;
        toolchain = fenixLib.fromToolchainFile {
          file = ./rust-toolchain.toml;
          sha256 = "sha256-zC8E38iDVJ1oPIzCqTk/Ujo9+9kx9dXq7wAwPMpkpg0=";
        };
        craneLib = (crane.mkLib pkgs).overrideToolchain toolchain;

        commonArgs = let
          # Only keeps xml files
          fixturesFilter = path: _type: builtins.match ".*/tests/fixtures/.*" path != null;
          fixturesOrCargo = path: type:
            (fixturesFilter path type) || (craneLib.filterCargoSources path type);
        in {
          src = lib.cleanSourceWith {
            src = ./.; # The original, unfiltered source
            filter = fixturesOrCargo;
            name = "source"; # Be reproducible, regardless of the directory name
          };

          strictDeps = true;
        };

        cargoArtifacts = craneLib.buildDepsOnly commonArgs;
      in rec {
        packages.default = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            doCheck = false;
          }
        );

        checks = {
          clippy = craneLib.cargoClippy (
            commonArgs
            // {
              inherit cargoArtifacts;
            }
          );

          nextest = craneLib.cargoNextest (
            commonArgs
            // {
              inherit cargoArtifacts;
              partitions = 1;
              partitionType = "count";
              cargoNextestPartitionsExtraArgs = "--no-tests=pass";
            }
          );
        };

        devShells.default = craneLib.devShell {
          # Inherit inputs from checks.
          inherit checks;

          # Extra inputs can be added here; cargo and rustc are provided by default.
          packages = [
            pkgs.cargo-dist
          ];
        };
      };
    };
}
