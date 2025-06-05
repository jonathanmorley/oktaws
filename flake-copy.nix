{
  inputs = {
    # crane.url = "github:ipetkov/crane";
    # dream2nix.url = "github:nix-community/dream2nix";
    flake-utils.url = "github:numtide/flake-utils";
    crate2nix.url = "github:nix-community/crate2nix";
  };

  outputs = {
    nixpkgs,
    crate2nix,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      cargoNix = crate2nix.tools.${system}.appliedCargoNix {
        name = "oktaws";
        src = ./.;
      };
    in {
      formatter = pkgs.alejandra;
      packages.default = cargoNix.rootCrate.build;
    });
}
