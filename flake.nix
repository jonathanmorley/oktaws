{
  inputs = {
    crane.url = "github:ipetkov/crane";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    nixpkgs,
    crane,
    flake-utils,
    ...
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = nixpkgs.legacyPackages.${system};
      craneLib = crane.mkLib pkgs;
    in {
      formatter = pkgs.alejandra;
      packages.default = craneLib.buildPackage {
        src = craneLib.cleanCargoSource ./.;
        doCheck = false;
      };
    });
}
