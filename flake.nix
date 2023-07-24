{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    {
      overlay = final: prev: {
        oktaws = prev.callPackage ./default.nix { };
      };
    } // flake-utils.lib.eachDefaultSystem(system:
      let
        pkgs = import nixpkgs { inherit system; };
        oktaws = pkgs.callPackage ./default.nix { };
      in
        {
          packages = {
            inherit oktaws;
            default = oktaws;
          };
        }
    );
}