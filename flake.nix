{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/24.05";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    {
      overlays.default = final: prev: {
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