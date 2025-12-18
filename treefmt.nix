# See available programs from https://github.com/numtide/treefmt-nix/tree/main/programs
{inputs, ...}: {
  imports = [inputs.treefmt-nix.flakeModule];
  perSystem = {
    pkgs,
    lib,
    ...
  }: {
    treefmt = {
      settings.on-unmatched = "fatal"; # Ensure 100% coverage
      settings.global.excludes = lib.mkAfter [
        ".editorconfig"
        ".github/workflows/release.yml"
      ];
      programs.actionlint.enable = true; # github action linter
      programs.alejandra.enable = true; # nix
      programs.jsonfmt.enable = true; # json
      programs.mdformat.enable = true; # markdown
      programs.rustfmt.enable = true; # rust
      programs.taplo.enable = true; # toml
      programs.xmllint.enable = true; # xml
    };
  };
}
