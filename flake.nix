{
  inputs = {
    nixpkgs.url = "github:Princemachiavelli/nixpkgs/unstable-good";
    flake-utils.url = "github:numtide/flake-utils";
  };

outputs = { self, nixpkgs, flake-utils, ... }:
  {
      nixosModules = rec {
        default = import ./module.nix; 
      };
  } //
  flake-utils.lib.eachDefaultSystem (system:
    let
      pkgs = import nixpkgs {
          inherit system;
          config.allowUnfree = true;
        };
      prometheus-clamscan-exporter = pkgs.callPackage ./prometheus-clamscan-exporter.nix { };
    in {
      packages = {
        inherit prometheus-clamscan-exporter;
        default = prometheus-clamscan-exporter;
      };
    });
}
