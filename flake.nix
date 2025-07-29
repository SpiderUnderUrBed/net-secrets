{
  description = "Manage secrets over the network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, systems, ... }:
    let
      systemList = builtins.attrNames systems;
      eachSystem = nixpkgs.lib.genAttrs systemList;
    in {
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          netsecretsPkg = pkgs.callPackage ./pkgs/netsecrets.nix {};
        in {
          netsecrets = netsecretsPkg;
          default = netsecretsPkg;
        }
      );

      nixosModules.netsecrets = ./modules/netsecrets/default.nix;
      nixosModules.default = self.nixosModules.netsecrets;

      overlays.default = import ./overlay.nix;
    };
}
