{
  description = "Manage secrets over the network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      systems = [ "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
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
