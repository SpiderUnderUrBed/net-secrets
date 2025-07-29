{
  description = "Manage secrets over the network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # systems input can be omitted or replaced if you want to hardcode systems
  };

  outputs = { self, nixpkgs, ... }:
    let
      systemList = [ "x86_64-linux" ];  # hardcoded system list for simplicity
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
