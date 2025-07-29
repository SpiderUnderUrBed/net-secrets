{
  description = "Manage secrets over the network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    systems.url = "github:nix-systems/default";
  };

  outputs = { self, nixpkgs, systems, ... }:
    let
      # systems is expected to be an attribute set, e.g. { x86_64-linux = ...; aarch64-linux = ...; }
      eachSystem = nixpkgs.lib.genAttrs (builtins.attrNames systems);
    in
    {
      nixosModules.netsecrets = ./modules/netsecrets/default.nix;
      nixosModules.default = self.nixosModules.netsecrets;

      overlays.default = import ./overlay.nix;

      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          netsecretsPkg = pkgs.callPackage ./pkgs/netsecrets.nix {};
        in {
          netsecrets = netsecretsPkg;
          lib = import ./lib { inherit pkgs; };
          default = netsecretsPkg;  # No self reference here!
        });
    };
}
