{
  description = "Manage secrets over the network";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      systemList = [ "x86_64-linux" ];
      eachSystem = nixpkgs.lib.genAttrs systemList;
    in {
      # Expose per‑system packages.netsecrets and .default
      packages = eachSystem (system:
        let
          pkgs = import nixpkgs { inherit system; };
          netsecretsPkg = pkgs.callPackage ./pkgs/netsecrets.nix {};
        in {
          netsecrets = netsecretsPkg;
          default    = netsecretsPkg;
        });

      # Your NixOS module
      nixosModules.netsecrets = ./modules/netsecrets/default.nix;
      nixosModules.default     = self.nixosModules.netsecrets;

      # Any overlay you need
      overlays.default = import ./overlay.nix;
    };
}
