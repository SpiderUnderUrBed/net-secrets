outputs = {
  self,
  nixpkgs,
  systems,
}: let
  eachSystem = nixpkgs.lib.genAttrs (import systems);
in {
  nixosModules.netsecrets = ./modules/netsecrets/default.nix;
  nixosModules.default = self.nixosModules.netsecrets;

  overlays.default = import ./overlay.nix;

  packages = eachSystem (system: let
    pkgs = import nixpkgs {inherit system;};
    netsecretsPkg = pkgs.callPackage ./pkgs/netsecrets.nix {};
  in {
    netsecrets = netsecretsPkg;
    lib = import ./lib {inherit pkgs;};
    default = netsecretsPkg;  # no recursive self reference
  });
};
