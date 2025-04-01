{ config, lib, pkgs, ... }:

let
  netsecrets = import ../lib/default.nix { inherit pkgs; };
  
  # Function to build secrets attribute set
  makeSecrets = names: lib.foldl' (acc: name: 
    acc // { "${name}" = { file = "/var/lib/netsecrets/${name}"; }; }
  ) {} names;

in {
  options = {
    netsecrets.client = {
      enable = lib.mkEnableOption "the netsecrets client";
      secrets = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "List of secret names to fetch";
      };
      ip = lib.mkOption {
        type = lib.types.str;
        description = "Netsecrets server IP";
      };
    };

    secrets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options.file = lib.mkOption {
          type = lib.types.path;
          description = "Path to secret file";
        };
      });
      default = {};
      internal = true;
    };
  };

  config = lib.mkIf config.netsecrets.client.enable {
    # Initialize secrets using foldl
    secrets = makeSecrets config.netsecrets.client.secrets;

    system.activationScripts.netsecrets-dir = ''
      mkdir -p /var/lib/netsecrets
      chmod 700 /var/lib/netsecrets
    '';

    systemd.services.netsecrets-client = {
      description = "Fetch secrets from server";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      serviceConfig = {
        ExecStart = let
          fetchCmd = name: 
            "${netsecrets.send} fetch ${name} --output ${config.secrets.${name}.file}";
        in pkgs.writeShellScript "fetch-secrets" ''
          ${toString (map fetchCmd config.netsecrets.client.secrets)}
        '';
        User = "root";
      };
    };
  };
}
