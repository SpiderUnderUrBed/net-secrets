{ config, lib, pkgs, ... }:

let
  netsecrets = import ../lib/default.nix { inherit pkgs; };
in {
  options = {
    netsecrets.client = {
      enable = lib.mkEnableOption "the netsecrets client";

      secrets = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "List of secret names to fetch from server";
      };

      ip = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = "Server IP address";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 8080;
        description = "Server port";
      };

      verbose = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable verbose logging";
      };
    };

    secrets = lib.mkOption {
      type = lib.types.attrsOf (lib.types.submodule {
        options = {
          file = lib.mkOption {
            type = lib.types.path;
            description = "Path to the secret file";
          };
        };
      });
      default = {};
      description = "Available secrets configuration";
    };
  };

  config = let
    cfg = config.netsecrets.client;
    secretPaths = lib.listToAttrs (map (name: {
      name = name;
      value = { file = "/var/lib/netsecrets/${name}"; };
    }) cfg.secrets);
  in lib.mkIf cfg.enable {
    secrets = secretPaths;

    system.activationScripts.netsecrets-dir = ''
      mkdir -p /var/lib/netsecrets
      chmod 700 /var/lib/netsecrets
    '';

    environment.etc."netsecrets/client.conf".text = ''
      NETSECRETS_SERVER_IP=${cfg.ip}
      NETSECRETS_SERVER_PORT=${toString cfg.port}
      ${lib.optionalString cfg.verbose "NETSECRETS_VERBOSE=1"}
    '';

    systemd.services.netsecrets-client = {
      description = "NetSecrets Client";
      wantedBy = ["multi-user.target"];
      after = ["network-online.target"];
      wants = ["network-online.target"];
      serviceConfig = {
        ExecStart = pkgs.writeShellScript "netsecrets-fetch" ''
          set -e
          ${toString (map (name: 
            "${netsecrets.send} fetch ${name} --output /var/lib/netsecrets/${name}"
          ) cfg.secrets}
        '';
        Restart = "on-failure";
        User = "root";
        EnvironmentFile = "/etc/netsecrets/client.conf";
      };
    };
  };
}
