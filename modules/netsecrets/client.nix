{ config, lib, pkgs, ... }:

let
  netsecrets = import ../lib/default.nix { inherit pkgs; };

  secretType = lib.types.submodule {
    options = {
      file = lib.mkOption {
        type = lib.types.path;
        description = "Path where the secret will be stored";
      };
      restartUnits = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [];
        description = "Units to restart when this secret changes";
      };
    };
  };

in {
  options.netsecrets.client = {
    enable = lib.mkEnableOption "the netsecrets client";

    secrets = lib.mkOption {
      type = lib.types.attrsOf secretType;
      default = {};
      description = "Secrets to fetch from the server";
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

  config = let
    cfg = config.netsecrets.client;
  in lib.mkIf cfg.enable (lib.mkMerge [
    {
      system.activationScripts.netsecrets-dir = ''
        mkdir -p /var/lib/netsecrets
        chmod 700 /var/lib/netsecrets
      '';

      systemd.services.netsecrets-client = {
        description = "NetSecrets Client";
        wantedBy = ["multi-user.target"];
        after = ["network-online.target"];
        wants = ["network-online.target"];
        serviceConfig = {
          ExecStart = "${netsecrets.send}";
          Restart = "on-failure";
          User = "root";
          EnvironmentFile = "/etc/netsecrets/client.conf";
        };
      };

      environment.etc."netsecrets/client.conf".text = ''
        NETSECRETS_SERVER_IP=${cfg.ip}
        NETSECRETS_SERVER_PORT=${toString cfg.port}
        ${lib.optionalString cfg.verbose "NETSECRETS_VERBOSE=1"}
      '';
    }

    # Create services for each secret
    (lib.mapAttrs (name: secret: {
      systemd.services."netsecrets-fetch-${name}" = {
        description = "Fetch secret ${name}";
        script = ''
          ${netsecrets.send} get ${name} > ${secret.file}
          chmod 600 ${secret.file}
        '';
        serviceConfig = {
          Type = "oneshot";
          User = "root";
        };
      };
    }) cfg.secrets)

    # Create restart services where needed
    (lib.mapAttrs (name: secret: lib.optionalAttrs (secret.restartUnits != []) {
      systemd.services."netsecrets-restart-${name}" = {
        description = "Restart services for secret ${name}";
        wantedBy = ["netsecrets-fetch-${name}.service"];
        script = lib.concatMapStrings (unit: "systemctl try-restart ${unit}\n") secret.restartUnits;
        serviceConfig = {
          Type = "oneshot";
          User = "root";
        };
      };
    }) cfg.secrets)
  ]);
}
