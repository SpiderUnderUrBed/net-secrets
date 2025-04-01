{ config, lib, pkgs, ... }:

let
  cfg = config.netsecrets.client;
  netsecrets = import ../lib/default.nix { inherit pkgs; };

  secretType = lib.types.submodule {
    options = {
      file = lib.mkOption {
        type = lib.types.path;
        description = "Path where the secret will be stored";
      };
      value = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "The secret value";
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

    requestedSecrets = lib.mkOption {
      type = lib.types.listOf (lib.types.submodule {
        options = {
          name = lib.mkOption {
            type = lib.types.str;
            description = "Name of the secret to request";
          };
          file = lib.mkOption {
            type = lib.types.path;
            default = "/var/lib/netsecrets/secret";
            description = "Path where the secret will be stored";
          };
          restartUnits = lib.mkOption {
            type = lib.types.listOf lib.types.str;
            default = [];
            description = "Units to restart when this secret changes";
          };
        };
      });
      default = [];
      description = "List of secrets to request from server";
    };

    ip = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "IP address for requesting secrets";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Port for requesting secrets";
    };

    verbose = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable verbose logging";
    };
  };

  options.netsecrets.secrets = lib.mkOption {
    type = lib.types.attrsOf secretType;
    default = {};
    description = "Configuration for manually managed secrets";
  };

  config = lib.mkIf cfg.enable (lib.mkMerge [
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

    # Services for requested secrets
    (lib.mkMerge (map (secret: {
      systemd.services."netsecrets-fetch-${secret.name}" = {
        description = "Fetch secret ${secret.name}";
        script = ''
          ${netsecrets.send} get ${secret.name} > ${secret.file}
          chmod 600 ${secret.file}
        '';
        serviceConfig = {
          Type = "oneshot";
          User = "root";
        };
      };
      
    } // lib.optionalAttrs (secret.restartUnits != []) {
      systemd.services."netsecrets-restart-${secret.name}" = {
        description = "Restart services for secret ${secret.name}";
        wantedBy = ["netsecrets-fetch-${secret.name}.service"];
        script = lib.concatMapStrings (unit: "systemctl try-restart ${unit}\n") secret.restartUnits;
        serviceConfig = {
          Type = "oneshot";
          User = "root";
        };
      };
    }) cfg.requestedSecrets))

    # Services for manually configured secrets
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
    }) config.netsecrets.secrets)

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
    }) config.netsecrets.secrets)
  ]);
}
