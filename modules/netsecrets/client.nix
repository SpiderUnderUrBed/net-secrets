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
      type = lib.types.listOf lib.types.str;
      default = [];
      example = ["dockerswarm" "k8stoken"];
      description = "List of secret names to request from server";
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
    description = "Configuration for individual secrets";
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

    # Automatically create default secret configurations for requested secrets
    (lib.listToAttrs (map (name: lib.nameValuePair name {
      netsecrets.secrets.${name} = {
        file = "/var/lib/netsecrets/${name}";
        value = null;
        restartUnits = [];
      };
    }) cfg.requestedSecrets))

    # Create fetch services for all secrets (both requested and manually configured)
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
    }) config.netsecrets.secrets)
  ]);
}
