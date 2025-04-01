{ config, lib, pkgs, ... }:

let
  netsecrets = import ../lib/default.nix { inherit pkgs; };
in {
  options.netsecrets.client = {
    enable = lib.mkEnableOption "the netsecrets client";

    secretsFile = lib.mkOption {
      type = lib.types.path;
      default = "/etc/netsecrets/secrets.json";
      description = "Path to JSON file defining secrets to fetch";
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
  in lib.mkIf cfg.enable {
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
        ExecStart = "${pkgs.writeShellScript "netsecrets-start" ''
          set -e
          ${netsecrets.send} fetch-all \
            --config ${cfg.secretsFile} \
            --output-dir /var/lib/netsecrets
        ''}";
        Restart = "on-failure";
        User = "root";
        EnvironmentFile = "/etc/netsecrets/client.conf";
      };
    };

    systemd.services.netsecrets-restarter = {
      description = "Restart services affected by secret changes";
      wantedBy = ["netsecrets-client.service"];
      after = ["netsecrets-client.service"];
      serviceConfig = {
        Type = "oneshot";
        User = "root";
        ExecStart = "${pkgs.writeShellScript "netsecrets-restart" ''
          set -e
          if [ -f "${cfg.secretsFile}" ]; then
            ${pkgs.jq}/bin/jq -r 'to_entries[] | select(.value.restartUnits != null) | .value.restartUnits[]' \
              "${cfg.secretsFile}" | sort -u | while read unit; do
              systemctl try-restart "$unit" || true
            done
          fi
        ''}";
      };
    };
  };
}
