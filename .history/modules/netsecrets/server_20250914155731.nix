{ config, lib, pkgs, ... }:

let
  cfg = config.netsecrets.server;
  netsecrets = import ../../lib/default.nix { inherit pkgs; };
in
{
  options.netsecrets.server = {
    enable = lib.mkEnableOption "the netsecrets daemon";

    ip = lib.mkOption {
      description = "IP address for netsecrets server";
      type = lib.types.str;
      default = "";
    };

    port = lib.mkOption {
      description = "Port for netsecrets server";
      type = lib.types.str;
      default = "8080";
    };

    verbose = lib.mkOption {
      description = "Enable verbose logging for requesting secrets";
      type = lib.types.bool;
      default = false;
    };

    encryptionKey = lib.mkOption {
      description = "Optional encryption key for symmetric encryption";
      type = lib.types.str;
      default = "";
    };

    systemdOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      description = ''
        Additional systemd service options for the netsecrets-daemon systemd unit.
        These will override or be merged with the default serviceConfig.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.netsecrets-daemon = {
      description = "NetSecrets Daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "mongodb.service" ];
      wants = [ "network-online.target" ];

      # Construct ExecStart with all options as CLI arguments
      serviceConfig = lib.mkMerge [
        {
          ExecStart = lib.concatStringsSep " " [
            "${netsecrets.receive}"
            (lib.optionalString (cfg.ip != "") "--server ${cfg.ip}")
            (lib.optionalString (cfg.port != "") "--port ${cfg.port}")
            (lib.optionalString cfg.verbose "--verbose")
            (lib.optionalString (cfg.encryptionKey != "") "--encryption-key ${cfg.encryptionKey}")
          ];
          Restart = "always";
          User = "root";
          RuntimeDirectory = "netsecrets";
        }
        cfg.systemdOverrides
      ];
    };

    users.users.netsecrets = {
      isSystemUser = true;
      group = "netsecrets";
    };

    users.groups.netsecrets = {};

    # Still write JSON for reference if needed
    environment.etc."netsecrets/config.json".text = builtins.toJSON {
      ip = cfg.ip;
      port = cfg.port;
      verbose = cfg.verbose;
      encryptionKey = cfg.encryptionKey;
    };
  };
}
