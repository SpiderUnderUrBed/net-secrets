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
      description = "Optional encryption key for secrets";
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
      serviceConfig = lib.mkMerge [
        {
          ExecStart = "${netsecrets.receive}" +
                      (if cfg.encryptionKey != "" then " --encryption-key ${lib.escapeShellArg cfg.encryptionKey}" else "");
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

    environment.etc."netsecrets/config.json".text = builtins.toJSON {
      ip = cfg.ip;
      port = cfg.port;
      verbose = cfg.verbose;
      encryptionKey = cfg.encryptionKey;
    };
  };
}
