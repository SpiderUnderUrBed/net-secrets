{ config, lib, pkgs, ... }:

let
  cfg = config.netsecrets.server;
  netsecrets = import ../../lib/default.nix { inherit pkgs; };
in
{
  options.netsecrets.server = {
    enable = lib.mkEnableOption "the netsecrets daemon";

    server = lib.mkOption {
      description = "IP address for netsecrets server";
      type = lib.types.str;
      default = "";
    };

    authorized_ips = lib.mkOption {
      description = "Comma-separated list of authorized client IPs";
      type = lib.types.listOf lib.types.str;
      default = [];
    };

    port = lib.mkOption {
      description = "Port for netsecrets server";
      type = lib.types.str;
      default = "8080";
    };

    password = lib.mkOption {
      description = "Password for clients to authenticate";
      type = lib.types.str;
      default = "";
    };

    password_file = lib.mkOption {
      description = "File containing password for clients to authenticate";
      type = lib.types.str;
      default = "";
    };

    secrets = lib.mkOption {
      description = "List of secrets the server will serve";
      type = lib.types.listOf lib.types.str;
      default = [];
    };

    verbose = lib.mkOption {
      description = "Enable verbose logging";
      type = lib.types.bool;
      default = false;
    };

    encryptionKey = lib.mkOption {
      description = "Optional encryption key for symmetric encryption";
      type = lib.types.str;
      default = "";
    };

    insecure = lib.mkOption {
      description = "Disable TLS verification or other security checks";
      type = lib.types.bool;
      default = false;
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
          ExecStart = lib.concatStringsSep " " [
            "${netsecrets.receive}"
            (lib.optionalString (cfg.server != "") "--server ${cfg.server}")
            (lib.optionalString (cfg.port != "") "--port ${cfg.port}")
            (lib.optionalString (cfg.password != "") "--password ${cfg.password}")
            (lib.optionalString (cfg.password_file != "") "--password-file ${cfg.password_file}")
            (lib.optionalString (cfg.secrets != []) "--request_secrets ${lib.concatStringsSep "," cfg.secrets}")
            (lib.optionalString (cfg.authorized_ips != []) "--authorized-ips ${lib.concatStringsSep "," cfg.authorized_ips}")
            (lib.optionalString cfg.verbose "--verbose")
            (lib.optionalString (cfg.encryptionKey != "") "--encryption-key ${cfg.encryptionKey}")
            (lib.optionalString cfg.insecure "--insecure")
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

    environment.etc."netsecrets/config.json".text = builtins.toJSON {
      server = cfg.server;
      port = cfg.port;
      password = cfg.password;
      password_file = cfg.password_file;
      secrets = cfg.secrets;
      authorized_ips = cfg.authorized_ips;
      verbose = cfg.verbose;
      encryptionKey = cfg.encryptionKey;
      insecure = cfg.insecure;
    };
  };
}
