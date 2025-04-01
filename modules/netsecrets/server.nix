{ config, lib, pkgs, ... }:

let
  cfg = config.netsecrets.server;
  netsecrets = import ../lib/default.nix { inherit pkgs; };
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
  };

  config = lib.mkIf cfg.enable {
    services.mongodb = {
      enable = true;
      dbpath = "/var/lib/netsecrets/db";
      pidFile = "/run/netsecrets/mongodb.pid";
      user = "netsecrets";
    };

    systemd.services.netsecrets-daemon = {
      description = "NetSecrets Daemon";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" "mongodb.service" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = "${netsecrets.receive}";
        Restart = "always";
        User = "root";
        RuntimeDirectory = "netsecrets";
      };
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
    };
  };
}
