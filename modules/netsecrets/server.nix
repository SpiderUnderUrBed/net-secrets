{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.netsecrets;
  netsecrets = import ../lib/default.nix {inherit pkgs;};
in {
  options = {
    netsecrets = {
      # NOTE: This is option would be used by the server.
      #       You can declare the client as a local IP
      #       in order to request secrets stored locally.
      server = lib.mkOption {
        type = lib.types.submodule {
          options = {
            enable = lib.mkOption {
              description = "Whether to enable the netsecrets daemon.";
              type = lib.types.bool;
              default = false;
            };
            ip = lib.mkOption {
              description = "IP address for netsecrets server.";
              type = lib.types.str;
              default = "";
            };
            port = lib.mkOption {
              description = "Port for netsecrets server.";
              type = lib.types.str;
              default = "";
            };
            verbose = lib.mkOption {
              description = "Enable verbose logging for requesting secrets.";
              type = lib.types.bool;
              default = false;
            };
          };
        };
      };
    };

    config = lib.mkIf cfg.enable {
      # nosql database for storing secrets
      services = {
        mongodb = {
          enable = true;
          dbpath = "/var/lib/netsecrets/db";
          pidFile = "/run/netsecrets/mongodb.pid";
          user = "netsecrets";
        };

        netsecrets-daemon = {
          description = "NetSecrets Daemon";
          wantedBy = ["multi-user.target"];
          after = ["network-online.target"];
          wants = ["network-online.target"];
          serviceConfig = {
            ExecStart = netsecrets.receive;
            Restart = "always";
            User = "root";
          };
        };
      };
    };
  };
}
