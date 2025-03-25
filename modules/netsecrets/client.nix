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
      client = lib.mkOption {
        type = lib.types.submodule {
          options = {
            enable = lib.mkOption {
              description = "Whether to enable the netsecrets client.";
              type = lib.types.bool;
              default = false;
            };
            ip = lib.mkOption {
              description = "IP address for requesting secrets.";
              type = lib.types.str;
              default = "";
            };
            port = lib.mkOption {
              description = "Port for requesting secrets.";
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

      secrets = lib.mkOption {
        type = lib.types.submodule {
          options = {
            name = lib.mkOption {
              type = lib.types.str;
              default = config._module.args.name;
              description = ''
                Name of the file used in /var/lib/netsecrets
              '';
            };
            restartUnits = lib.mkOption {
              type = lib.types.listOf lib.types.str;
              default = [];
              example = ["apparmor.service"];
              description = ''
                Names of units to be restarted upon activation of secret.
              '';
            };
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    inherit (cfg) secrets;

    services = {
      netsecrets-client = {
        description = "NetSecrets Client";
        wantedBy = ["multi-user.target"];
        after = ["network-online.target"];
        wants = ["network-online.target"];
        serviceConfig = {
          ExecStart = netsecrets.send;
          Restart = "always";
          User = "root";
        };
      };
    };
  };
}
