{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.sops;
  netsecrets = import ../lib/default.nix {inherit pkgs;};
in {
  options.netsecrets = {
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
        };
      };
    };

    environment = lib.mkOption {
      type = lib.types.attrsOf (lib.types.either lib.types.str lib.types.path);
      default = {};
      description = ''
        Environment variables to set before calling netsecrets.

        To properly quote strings with quotes use lib.escapeShellArg.
      '';
    };
  };

  config = lib.mkIf (cfg.secrets != {}) {
    netsecrets.environment = cfg.environment;

    systemd.user.services.netsecrets = {
      Unit.Description = "netsecrets user activation";
      Service = {
        Type = "oneshot";
        Environment = builtins.concatStringsSep " " (
          lib.mapAttrsToList (name: value: "'${name}=${value}'") cfg.environment
        );
        ExecStart = netsecrets.activate;
      };
      Install.WantedBy = ["network-online.target"];
    };
  };
}
