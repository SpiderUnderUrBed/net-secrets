{
  config,
  lib,
  pkgs,
  ...
}: let
  cfg = config.netsecrets;
  # Nixpkgs library with this flakes added functions
  lib = lib // (import ../lib/default.nix {inherit pkgs;});
in {
  options = {
    netsecrets = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Enable the secrets platform.";
      };

      # NOTE: This is option would be used by the server.
      #       You can declare the client as a local IP
      #       in order to request secrets stored locally.
      client = lib.mkOption {
        type = lib.types.submodule {
          options = {
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

      server = lib.mkOption {
        type = lib.types.submodule {
          options = {
            ip = lib.mkOption {
              description = "Server address for authorizing secrets.";
              type = lib.types.str;
              default = "";
            };
            port = lib.mkOption {
              description = "Port for authorizing secrets.";
              type = lib.types.port;
              default = "";
            };
            secrets = lib.mkOption {
              description = "Mapping of secret names to file paths.";
              type = lib.types.attrsOf lib.types.secrets;
              default = {};
            };
            verbose = lib.mkOption {
              description = "Enable verbose logging for authorizing secrets.";
              type = lib.types.bool;
              default = false;
            };
          };
        };
      };
    };

    secrets = lib.mkOption {
      type = lib.types.submodule (
        {config, ...}: {
          config = {
            secrets = lib.mkOptionDefault cfg.defaultSopsFile;
            sopsFileHash = lib.mkOptionDefault (
              lib.optionalString cfg.validateSopsFiles "${builtins.hashFile "sha256" config.sopsFile}"
            );
          };
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
        }
      );
    };
  };

  config = lib.mkIf cfg.enable {
    systemd = {
      tmpfiles.rules =
        [
          "d /var/lib/netsecrets 0700 root root -"
        ]
        ++ (lib.mapAttrsToList (name: attr: "f ${attr} 0600 root root -") cfg.secrets);
      services = {
        netsecrets-client = {
          description = "NetSecrets Client";
          wantedBy = ["multi-user.target"];
          after = ["network-online.target"];
          wants = ["network-online.target"];
          serviceConfig = {
            ExecStart = lib.send;
            Restart = "always";
            User = "root";
          };
        };
        netsecrets-daemon = {
          description = "NetSecrets Daemon";
          wantedBy = ["multi-user.target"];
          after = ["network-online.target"];
          wants = ["network-online.target"];
          serviceConfig = {
            ExecStart = lib.receive;
            Restart = "always";
            User = "root";
          };
        };
        secrets = builtins.mapAttrs (name: path:
          {
            file = path;
            value = lib.mkDefault (builtins.readFile path);
          }
          cfg.secrets);
      };
    };
  };
}
