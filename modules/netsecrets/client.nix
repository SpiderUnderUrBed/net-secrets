{ config, lib, pkgs, ... }:

let
  netsecrets = pkgs.callPackage ../../pkgs/netsecrets.nix {};

  # Define your secrets here
  secretNames = [ "enableswarm" "enablek8s" ];
  
  # Build the secrets attribute set with file paths
  secretsFiles = lib.foldl' (acc: secret: 
    acc // { "${secret}" = "/var/lib/netsecrets/${secret}"; }
  ) {} secretNames;

in {
  options.netsecrets.client = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the secrets client";
    };

    server = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Server IP address for requesting secrets";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8081;
      description = "Server port for requesting secrets";
    };

    password = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = "Password for requesting secrets";
    };

    request_secrets = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = secretNames;  # Use our predefined secret names
      description = "List of secrets to request from server";
    };

    fallbacks = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [];
      description = "List of fallback servers";
    };

    verbose = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable verbose logging";
    };
  };

  options.secrets = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule {
      options.file = lib.mkOption {
        type = lib.types.path;
        description = "Path to the secret file";
      };
    });
    default = {};
    description = "Mapping of secret names to their file paths";
  };

  config = lib.mkIf config.netsecrets.client.enable {
    secrets = lib.mkOverride 0 secretsFiles;

    # Ensure secrets directory exists
    system.activationScripts.netsecrets-dir = ''
      mkdir -p /var/lib/netsecrets
      chmod 700 /var/lib/netsecrets
    '';

    # Set up tmpfiles for each secret
    systemd.tmpfiles.rules = 
      lib.mapAttrsToList (name: path: 
        "f ${path} 0600 root root -"
      ) secretsFiles;

    # Client service to fetch secrets
    systemd.services.netsecrets-client = {
      description = "NetSecrets Client";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = {
        ExecStart = let
          fetchCmd = secret: 
            "${netsecrets}/bin/netsecrets send " +
            "--server ${config.netsecrets.client.server} " +
            "--port ${toString config.netsecrets.client.port} " +
            (lib.optionalString (config.netsecrets.client.password != "") "--password ${lib.escapeShellArg config.netsecrets.client.password} ") +
            (lib.optionalString config.netsecrets.client.verbose "--verbose ") +
            "--request_secrets ${secret} " +
            "--file-output /var/lib/netsecrets/${secret} " +
            (lib.optionalString (config.netsecrets.client.fallbacks != []) "--fallbacks ${lib.concatStringsSep "," config.netsecrets.client.fallbacks}");
        in pkgs.writeShellScript "fetch-secrets" ''
          set -euo pipefail
          ${lib.concatStringsSep "\n" (map fetchCmd config.netsecrets.client.request_secrets)}
        '';
        Restart = "on-failure";
        User = "root";
      };
    };
  };
}
