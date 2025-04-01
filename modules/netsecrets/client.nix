{ config, lib, pkgs, ... }:

let
  netsecrets = pkgs.callPackage ../../pkgs/netsecrets.nix {};

  # Build the secrets attribute set with file paths
  secretsFiles = lib.foldl' (acc: secret: 
    acc // { "${secret}" = "/var/lib/netsecrets/${secret}"; }
  ) {} config.netsecrets.client.request_secrets;

  # Helper function to build the netsecrets command with flags
  buildNetsecretsCommand = secret: let
    cfg = config.netsecrets.client;
  in
    "${netsecrets}/bin/netsecrets send " +
    "--server ${cfg.server} " +
    "--port ${toString cfg.port} " +
    (lib.optionalString (cfg.password != "") "--password ${lib.escapeShellArg cfg.password} ") +
    (lib.optionalString cfg.verbose "--verbose ") +
    "--request_secrets ${secret} " +
    "--file-output /var/lib/netsecrets/${secret} " +  # Fixed path - no double secret name
    (lib.optionalString (cfg.fallbacks != []) 
      "--fallbacks ${lib.concatStringsSep "," cfg.fallbacks}");

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
      default = [];
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
    type = lib.types.attrsOf (lib.types.attrs);
    default = {};
    description = "Mapping of secret names to their file paths.";
  };

  config = lib.mkIf config.netsecrets.client.enable {
    assertions = [
      {
        assertion = config.netsecrets.client.server != "";
        message = "netsecrets.client.server must be set";
      }
    ];

    secrets = lib.mkOverride 0 (lib.mapAttrs (name: path: { file = path; }) secretsFiles);

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
        ExecStart = pkgs.writeShellScript "fetch-secrets" ''
          set -euo pipefail
          ${lib.concatStringsSep "\n" (map buildNetsecretsCommand config.netsecrets.client.request_secrets)}
        '';
        Restart = "on-failure";
        User = "root";
      };
    };
  };
}
