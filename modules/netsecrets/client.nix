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
    outputFile = "/var/lib/netsecrets/${secret}";
  in
    ''
      # First ensure the parent directory exists
      mkdir -p "$(dirname ${outputFile})"
      chmod 700 "$(dirname ${outputFile})"
      
      # Then execute the command with direct file output
      ${netsecrets}/bin/netsecrets send \
        --server ${lib.escapeShellArg cfg.server} \
        --port ${toString cfg.port} \
        ${lib.optionalString (cfg.password != "") "--password ${lib.escapeShellArg cfg.password}"} \
        ${lib.optionalString cfg.verbose "--verbose"} \
        --request_secrets ${lib.escapeShellArg secret} \
        --file-output ${lib.escapeShellArg outputFile} \
        ${lib.optionalString (cfg.fallbacks != []) "--fallbacks ${lib.escapeShellArg (lib.concatStringsSep "," cfg.fallbacks)}"}
    '';

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

  config = lib.mkIf config.netsecrets.client.enable {
    assertions = [
      {
        assertion = config.netsecrets.client.server != "";
        message = "netsecrets.client.server must be set";
      }
    ];

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
          # Ensure base directory exists with correct permissions
          mkdir -p /var/lib/netsecrets
          chmod 700 /var/lib/netsecrets
          
          # Fetch each secret
          ${lib.concatStringsSep "\n" (map buildNetsecretsCommand config.netsecrets.client.request_secrets)}
        '';
        Restart = "on-failure";
        User = "root";
      };
    };
  };
}
