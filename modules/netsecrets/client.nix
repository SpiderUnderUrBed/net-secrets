{ config, lib, pkgs, ... }:

let
  netsecrets = pkgs.callPackage ../pkgs/netsecrets.nix {};

  # Build the secrets attribute set with file paths
  secretsFiles = lib.foldl' (acc: secret: 
    acc // { "${secret}" = "/var/lib/netsecrets/${secret}"; }
  ) {} config.netsecrets.client.request_secrets;

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
      type = lib.types.str;
      default = "";
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
    # Initialize secrets configuration
    secrets = lib.mapAttrs (name: path: {
      file = path;
    }) secretsFiles;

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
            "${netsecrets}/bin/netsecrets fetch ${secret} --output /var/lib/netsecrets/${secret}";
        in pkgs.writeShellScript "fetch-secrets" ''
          set -e
          ${lib.concatStringsSep "\n" (map fetchCmd config.netsecrets.client.request_secrets)}
        '';
        Restart = "on-failure";
        User = "root";
        Environment = [
          "NETSECRETS_SERVER=${config.netsecrets.client.server}"
          "NETSECRETS_PORT=${toString config.netsecrets.client.port}"
          ${lib.optionalString (config.netsecrets.client.password != "") 
            "NETSECRETS_PASSWORD=${config.netsecrets.client.password}"}
          ${lib.optionalString config.netsecrets.client.verbose 
            "NETSECRETS_VERBOSE=1"}
        ];
      };
    };
  };
}
