{ config, lib, pkgs, ... }:

let
  netsecrets = pkgs.callPackage ../../pkgs/netsecrets.nix {};

  buildNetsecretsCommand = secret: s: let
    cfg = s.netsecrets.client;
  in
    "${netsecrets}/bin/netsecrets send " +
    "--server ${cfg.server} " +
    "--port ${toString cfg.port} " +
    (lib.optionalString (cfg.password != "") "--password ${lib.escapeShellArg cfg.password} ") +
    (lib.optionalString cfg.verbose "--verbose ") +
    "--request_secrets ${secret} " +
    "--file-output /var/lib/netsecrets/${secret} " +
    (lib.optionalString (cfg.fallbacks != [])
      "--fallbacks ${lib.concatStringsSep "," cfg.fallbacks}");

in {

  options.netsecrets.client = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the secrets client";
    };

    enableInitrd = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable fetching secrets during initrd boot (initrd systemd service)";
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

    systemdOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      description = ''
        Additional systemd service options for the netsecrets-client systemd unit.
      '';
    };

    systemdInitrdOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      description = ''
        Additional systemd service options for the netsecrets-client initrd systemd unit.
      '';
    };
  };

  options.secrets = lib.mkOption {
    type = lib.types.attrsOf (lib.types.attrs);
    default = {};
    description = "Mapping of secret names to their file paths.";
  };

  config = lib.mkIf config.netsecrets.client.enable (let
    secretsFiles = lib.foldl' (acc: secret:
      acc // { "${secret}" = "/var/lib/netsecrets/${secret}"; }
    ) {} config.netsecrets.client.request_secrets;

  in lib.mkMerge [
    {
      assertions = [
        {
          assertion = config.netsecrets.client.server != "";
          message = "netsecrets.client.server must be set";
        }
      ];

      secrets = lib.mkOverride 0 (lib.mapAttrs (name: path: { file = path; }) secretsFiles);

      # Ensure secrets directory exists for normal boot
      system.activationScripts.netsecrets-dir = ''
        mkdir -p /var/lib/netsecrets
        chmod 700 /var/lib/netsecrets
      '';

      # Normal boot tmpfiles rules (create empty secret files with correct permissions)
      systemd.tmpfiles.rules =
        lib.mapAttrsToList (name: path:
          "f ${path} 0600 root root -"
        ) secretsFiles;

      # Normal boot systemd service to fetch secrets
      systemd.services.netsecrets-client = {
        description = "NetSecrets Client";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = lib.mkMerge [
          {
            ExecStart = pkgs.writeShellScript "fetch-secrets" ''
              set -euo pipefail
              ${lib.concatStringsSep "\n" (map (secret: buildNetsecretsCommand secret config) config.netsecrets.client.request_secrets)}
            '';
            Restart = "on-failure";
            User = "root";
          }
          config.netsecrets.client.systemdOverrides
        ];
      };
    }
    (lib.mkIf config.netsecrets.client.enableInitrd {
      boot.initrd.secrets = lib.mapAttrs (name: path: pkgs.path) secretsFiles;

      # Initrd systemd service to fetch secrets early
      boot.initrd.systemd.services.netsecrets-client = {
        description = "NetSecrets Client (initrd)";
        wantedBy = [ "initrd-root-fs.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = lib.mkMerge [
          {
            ExecStartPre = ''
              mkdir -p /var/lib/netsecrets
              chmod 700 /var/lib/netsecrets
            '';
            ExecStart = pkgs.writeShellScript "fetch-secrets-initrd" ''
              set -euo pipefail
              ${lib.concatStringsSep "\n" (map (secret: buildNetsecretsCommand secret config) config.netsecrets.client.request_secrets)}
            '';
            Restart = "on-failure";
            User = "root";
          }
          config.netsecrets.client.systemdInitrdOverrides
        ];
      };

      # Initrd systemd service to copy secrets into real root after rootfs is mounted
      boot.initrd.systemd.services.netsecrets-copy = {
        description = "Copy netsecrets from initrd to real root";
        wantedBy = [ "initrd-root-fs.target" ];
        after = [ "initrd-root-fs.target" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStartPre = "mkdir -p /run/secrets";
          ExecStart = ''
            cp -a /var/lib/netsecrets/* /run/secrets/
            chmod 600 /run/secrets/*
          '';
        };
      };
    })
  ]);
}
