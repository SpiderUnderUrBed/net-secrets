{ config, lib, pkgs, ... }:

let
  netsecrets = pkgs.callPackage ../../pkgs/netsecrets.nix {};

  buildNetsecretsCommand = secret: s: let
    cfg = s.netsecrets.client;
    passwordArg = if cfg.enableInitrdPassword then "--password-file /run/netsecrets-password"
                 else if cfg.password != "" then "--password ${lib.escapeShellArg cfg.password}"
                 else "";
  in
    "${netsecrets}/bin/netsecrets send " +
    "--server ${cfg.server} " +
    "--port ${toString cfg.port} " +
    passwordArg + " " +
    (lib.optionalString cfg.verbose "--verbose ") +
    "--request_secrets ${secret} " +
    "--file-output /var/lib/netsecrets/${secret} " +
    (lib.optionalString (cfg.fallbacks != [])
      "--fallbacks ${lib.concatStringsSep "," cfg.fallbacks}");

in

let
  fetchSecrets = pkgs.writeShellScript "fetch-secrets" ''
    ${pkgs.coreutils}/bin/set -euo pipefail
    ${lib.concatStringsSep "\n" (map (secret: buildNetsecretsCommand secret config) config.netsecrets.client.request_secrets)}
  '';
in

{
  options.netsecrets.client = {
    enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable the secrets client";
    };

    enableInitrd = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Enable fetching secrets during initrd boot";
    };

    enableInitrdPassword = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Prompt for password during initrd and pass to services";
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
      description = "Additional systemd service options for the netsecrets-client systemd unit.";
    };

    systemdInitrdOverrides = lib.mkOption {
      type = lib.types.attrsOf lib.types.anything;
      default = {};
      description = "Additional systemd service options for the netsecrets-client initrd systemd unit.";
    };
  };

  config = lib.mkIf config.netsecrets.client.enable (let
    secretsFiles = lib.foldl' (acc: secret:
      acc // { "${secret}" = "/var/lib/netsecrets/${secret}"; }
    ) {} config.netsecrets.client.request_secrets;

    passwordPromptService = {
      description = "Prompt for netsecrets password during initrd";
      requiredBy = [ "initrd.target" ];
      before = [ "initrd.target" ];
      serviceConfig = {
        Type = "oneshot";
        StandardOutput = "tty";
        StandardError = "tty";
        TTYPath = "/dev/console";
        ExecStart = pkgs.writeShellScript "ask-password" ''
          PASSWORD=$(${pkgs.systemd}/bin/systemd-ask-password --timeout=0 "Enter netsecrets server password:")
          echo "netsecrets-password" > /proc/self/attr/current
          echo "$PASSWORD" > /run/netsecrets-password
          chmod 600 /run/netsecrets-password
        '';
      };
    };

    passwordCopyService = {
      description = "Copy netsecrets password to real root";
      requiredBy = [ "initrd.target" ];
      after = [ "netsecrets-password.service" ];
      before = [ "initrd.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = ''
          ${pkgs.coreutils}/bin/mkdir -p /run/secrets
          ${pkgs.coreutils}/bin/cp -a /run/netsecrets-password /run/secrets/
        '';
      };
    };

  in lib.mkMerge [
    {
      assertions = [
        {
          assertion = config.netsecrets.client.server != "";
          message = "netsecrets.client.server must be set";
        }
        {
          assertion = !(config.netsecrets.client.enableInitrdPassword && config.netsecrets.client.password != "" && !config.netsecrets.client.enableInitrd);
          message = "Cannot use both password field and enableInitrdPassword for main service";
        }
      ];

      system.activationScripts.netsecrets-dir = ''
        ${pkgs.coreutils}/bin/mkdir -p /var/lib/netsecrets
        ${pkgs.coreutils}/bin/chmod 700 /var/lib/netsecrets
      '';

      systemd.tmpfiles.rules =
        lib.mapAttrsToList (name: path:
          "f ${path} 0600 root root -"
        ) secretsFiles;

      systemd.services.netsecrets-client = {
        description = "NetSecrets Client";
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = lib.mkMerge [
          {
            ExecStart = fetchSecrets;
            Restart = "on-failure";
            User = "root";
          }
          config.netsecrets.client.systemdOverrides
        ];
      };
    }

    # Initrd service (when enableInitrd is true)
    (lib.mkIf config.netsecrets.client.enableInitrd {
      boot.initrd.systemd.services.netsecrets-client = {
        description = "NetSecrets Client (initrd)";
        wantedBy = [ "initrd.target" ];
        after = [ "network-online.target" ] ++ 
               lib.optional config.netsecrets.client.enableInitrdPassword "netsecrets-password.service";
        wants = [ "network-online.target" ] ++
               lib.optional config.netsecrets.client.enableInitrdPassword "netsecrets-password.service";
        serviceConfig = lib.mkMerge [
          {
            ExecStartPre = ''
              ${pkgs.coreutils}/bin/mkdir -p /var/lib/netsecrets
              ${pkgs.coreutils}/bin/chmod 700 /var/lib/netsecrets
            '';
            ExecStart = fetchSecrets;
            Restart = "on-failure";
            User = "root";
          }
          config.netsecrets.client.systemdInitrdOverrides
        ];
      };
    })

    # Password prompt handling (when enableInitrdPassword is true)
    (lib.mkIf config.netsecrets.client.enableInitrdPassword (lib.mkMerge [
      {
        boot.initrd.systemd.services.netsecrets-password = passwordPromptService;
        boot.initrd.systemd.services.netsecrets-password-copy = passwordCopyService;
      }

      # Configure main service to use the password file
      {
        systemd.services.netsecrets-client.serviceConfig.Environment = [
          "NETSECRETS_PASSWORD_FILE=/run/secrets/netsecrets-password"
        ];
      }

      # Configure initrd service to use the password file if both are enabled
      (lib.mkIf config.netsecrets.client.enableInitrd {
        boot.initrd.systemd.services.netsecrets-client.serviceConfig.Environment = [
          "NETSECRETS_PASSWORD_FILE=/run/netsecrets-password"
        ];
      })
    ]))
  ]);
}
