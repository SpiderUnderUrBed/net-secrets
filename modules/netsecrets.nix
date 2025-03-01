{ config, options, lib, pkgs, ... }:
with lib; let
  cfg = config.netsecrets;
  netsecrets = pkgs.callPackage ../pkgs/netsecrets.nix {};

  send = pkgs.writeShellScript "netsecrets-send" ''
    echo "Sending secrets..."
    command="${netsecrets}/bin/netsecrets send --file-output /var/lib/netsecrets/"
    ${if cfg.requesting.server != "" then "command=\"$command --server " + cfg.requesting.server + "\"" else ""}
    ${if cfg.requesting.port != "" then "command=\"$command --port " + cfg.requesting.port + "\"" else ""}
    ${if cfg.requesting.password != "" then "command=\"$command --password " + cfg.requesting.password + "\"" else ""}
    ${if cfg.requesting.request_secrets != "" then "command=\"$command --request_secrets " + cfg.requesting.request_secrets + "\"" else ""}
    #${if cfg.authorize.secrets != [] then "command=\"$command --secrets " + lib.concatStringsSep " " (builtins.attrNames cfg.authorize.secrets) + "\"" else ""}
    ${if cfg.requesting.verbose then "command=\"$command --verbose\"" else ""}
    $command

  '';
receive = pkgs.writeShellScript "netsecrets-receive" ''
  echo "Receiving secrets..."

  # Prepare the command to receive secrets
  command="${netsecrets}/bin/netsecrets receive"
  ${if cfg.authorize.ipOrRange != "" then "command=\"$command --authorized-ips " + cfg.authorize.ipOrRange + "\"" else ""}
  ${if cfg.authorize.server != "" then "command=\"$command --server " + cfg.authorize.server + "\"" else ""}
  ${if cfg.authorize.password != "" then "command=\"$command --password " + cfg.authorize.password + "\"" else ""}
  ${if cfg.authorize.port != "" then "command=\"$command --port " + cfg.authorize.port + "\"" else ""}
  ${if cfg.authorize.secrets != {} then "command=\"$command --secrets " + lib.concatStringsSep "," (map (n: n + "=" + cfg.authorize.secrets.${n}) (builtins.attrNames cfg.authorize.secrets)) + "\"" else ""}
  ${if cfg.authorize.verbose then "command=\"$command --verbose\"" else ""}
  $command
'';



  secretsFiles = builtins.mapAttrs
    (name: _value: "/var/lib/netsecrets/" + name)
    cfg.authorize.secrets;

in {
  options = {
    netsecrets = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable the secrets platform.";
      };

      requesting = {
        server = mkOption {
          description = "IP address for requesting secrets.";
          type = types.str;
          default = "";
        };
        port = mkOption {
          description = "Port for requesting secrets.";
          type = types.str;
          default = "";
        };
        priority = mkOption {
          description = "Priority for requesting secrets.";
          type = types.int;
          default = 0;
        };
        authenticate = mkOption {
          description = "Authentication method for requesting secrets.";
          type = types.str;
          default = "password";
        };
        password = mkOption {
          description = "Password for requesting secrets.";
          type = types.str;
          default = "";
        };
        signSelf = mkOption {
          description = "Whether to sign the request to the server.";
          type = types.bool;
          default = false;
        };
        # request_secret = mkOption {
        #   description = "Secrets to request";
        #   type = types.str;
        #   default = false;
        # };
        # secrets = mkOption {
        #   description = "Mapping of secret names to file paths.";
        #   type = types.attrsOf types.str;
        #   default = {};
        # };
        request_secrets = mkOption {
          description = "Secret to request specifically.";
          type = types.str;
          default = "";
        };
        verbose = mkOption {
          description = "Enable verbose logging for requesting secrets.";
          type = types.bool;
          default = false;
        };
      };

      authorize = {
        ipOrRange = mkOption {
          description = "IP or range authorized to request secrets.";
          type = types.str;
          default = "";
        };
        server = mkOption {
          description = "Server address for authorizing secrets.";
          type = types.str;
          default = "";
        };
        authenticate = mkOption {
          description = "Authentication method for authorizing secrets.";
          type = types.str;
          default = "password";
        };
        password = mkOption {
          description = "Password for authorizing secrets.";
          type = types.str;
          default = "";
        };
        signSelf = mkOption {
          description = "Whether to sign the authorization.";
          type = types.bool;
          default = false;
        };
        secrets = mkOption {
          description = "Mapping of secret names to file paths.";
          type = types.attrsOf types.str;
          default = {};
        };
        port = mkOption {
          description = "Port for authorizing secrets.";
          type = types.str;
          default = "";
        };
        verbose = mkOption {
          description = "Enable verbose logging for authorizing secrets.";
          type = types.bool;
          default = false;
        };
      };
    };

    secrets = mkOption {
      description = "Mapping of secret names to file attribute sets (each with a file attribute).";
      type = types.attrsOf (types.attrsOf types.str);
      default = {};
    };
  };

  config = mkMerge [
    {
      systemd.tmpfiles.rules = [
        "d /var/lib/netsecrets 0700 root root -"
      ] ++ (mapAttrsToList (name: attr:
        "f ${attr} 0600 root root -") secretsFiles);
    }
    {
      system.activationScripts.netsecrets-sender = {
        text = send;
        deps = [];
      };
      system.activationScripts.netsecrets-receiver = {
        text = receive;
        deps = [];
      };
    }
    (mkIf cfg.enable {
      secrets = builtins.mapAttrs (name: path: { file = path; }) secretsFiles;
    })
  ];
}
