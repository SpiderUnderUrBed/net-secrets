{
  config,
  options,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.netsecrets;
  netsecrets = pkgs.callPackage ../pkgs/netsecrets.nix {};

  sendServices = lib.mapAttrs' (name: req:
    let
      sendScript = pkgs.writeShellScript ("netsecrets-send-" + name) ''
        echo "Sending secrets for ${name}..."
        command="${netsecrets}/bin/netsecrets send"
        ${if req.ip != "" then "command=\"$command --ip " + req.ip + "\"" else ""}
        ${if req.port != "" then "command=\"$command --port " + req.port + "\"" else ""}
        ${if req.password != "" then "command=\"$command --password " + req.password + "\"" else ""}
        ${if req.request_secret != "" then "command=\"$command --request_secret " + req.request_secret + "\"" else ""}
        ${if req.verbose == true then "command=\"$command --verbose\"" else ""}
        echo "$command"
        $command
      '';
    in {
      serviceName = "netsecrets-sender-" + name;
      execStart = sendScript;
    }
  ) cfg.requesting;

  receiveServices = lib.mapAttrs' (name: auth:
    let
      receiveScript = pkgs.writeShellScript ("netsecrets-receive-" + name) ''
        echo "Receiving secrets for ${name}..."
        command="${netsecrets}/bin/netsecrets recive"
        ${if auth.ipOrRange != "" then "command=\"$command --authorized_ips " + auth.ipOrRange + "\"" else ""}
        ${if (lib.hasAttr "server" auth) && auth.server != "" then "command=\"$command --server " + auth.server + "\"" else ""}
        ${if auth.password != "" then "command=\"$command --password " + auth.password + "\"" else ""}
        ${if auth.port != "" then "command=\"$command --port " + auth.port + "\"" else ""}
        ${if auth.secrets != [] then "command=\"$command --secrets " + lib.concatStringsSep " " auth.secrets + "\"" else ""}
        ${if auth.verbose == true then "command=\"$command --verbose\"" else ""}
        echo "$command"
        $command
      '';
    in {
      serviceName = "netsecrets-receiver-" + name;
      execStart = receiveScript;
    }
  ) cfg.authorize;

  sendSystemdServices = lib.attrsets.fromList (map (v: {
    name = v.serviceName;
    serviceConfig = {
      Description = "NetSecrets Sender Service for " + v.serviceName;
      WantedBy = [ "multi-user.target" ];
      ExecStart = v.execStart;
      Restart = "always";
      User = "root";
    };
  }) (attrValues sendServices));

  receiveSystemdServices = lib.attrsets.fromList (map (v: {
    name = v.serviceName;
    serviceConfig = {
      Description = "NetSecrets Receiver Service for " + v.serviceName;
      WantedBy = [ "multi-user.target" ];
      ExecStart = v.execStart;
      Restart = "always";
      User = "root";
    };
  }) (attrValues receiveServices));

  allServices = sendSystemdServices // receiveSystemdServices;

in {
  options = {
    netsecrets = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable the secrets platform.";
      };
      requesting = mkOption {
        description = "Configuration for requesting secrets";
        default = {};
        type = with types; attrsOf (submodule ({ lib, ... }: {
          options = {
            ip = mkOption {
              default = "";
              description = "The IP to request from.";
              type = types.str;
            };
            port = mkOption {
              default = "";
              description = "The port to request from.";
              type = types.str;
            };
            priority = mkOption {
              default = 0;
              description = "Priority.";
              type = types.int;
            };
            authenticate = mkOption {
              default = "password";
              description = "Authentication method.";
              type = types.str;
            };
            password = mkOption {
              default = "";
              description = "Password for authentication.";
              type = types.str;
            };
            request_secret = mkOption {
              default = "";
              description = "Name of the secret to request.";
              type = types.str;
            };
            verbose = mkOption {
              type = types.bool;
              default = false;
              description = "Enable verbose output.";
            };
            secrets = mkOption {
              type = types.listOf types.any;
              default = [];
              description = "Names of secrets to send.";
            };
          };
        }));
      };
      authorize = mkOption {
        description = "Configuration for authorizing secrets";
        default = {};
        type = with types; attrsOf (submodule ({ lib, ... }: {
          options = {
            ipOrRange = mkOption {
              default = "";
              description = "IP or range to authorize.";
              type = types.str;
            };
            server = mkOption {
              default = "";
              description = "Server for authorization.";
              type = types.str;
            };
            authenticate = mkOption {
              default = "password";
              description = "Authentication method.";
              type = types.str;
            };
            password = mkOption {
              default = "";
              description = "Password for authentication.";
              type = types.str;
            };
            signSelf = mkOption {
              default = false;
              description = "Sign self.";
              type = types.bool;
            };
            secrets = mkOption {
              type = types.listOf types.any;
              default = [];
              description = "Names of secrets to receive.";
            };
            verbose = mkOption {
              type = types.bool;
              default = false;
              description = "Enable verbose output.";
            };
          };
        }));
      };
    };

    secrets = mkOption {
      type = types.attrsOf (types.submodule ({ lib, ... }: {
        options = {
          file = mkOption {
            type = types.str;
            description = "File path of the secret.";
          };
        };
      }));
      default = {};
      description = "Mapping of secret names to file paths.";
    };
  };

  config = mkMerge [
    {
      systemd.tmpfiles.rules = [
        "d /var/lib/netsecrets 0700 root root -"
      ];
    }
    {
      systemd.services = allServices;
    }
    (mkIf cfg.enable {
      secrets = builtins.mapAttrs (name: path: { file = path; }) (builtins.attrNames cfg.requesting);
    })
  ];
}
