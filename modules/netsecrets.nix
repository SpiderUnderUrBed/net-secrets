{
  config,
  options,
  lib,
  pkgs,
  ...
}:
with lib; let
  cfg = config.netsecrets;
  users = config.users.users;
  netsecrets = pkgs.callPackage ../pkgs/netsecrets.nix {};
  finalRequesting = lib.mapAttrs
    (name: attr: attr // { file = "/var/lib/netsecrets/" + name; })
    config.netsecrets.requesting;

  tmpfileRules = concatMapStringsSep "\n" (name: attr:
    "f ${attr.file} 0600 root root -") (attrValues finalRequesting);

  send = pkgs.writeShellScript "netsecrets-send" ''
    echo "Sending secrets..."

    command="${netsecrets}/bin/netsecrets send"

    if [ -n "${cfg.requesting.ip or ""}" ]; then
      command="$command --ip ${cfg.requesting.ip or ""}"
    fi

    if [ -n "${cfg.requesting.port or ""}" ]; then
      command="$command --port ${cfg.requesting.port or ""}"
    fi

    if [ -n "${cfg.requesting.password or ""}" ]; then
      command="$command --password ${cfg.requesting.password or ""}"
    fi

    if [ -n "${cfg.requesting.request_secret or ""}" ]; then
      command="$command --request_secret ${cfg.requesting.request_secret or ""}"
    fi

    if [ "${cfg.requesting.verbose or ""}" = true ]; then
      command="$command --verbose"
    fi

    $command
  '';

  receive = pkgs.writeShellScript "netsecrets-receive" ''
    echo "Receiving secrets..."

    command="${netsecrets}/bin/netsecrets recive"

    if [ -n "${cfg.authorize.ipOrRange or ""}" ]; then
      command="$command --authorized_ips ${cfg.authorize.ipOrRange or ""}"
    fi

    if [ -n "${cfg.authorize.server or ""}" ]; then
      command="$command --server ${cfg.authorize.server or ""}"
    fi

    if [ -n "${cfg.authorize.password or ""}" ]; then
      command="$command --password ${cfg.authorize.password or ""}"
    fi

    if [ -n "${cfg.authorize.port or ""}" ]; then
      command="$command --port ${cfg.authorize.port or ""}"
    fi

    if [ -n "${cfg.authorize.secrets or ""}" ]; then
      command="$command --secrets ${lib.concatStringsSep " " cfg.authorize.secrets or [""]}"
    fi

    if [ "${cfg.authorize.verbose or "false"}" = true ]; then
      command="$command --verbose"
    fi

    $command
  '';

  secretsFiles = builtins.mapAttrs
    (name: _value: "/var/lib/netsecrets/" + name)
    cfg.requesting;
in
{
  options = {
    netsecrets = {
      enable = mkOption {
        type = types.bool;
        default = false;
        description = "Enable the secrets platform.";
      };
      requesting = mkOption {
        description = "The place to request the secrets from";
        default = {};
        type = with types; attrsOf (submodule ({ lib, ... }: {
          options = {
            ip = mkOption {
              default = "";
              description = "The IP to request from";
              type = types.str;
            };
            port = mkOption {
              default = "";
              description = "The port to request from";
              type = types.str;
            };
            priority = mkOption {
              default = 0;
              description = "The priority";
              type = types.int;
            };
            authenticate = mkOption {
              default = "password";
              description = "The method of authentication";
              type = types.str;
            };
            password = mkOption {
              default = "";
              description = "The password to authenticate with";
              type = types.str;
            };
            signSelf = mkOption {
              default = false;
              description = "Whether or not to be signed from the remote machine to request secrets from other machines";
              type = types.bool;
            };
            secrets = mkOption {
              type = types.listOf types.any;
              default = [];
              description = "Names of the secrets to send";
            };
          };
        }));
      };
      authorize = mkOption {
        description = "The place to authorize machines to get secrets";
        default = {};
        type = with types; attrsOf (submodule ({ lib, ... }: {
          options = {
            ipOrRange = mkOption {
              default = "";
              description = "The IP or range to request from";
              type = types.str;
            };
            authenticate = mkOption {
              default = "password";
              description = "The method of authentication";
              type = types.str;
            };
            password = mkOption {
              default = "";
              description = "The password to authenticate with";
              type = types.str;
            };
            signSelf = mkOption {
              default = false;
              description = "Whether or not it will sign the machine requesting the secrets";
              type = types.bool;
            };
            secrets = mkOption {
              type = types.listOf types.any;
              default = [];
              description = "Names of the secrets to receive";
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
            description = "The file path of the secret.";
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
      ] ++ (mapAttrsToList (name: attr:
        "f ${attr.file} 0600 root root -") finalRequesting);
    }
    {
      systemd.services.netsecrets-sender = {
        description = "NetSecrets Sender";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = send;
          Restart = "always";
          User = "root";
        };
      };

      systemd.services.netsecrets-receiver = {
        description = "NetSecrets Receiver";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          ExecStart = receive;
          Restart = "always";
          User = "root";
        };
      };
    }

    (mkIf cfg.enable {
      secrets = builtins.mapAttrs (name: path: { file = path; }) secretsFiles;
    })
  ];
}
