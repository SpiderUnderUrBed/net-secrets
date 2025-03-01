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
    ${if cfg.requesting.request_secrets != [] then "command=\"$command --request_secrets " + (lib.concatStringsSep "," cfg.requesting.request_secrets) + "\"" else ""}
    ${if cfg.requesting.verbose then "command=\"$command --verbose\"" else ""}
    $command
  '';
  
receive = pkgs.writeShellScript "netsecrets-receive" ''
  echo "Receiving secrets..."

  # Initialize the command
  cmd="${netsecrets}/bin/netsecrets receive"
  
  # Append to the command based on conditions
  ${if cfg.authorize.ipOrRange != "" then "cmd=\"$cmd --authorized-ips ${cfg.authorize.ipOrRange}\"\n" else ""}
  ${if cfg.authorize.server != "" then "cmd=\"$cmd --server ${cfg.authorize.server}\"\n" else ""}
  ${if cfg.authorize.password != "" then "cmd=\"$cmd --password ${cfg.authorize.password}\"\n" else ""}
  ${if cfg.authorize.port != "" then "cmd=\"$cmd --port ${cfg.authorize.port}\"\n" else ""}
  ${if cfg.authorize.verbose then "cmd=\"$cmd --verbose\"\n" else ""}
  
  # Output the final command and run it
  echo "$cmd"
  $cmd
'';


secretsFiles = lib.foldl' (acc: set: acc // set) {} [
  (builtins.mapAttrs (name: _value: "/var/lib/netsecrets/" + name) cfg.authorize.secrets)
  (builtins.listToAttrs (map (secret: { name = secret; value = "/var/lib/netsecrets/" + secret; }) cfg.requesting.request_secrets))
];


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
        request_secrets = mkOption {
          description = "Secrets to request specifically.";
          type = types.listOf types.str;
          default = [];
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

  systemd.services.netsecrets-sender = {
    description = "NetSecrets Sender";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = send;
      Restart = "always";
      User = "root";
    };
  };
  systemd.services.netsecrets-receiver = {
    description = "NetSecrets Receiver";
    wantedBy = [ "multi-user.target" ];
    after = [ "network-online.target" ];
    wants = [ "network-online.target" ];
    serviceConfig = {
      ExecStart = receive;
      Restart = "always";
      User = "root";
    };
  };

    }
    (mkIf cfg.enable {
      secrets = builtins.mapAttrs (name: path: {
        file = path;
        value = mkDefault (builtins.readFile path);
      }) secretsFiles;
    })
  ];
}
