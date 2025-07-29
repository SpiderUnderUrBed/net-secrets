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

    system.activationScripts.netsecrets-dir = ''
      mkdir -p /var/lib/netsecrets
      chmod 700 /var/lib/netsecrets
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
    system.initrd.activationScripts.netsecrets-dir = ''
      mkdir -p /var/lib/netsecrets
      chmod 700 /var/lib/netsecrets
    '';

    system.initrd.tmpfiles.rules =
      lib.mapAttrsToList (name: path:
        "f ${path} 0600 root root -"
      ) secretsFiles;

    system.initrd.systemd.services.netsecrets-client = {
      description = "NetSecrets Client (initrd)";
      wantedBy = [ "initrd-root-fs.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      serviceConfig = lib.mkMerge [
        {
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
  })
]);
