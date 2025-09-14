

  config = lib.mkIf config.netsecrets.client.enable (let
    secretsFiles = lib.foldl' (acc: secret:
      acc // { "${secret}" = { file = "/var/lib/netsecrets/${secret}"; }; }
    ) {} config.netsecrets.client.request_secrets;

    passwordPromptService = {
      description = "Prompt for netsecrets password during initrd";
      requiredBy = [ "initrd.target" ];
      before = [ "initrd.target" ];
      serviceConfig = {
        Type = "oneshot";
        StandardInput = "tty";
        StandardOutput = "tty";
        StandardError = "tty";
        TTYPath = "/dev/console";
        # Use direct command instead of script to avoid dependency issues
        ExecStart = [
          ""  # Clear any existing ExecStart
          "${pkgs.writeShellScript "ask-password-simple" ''
            #!/bin/sh
            PASSWORD=$(systemd-ask-password --timeout=0 "Enter netsecrets server password:")
            echo "$PASSWORD" > /run/netsecrets-password
            chmod 600 /run/netsecrets-password
          ''}"
        ];
      };
    };

    passwordCopyService = {
      description = "Copy netsecrets password to real root";
      requiredBy = [ "initrd.target" ];
      after = [ "netsecrets-password.service" ];
      before = [ "initrd.target" ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart = pkgs.writeShellScript "copy-password" ''
          set -euo pipefail
          ${pkgs.coreutils}/bin/mkdir -p /run/secrets
          if [ -f /run/netsecrets-password ]; then
            ${pkgs.coreutils}/bin/cp /run/netsecrets-password /run/secrets/
          fi
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

      secrets = secretsFiles;

      system.activationScripts.netsecrets-dir = ''
        ${pkgs.coreutils}/bin/mkdir -p /var/lib/netsecrets
        ${pkgs.coreutils}/bin/chmod 700 /var/lib/netsecrets
      '';

      systemd.tmpfiles.rules =
        lib.mapAttrsToList (name: secret:
          "f ${secret.file} 0600 root root -"
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

    (lib.mkIf config.netsecrets.client.enableInitrd {
      # Add required binaries to initrd
      boot.initrd.systemd.extraBin = {
        systemd-ask-password = "${pkgs.systemd}/bin/systemd-ask-password";
        mkdir = "${pkgs.coreutils}/bin/mkdir";
        chmod = "${pkgs.coreutils}/bin/chmod";
        echo = "${pkgs.coreutils}/bin/echo";
        cp = "${pkgs.coreutils}/bin/cp";
        sh = "${pkgs.bash}/bin/sh";
      };

      boot.initrd.systemd.services.netsecrets-client = {
        description = "NetSecrets Client (initrd)";
        wantedBy = [ "initrd.target" ];
        after = [ "network-online.target" ] ++ 
               lib.optional config.netsecrets.client.enableInitrdPassword "netsecrets-password.service";
        wants = [ "network-online.target" ] ++
               lib.optional config.netsecrets.client.enableInitrdPassword "netsecrets-password.service";
        serviceConfig = lib.mkMerge [
          {
            ExecStartPre = "/bin/sh -c 'mkdir -p /var/lib/netsecrets; chmod 700 /var/lib/netsecrets'";
            ExecStart = fetchSecrets;
            Restart = "on-failure";
            User = "root";
          }
          config.netsecrets.client.systemdInitrdOverrides
        ];
      };
    })

    (lib.mkIf config.netsecrets.client.enableInitrdPassword (lib.mkMerge [
      {
        # Add systemd-ask-password and basic tools to initrd
        boot.initrd.systemd.extraBin = {
          systemd-ask-password = "${pkgs.systemd}/bin/systemd-ask-password";
          sh = "${pkgs.bash}/bin/sh";
        };

        boot.initrd.systemd.services.netsecrets-password = {
          description = "Prompt for netsecrets password during initrd";
          requiredBy = [ "initrd.target" ];
          before = [ "initrd.target" ];
          serviceConfig = {
            Type = "oneshot";
            StandardInput = "tty";
            StandardOutput = "tty";
            StandardError = "tty";
            TTYPath = "/dev/console";
            ExecStart = [
              "/bin/sh -c 'PASSWORD=$(systemd-ask-password --timeout=0 \"Enter netsecrets server password:\"); echo \"$PASSWORD\" > /run/netsecrets-password; chmod 600 /run/netsecrets-password'"
            ];
          };
        };

        boot.initrd.systemd.services.netsecrets-password-copy = {
          description = "Copy netsecrets password to real root";
          requiredBy = [ "initrd.target" ];
          after = [ "netsecrets-password.service" ];
          before = [ "initrd.target" ];
          serviceConfig = {
            Type = "oneshot";
            ExecStart = [
              "/bin/sh -c 'mkdir -p /run/secrets; if [ -f /run/netsecrets-password ]; then cp /run/netsecrets-password /run/secrets/; fi'"
            ];
          };
        };
      }

      {
        systemd.services.netsecrets-client.serviceConfig.Environment = [
          "NETSECRETS_PASSWORD_FILE=/run/secrets/netsecrets-password"
        ];
      }

      (lib.mkIf config.netsecrets.client.enableInitrd {
        boot.initrd.systemd.services.netsecrets-client.serviceConfig.Environment = [
          "NETSECRETS_PASSWORD_FILE=/run/netsecrets-password"
        ];
      })
    ]))
  ]);
}
