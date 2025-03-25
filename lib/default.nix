{pkgs, ...}: let
  netsecrets = pkgs.callPackage ../pkgs/netsecrets.nix {};
in {
  send = pkgs.writeShellScript "netsecrets-send" ''
    echo "Sending secrets..."
    command="${netsecrets}/bin/netsecrets send --file-output /var/lib/netsecrets/"
    $command
  '';

  receive = pkgs.writeShellScript "netsecrets-receive" ''
    echo "Receiving secrets..."
    cmd="${netsecrets}/bin/netsecrets receive"
    echo "$cmd"
    $cmd
  '';
}
