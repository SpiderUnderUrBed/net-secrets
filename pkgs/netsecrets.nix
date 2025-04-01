{ lib
, stdenv
, rustPlatform
}:

rustPlatform.buildRustPackage {
  pname = "netsecrets";
  version = "0.0.1";
  src = ./.;
  cargoLock = {
    lockFile = ./netsecrets/Cargo.lock;
  };
}
