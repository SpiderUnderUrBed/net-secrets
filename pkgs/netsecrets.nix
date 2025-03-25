{buildRustPackage}:
buildRustPackage {
  pname = "netsecrets";
  version = "0.0.1";
  src = ./netsecrets;
  cargoLock = {
    lockFile = ./netsecrets/Cargo.lock;
  };
}
