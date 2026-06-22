
# Net-Secrets
This is a nixos secrets distribution system. One machine would hold the secrets in plaintext while the clients will request them over a TCP connection, which happens at boot time and write them over to `/var/lib/netsecrets/<name of the secret>`

## How it works
### Protocol
THe client will open a raw TCP connection where it will exchange framed messages.
```
Client -> Server
[4 bytes in big endian format][payload]

payload (before the encryption which is entirely optional but recommended)
"<password> <secret name>"

Server -> The client
[4 bytes big-endian length][payload]

payload (before encryption, optional as stated prior but recommended)
"secret value" or "Not found"
```
### Encryption
its controlled by `--encryption-key` and `--insecure`
flags:          behavior:
`--insecure`    plaintext with no encryption
`--encryption-key <input>` AES-256-GCM where the key is SHA-256 of the file
`--encryption-key-file` AES-256-GCM where the key is SHA-256 of the file, priority over the `--encryption-key` flag
neither         plaintext (like `--insecure`)

When the encryption is active the framed payload is 
a 12-byte random nonce, then ciphertext + a 16-byte GCM tag

where both sides are REQUIRED to use the same key otherwise it fails 

### Ip's allowlist
The server will accept an `--authorized-ips` list (in CIDR notation). If the connection is not from the source ip its dropped and will not read the request

### Fallback servers
The client WILL accept a fallback like `--fallbacks <ip1, ip2, etc>`. If the primary server is , it will try each fallback using the same exact port

## netsecrets commands
### `netsecrets receive` (the server mode)
This will bind a TCP listener and it will serve 
secrets from its map from memory

```
netsecrets receive \
  --server <ip>          # bind address (env: NETSECRETS_SERVER)
  --port <port>          # default 8080 (env: NETSECRETS_PORT)
  --password <pw>        # shared password (env: NETSECRETS_PASSWORD)
  --password-file <path> # read password from file instead
  -S key=value           # secret to serve; repeat for multiple
  -a <cidr,...>          # authorized client IPs (optional)
  --encryption-key <str>      # optional AES-256-GCM key
  --encryption-key-file <path> # read AES-256-GCM key from file
  --insecure             # disable encryption
  --verbose
```

### `netsecrets send` (the client mode)
```
netsecrets send \
  --server <ip>              # env: NETSECRETS_SERVER
  --port <port>              # default 8080; env: NETSECRETS_PORT
  --password <pw>            # env: NETSECRETS_PASSWORD
  --password-file <path>
  --request_secrets <names>  # space-separated; env: NETSECRETS_REQUEST_SECRETS
  --file-output <path>       # write result here instead of stdout
  --fallbacks <ip,...>         # env: NETSECRETS_FALLBACKS
  --encryption-key <str>
  --encryption-key-file <path> # takes priority over --encryption-key
  --insecure
  --verbose
```
When multiple secret names are given they are fetched sequentially. The resulting values are written once per line to `--file-output` or stdout.

The nixos module will call netsecrets send once per secret with its own file output set under /var/lib/netsecrets/<name>

## The nixos module
### Server
```
{
  netsecrets.server = {
    enable       = true;
    ip           = "10.0.0.1";
    port         = "8081";
    password     = "hunter2";          # or use password_file
    password_file = "";                # path to file containing password
    secrets      = [ "db-password" "api-key" ];
    authorized_ips = [ "10.0.0.0/24" ];
    encryptionKey     = "my-aes-key";     # optional; or use encryptionKeyFile
    encryptionKeyFile = "";                # path to file; takes priority over encryptionKey
    insecure          = false;
    verbose        = false;

    # merge extra systemd serviceConfig keys
    systemdOverrides = {};
  };
}
```
This will create ` netsecrets-daemon` systemd service which starts after network-online.target

a config file at /etc/netsecrets/config.json

a netsecrets systemd user and group (not used right now)

### Client
```
# in your client's configuration.nix:
{
  netsecrets.client = {
    enable          = true;
    server          = "10.0.0.1";
    port            = 8081;
    password        = "hunter2";
    encryptionKey     = "my-aes-key";     # must match server; or use encryptionKeyFile
    encryptionKeyFile = "/run/secrets/enc-key"; # takes priority over encryptionKey
    request_secrets = [ "db-password" "api-key" ];
    fallbacks       = [ "10.0.0.2" ];
    insecure        = false;
    verbose         = false;

    # initrd support (see below)
    enableInitrd          = false;
    enableInitrdPassword  = false;

    systemdOverrides      = {};
    systemdInitrdOverrides = {};
  };
}
```

this will create /var/lib/netsecrets (owned by root)
a tmpfile rule creating each secret (owned by root)

a `netsecrets-client` systemd service which will start after `network-online.target` which will call netsecrets-send once per secret and it will and it will write each thing to `/var/lib/netsecrets/<name>`

a `secrets.<name>.file` attribute which will poiubt at all the relevent secrets path (think of sops-nix)

## Using a secret
```
{
  # after the client module populates it:
  environment.etc."myapp/db.conf".source = config.secrets.db-password.file;
  # or just hardcode the path:
  systemd.services.myapp.serviceConfig.EnvironmentFile = "/var/lib/netsecrets/db-password";
}
```

## Initrd questions
When you set `enableInitrd = true`, a second `netsecrets-client` service will be registered inside the startup set of initrd, secrets will be avalible before the real root is mounted

If you will set `enableInitrdPassword = true`, an additional service will prompt for the server password, its interactive so like /dev/console. It will write it to /run/netsecrets-password and will copy it to `/run/secrets/netsecrets-password` so a service post-initrd service can use it
