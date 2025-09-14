use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aes_gcm::aead::{rand_core::RngCore, Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rsa::pkcs1::{
    DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey,
};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

#[derive(Parser)]
#[command(name = "netsecrets")]
#[command(about = "A Rust CLI for secure secret sharing with E2E encryption")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(short, long)]
        server: Option<IpAddr>,
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short = 'P', long)]
        password: Option<String>,
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
        #[arg(short = 'r', long = "request_secrets")]
        request_secrets: Option<String>,
        #[arg(short = 'v', long)]
        verbose: bool,
        #[arg(long = "file-output", alias = "output")]
        file_output: Option<String>,
        #[arg(long = "fallbacks")]
        fallbacks: Option<String>,
        #[arg(long = "insecure")]
        insecure: bool,
        #[arg(long = "rsa-public-key")]
        rsa_public_key: Option<PathBuf>,
        #[arg(long = "ed25519-public-key")]
        ed25519_public_key: Option<PathBuf>,
        #[arg(long = "encryption-key")]
        encryption_key: Option<String>,
    },
    Receive {
        #[arg(short = 'a', long, value_delimiter = ',')]
        authorized_ips: Vec<IpNetwork>,
        #[arg(short, long)]
        server: Option<IpAddr>,
        #[arg(short = 'P', long)]
        password: Option<String>,
        #[arg(long = "password-file")]
        password_file: Option<PathBuf>,
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short = 'S', long)]
        secrets: Vec<String>,
        #[arg(short = 'v', long)]
        verbose: bool,
        #[arg(long = "insecure")]
        insecure: bool,
        #[arg(long = "rsa-private-key")]
        rsa_private_key: Option<PathBuf>,
        #[arg(long = "ed25519-private-key")]
        ed25519_private_key: Option<PathBuf>,
        #[arg(long = "encryption-key")]
        encryption_key: Option<String>,
    },
    GenerateKeys {
        #[arg(short, long, value_enum)]
        key_type: KeyType,
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
}

#[derive(clap::ValueEnum, Clone)]
enum KeyType {
    Rsa,
    Ed25519,
}

#[derive(Debug)]
enum EncryptionMethod {
    None,
    Symmetric(Vec<u8>),
    Rsa(RsaPublicKey),
    Ed25519(X25519PublicKey),
}

enum DecryptionMethod {
    None,
    Symmetric(Vec<u8>),
    Rsa(RsaPrivateKey),
    Ed25519(StaticSecret),
}

fn get_env_var_or_arg<T: std::str::FromStr>(env_var: &str, arg: Option<T>) -> Option<T> {
    arg.or_else(|| env::var(env_var).ok().and_then(|s| s.parse().ok()))
}

fn get_env_var_or_required_arg<T: std::str::FromStr>(
    env_var: &str,
    arg: Option<T>,
    field_name: &str,
) -> T {
    get_env_var_or_arg(env_var, arg).unwrap_or_else(|| {
        panic!(
            "{} must be provided either as argument or through {}",
            field_name, env_var
        )
    })
}

fn read_password_from_file(path: &Path) -> String {
    fs::read_to_string(path)
        .expect("Failed to read password file")
        .trim()
        .to_string()
}

fn parse_fallbacks(fallbacks: Option<String>) -> Option<Vec<IpAddr>> {
    fallbacks
        .or_else(|| env::var("NETSECRETS_FALLBACKS").ok())
        .map(|s| {
            s.split(',')
                .filter_map(|ip| ip.trim().parse().ok())
                .collect()
        })
}

fn generate_keys(key_type: KeyType, output_dir: Option<PathBuf>) {
    let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir).expect("Failed to create output directory");

    match key_type {
        KeyType::Rsa => {
            println!("Generating RSA key pair...");
            let mut rng = rand::thread_rng();
            let private_key =
                RsaPrivateKey::new(&mut rng, 2048).expect("Failed to generate RSA key");
            let public_key = RsaPublicKey::from(&private_key);

            let private_pem = private_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("Failed to encode private key");
            let public_pem = public_key
                .to_pkcs1_pem(rsa::pkcs1::LineEnding::LF)
                .expect("Failed to encode public key");

            fs::write(dir.join("rsa_private.pem"), private_pem.as_bytes())
                .expect("Failed to write private key");
            fs::write(dir.join("rsa_public.pem"), public_pem.as_bytes())
                .expect("Failed to write public key");

            println!("RSA keys generated:");
            println!("  Private key: {}", dir.join("rsa_private.pem").display());
            println!("  Public key: {}", dir.join("rsa_public.pem").display());
        }
        KeyType::Ed25519 => {
            println!("Generating Ed25519 key pair...");
            let mut csprng = rand::rngs::OsRng {};
            let signing_key = SigningKey::generate(&mut csprng);
            let verifying_key = signing_key.verifying_key();

            let private_bytes = signing_key.to_bytes();
            let public_bytes = verifying_key.to_bytes();

            let private_b64 = BASE64.encode(&private_bytes);
            let public_b64 = BASE64.encode(&public_bytes);

            fs::write(dir.join("ed25519_private.key"), private_b64)
                .expect("Failed to write private key");
            fs::write(dir.join("ed25519_public.key"), public_b64)
                .expect("Failed to write public key");

            println!("Ed25519 keys generated:");
            println!(
                "  Private key: {}",
                dir.join("ed25519_private.key").display()
            );
            println!("  Public key: {}", dir.join("ed25519_public.key").display());
        }
    }
}
fn load_authorized_keys(path: &Path) -> HashMap<String, RsaPublicKey> {
    let mut authorized_keys = HashMap::new();
    if let Ok(content) = fs::read_to_string(path) {
        for line in content.lines() {
            if let Some((name, key_b64)) = line.split_once(' ') {
                if let Ok(key_bytes) = BASE64.decode(key_b64) {
                    if let Ok(public_key) = RsaPublicKey::from_pkcs1_der(&key_bytes) {
                        authorized_keys.insert(name.to_string(), public_key);
                    }
                }
            }
        }
    }
    authorized_keys
}

fn load_rsa_public_key(path: &Path) -> RsaPublicKey {
    let pem = fs::read_to_string(path).expect("Failed to read RSA public key file");
    RsaPublicKey::from_pkcs1_pem(&pem).expect("Failed to parse RSA public key")
}

fn load_rsa_private_key(path: &Path) -> RsaPrivateKey {
    let pem = fs::read_to_string(path).expect("Failed to read RSA private key file");
    RsaPrivateKey::from_pkcs1_pem(&pem).expect("Failed to parse RSA private key")
}

fn load_ed25519_public_key(path: &Path) -> VerifyingKey {
    let b64 = fs::read_to_string(path).expect("Failed to read Ed25519 public key file");
    let bytes = BASE64.decode(b64.trim()).expect("Failed to decode base64");
    let array: [u8; 32] = bytes.try_into().expect("Invalid key length");
    VerifyingKey::from_bytes(&array).expect("Failed to parse Ed25519 public key")
}

fn load_ed25519_private_key(path: &Path) -> SigningKey {
    let b64 = fs::read_to_string(path).expect("Failed to read Ed25519 private key file");
    let bytes = BASE64.decode(b64.trim()).expect("Failed to decode base64");
    let array: [u8; 32] = bytes.try_into().expect("Invalid key length");
    SigningKey::from_bytes(&array)
}

fn derive_x25519_from_ed25519_public(ed25519_key: &VerifyingKey) -> X25519PublicKey {
    let bytes = ed25519_key.to_bytes();
    X25519PublicKey::from(bytes)
}

fn derive_x25519_from_ed25519_secret(ed25519_key: &SigningKey) -> StaticSecret {
    let bytes = ed25519_key.to_bytes();
    StaticSecret::from(bytes)
}

fn derive_symmetric_key(shared_secret: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(shared_secret);
    hasher.finalize().to_vec()
}

fn encrypt_data(data: &[u8], method: &EncryptionMethod) -> Vec<u8> {
    match method {
        EncryptionMethod::None => data.to_vec(),
        EncryptionMethod::Symmetric(key) => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            let ciphertext = cipher.encrypt(nonce, data).expect("Encryption failed");
            let mut result = nonce_bytes.to_vec();
            result.extend_from_slice(&ciphertext);
            result
        }
        EncryptionMethod::Rsa(public_key) => {
            let mut rng = rand::thread_rng();

            if data.len() > 190 {
                let mut aes_key = [0u8; 32];
                OsRng.fill_bytes(&mut aes_key);

                let symmetric_method = EncryptionMethod::Symmetric(aes_key.to_vec());
                let encrypted_data = encrypt_data(data, &symmetric_method);

                let encrypted_key = public_key
                    .encrypt(&mut rng, Pkcs1v15Encrypt, &aes_key)
                    .expect("RSA encryption failed");

                let mut result = Vec::new();
                result.extend_from_slice(&(encrypted_key.len() as u32).to_be_bytes());
                result.extend_from_slice(&encrypted_key);
                result.extend_from_slice(&encrypted_data);
                result
            } else {
                public_key
                    .encrypt(&mut rng, Pkcs1v15Encrypt, data)
                    .expect("RSA encryption failed")
            }
        }
        EncryptionMethod::Ed25519(public_key) => {
            let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
            let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

            let shared_secret = ephemeral_secret.diffie_hellman(public_key);
            let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

            let symmetric_method = EncryptionMethod::Symmetric(symmetric_key);
            let encrypted_data = encrypt_data(data, &symmetric_method);

            let mut result = ephemeral_public.as_bytes().to_vec();
            result.extend_from_slice(&encrypted_data);
            result
        }
    }
}

fn decrypt_data(data: &[u8], method: &DecryptionMethod) -> Vec<u8> {
    match method {
        DecryptionMethod::None => data.to_vec(),
        DecryptionMethod::Symmetric(key) => {
            if data.len() < 12 {
                panic!("Invalid encrypted data: too short");
            }

            let nonce = Nonce::from_slice(&data[0..12]);
            let ciphertext = &data[12..];

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(nonce, ciphertext)
                .expect("Decryption failed")
        }
        DecryptionMethod::Rsa(private_key) => {
            if data.len() > 256 {
                let key_length = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if data.len() >= 4 + key_length {
                    let encrypted_key = &data[4..4 + key_length];
                    let encrypted_data = &data[4 + key_length..];

                    let aes_key = private_key
                        .decrypt(Pkcs1v15Encrypt, encrypted_key)
                        .expect("RSA decryption failed");

                    let symmetric_method = DecryptionMethod::Symmetric(aes_key);
                    return decrypt_data(encrypted_data, &symmetric_method);
                }
            }

            private_key
                .decrypt(Pkcs1v15Encrypt, data)
                .expect("RSA decryption failed")
        }
        DecryptionMethod::Ed25519(static_secret) => {
            if data.len() < 32 {
                panic!("Invalid encrypted data: too short for Ed25519");
            }

            let ephemeral_public =
                X25519PublicKey::from(<[u8; 32]>::try_from(&data[0..32]).unwrap());
            let encrypted_data = &data[32..];

            let shared_secret = static_secret.diffie_hellman(&ephemeral_public);
            let symmetric_key = derive_symmetric_key(shared_secret.as_bytes());

            let symmetric_method = DecryptionMethod::Symmetric(symmetric_key);
            decrypt_data(encrypted_data, &symmetric_method)
        }
    }
}

fn determine_encryption_method(
    insecure: bool,
    rsa_public_key: Option<PathBuf>,
    ed25519_public_key: Option<PathBuf>,
    encryption_key: Option<String>,
) -> EncryptionMethod {
    if insecure {
        return EncryptionMethod::None;
    }

    if let Some(rsa_path) = rsa_public_key {
        let public_key = load_rsa_public_key(&rsa_path);
        return EncryptionMethod::Rsa(public_key);
    }

    if let Some(ed25519_path) = ed25519_public_key {
        let ed25519_public = load_ed25519_public_key(&ed25519_path);
        let x25519_public = derive_x25519_from_ed25519_public(&ed25519_public);
        return EncryptionMethod::Ed25519(x25519_public);
    }

    let key = if let Some(key_str) = encryption_key {
        if key_str.len() == 64 {
            hex::decode(&key_str).unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
        } else {
            derive_symmetric_key(key_str.as_bytes())
        }
    } else {
        let mut key = vec![0u8; 32];
        OsRng.fill_bytes(&mut key);
        eprintln!(
            "Generated random encryption key (hex): {}",
            hex::encode(&key)
        );
        eprintln!("Save this key to decrypt responses!");
        key
    };

    EncryptionMethod::Symmetric(key)
}

fn determine_decryption_method(
    insecure: bool,
    rsa_private_key: Option<PathBuf>,
    ed25519_private_key: Option<PathBuf>,
    encryption_key: Option<String>,
) -> DecryptionMethod {
    if insecure {
        return DecryptionMethod::None;
    }

    if let Some(rsa_path) = rsa_private_key {
        let private_key = load_rsa_private_key(&rsa_path);
        return DecryptionMethod::Rsa(private_key);
    }

    if let Some(ed25519_path) = ed25519_private_key {
        let ed25519_secret = load_ed25519_private_key(&ed25519_path);
        let x25519_static = derive_x25519_from_ed25519_secret(&ed25519_secret);
        return DecryptionMethod::Ed25519(x25519_static);
    }

    let key = if let Some(key_str) = encryption_key {
        if key_str.len() == 64 {
            hex::decode(&key_str).unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
        } else {
            derive_symmetric_key(key_str.as_bytes())
        }
    } else {
        panic!("Encryption key must be provided for decryption");
    };

    DecryptionMethod::Symmetric(key)
}

fn start_server(
    ip: IpAddr,
    port: u16,
    password: String,
    secrets: HashMap<String, String>,
    verbose: bool,
    authorized_ips: Vec<IpNetwork>,
    decryption_method: DecryptionMethod,
) {
    let listener = TcpListener::bind((ip, port)).expect("Failed to bind server");
    println!("Server started on {}:{}", ip, port);

    if matches!(decryption_method, DecryptionMethod::None) {
        println!("WARNING: Running in insecure mode - no encryption!");
    }

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let peer_ip = stream.peer_addr().unwrap().ip();
            let mut buffer = Vec::new();

            if stream.read_to_end(&mut buffer).is_ok() {
                let decrypted_request = decrypt_data(&buffer, &decryption_method);
                let request = String::from_utf8_lossy(&decrypted_request);

                let mut parts = request.split_whitespace();
                let req_password = parts.next().unwrap_or("");
                let requested = parts.next().unwrap_or("");
                let client_pub_key_b64 = parts.next(); // Extract client's public key

                if verbose {
                    println!(
                        "Authentication attempt from {} with password='{}'",
                        peer_ip, req_password
                    );
                    if let Some(key_b64) = client_pub_key_b64 {
                        println!("Client provided public key: {}", key_b64);
                    }
                }

                let password_ok = password.is_empty() || req_password == password;
                let ip_ok = authorized_ips.is_empty()
                    || authorized_ips.iter().any(|net| net.contains(peer_ip));

                if verbose {
                    println!(
                        "Authentication {}",
                        if password_ok && ip_ok {
                            "succeeded"
                        } else {
                            "failed"
                        }
                    );
                }

                let response = if password_ok && ip_ok {
                    let mut response_parts = Vec::new();
                    for name in requested.split(',').filter(|s| !s.is_empty()) {
                        if let Some(val) = secrets.get(name) {
                            if verbose {
                                println!("Retrieved secret: {}={}", name, val);
                            }
                            response_parts.push(format!("{}={}", name, val));
                        } else {
                            if verbose {
                                println!("Failed to retrieve secret: {}", name);
                            }
                            response_parts.push(format!("{}=Secret not found", name));
                        }
                    }
                    response_parts.join(",")
                } else {
                    let msg = match (password_ok, ip_ok) {
                        (false, false) => "Invalid password and IP",
                        (false, _) => "Invalid password",
                        (_, false) => "Invalid IP",
                        _ => "",
                    };
                    msg.to_string()
                };

                // Encrypt response with client's public key if provided
                let encrypted_response = if let Some(client_pub_key_b64) = client_pub_key_b64 {
                    match &decryption_method {
                        DecryptionMethod::Rsa(_) => {
                            // Client provided RSA public key
                            if let Ok(client_pub_key_pem) = BASE64.decode(client_pub_key_b64) {
                                if let Ok(client_pub_key) = RsaPublicKey::from_pkcs1_pem(
                                    &String::from_utf8(client_pub_key_pem).unwrap()
                                ) {
                                    if verbose {
                                        println!("Encrypting response with client's RSA public key");
                                    }
                                    encrypt_data(response.as_bytes(), &EncryptionMethod::Rsa(client_pub_key))
                                } else {
                                    if verbose {
                                        eprintln!("Failed to parse client's RSA public key, responding in plaintext");
                                    }
                                    response.as_bytes().to_vec()
                                }
                            } else {
                                if verbose {
                                    eprintln!("Failed to decode client's public key, responding in plaintext");
                                }
                                response.as_bytes().to_vec()
                            }
                        }
                        DecryptionMethod::Ed25519(_) => {
                            // Client provided X25519 public key
                            if let Ok(client_pub_key_bytes) = BASE64.decode(client_pub_key_b64) {
                                // FIX: Explicitly specify the target type for try_into()
                                if client_pub_key_bytes.len() == 32 {
                                    let mut client_pub_key_array = [0u8; 32];
                                    client_pub_key_array.copy_from_slice(&client_pub_key_bytes);
                                    let client_pub_key = X25519PublicKey::from(client_pub_key_array);
                                    if verbose {
                                        println!("Encrypting response with client's X25519 public key");
                                    }
                                    encrypt_data(response.as_bytes(), &EncryptionMethod::Ed25519(client_pub_key))
                                } else {
                                    if verbose {
                                        eprintln!("Invalid X25519 public key length, responding in plaintext");
                                    }
                                    response.as_bytes().to_vec()
                                }
                            } else {
                                if verbose {
                                    eprintln!("Failed to decode client's public key, responding in plaintext");
                                }
                                response.as_bytes().to_vec()
                            }
                        }
                        _ => {
                            // No asymmetric encryption, use normal flow
                            let encryption_method = match &decryption_method {
                                DecryptionMethod::None => EncryptionMethod::None,
                                DecryptionMethod::Symmetric(key) => EncryptionMethod::Symmetric(key.clone()),
                                _ => {
                                    if verbose {
                                        eprintln!("Unexpected decryption method, responding in plaintext");
                                    }
                                    EncryptionMethod::None
                                }
                            };
                            encrypt_data(response.as_bytes(), &encryption_method)
                        }
                    }
                } else {
                    // No client public key provided, use normal encryption
                    let encryption_method = match &decryption_method {
                        DecryptionMethod::None => EncryptionMethod::None,
                        DecryptionMethod::Symmetric(key) => EncryptionMethod::Symmetric(key.clone()),
                        DecryptionMethod::Rsa(private_key) => {
                            let public_key = RsaPublicKey::from(private_key);
                            EncryptionMethod::Rsa(public_key)
                        }
                        DecryptionMethod::Ed25519(static_secret) => {
                            let key = derive_symmetric_key(&static_secret.to_bytes());
                            EncryptionMethod::Symmetric(key)
                        }
                    };
                    encrypt_data(response.as_bytes(), &encryption_method)
                };

                let _ = stream.write_all(&encrypted_response);
            }
        }
    }
}

fn query_fallback(
    ip: IpAddr,
    port: u16,
    password: &str,
    secret: &str,
    verbose: bool,
    encryption_method: &EncryptionMethod,
    decryption_method: &DecryptionMethod,
) -> Option<String> {
    let socket = SocketAddr::new(ip, port);
    if verbose {
        println!("Querying fallback {} for {}", ip, secret);
    }

    if let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

        let message = format!("{} {}", password, secret);
        let encrypted_message = encrypt_data(message.as_bytes(), encryption_method);

        if stream.write_all(&encrypted_message).is_err() {
            if verbose {
                eprintln!("Fallback write error");
            }
            return None;
        }

        let mut response = Vec::new();
        if stream.read_to_end(&mut response).is_ok() {
            let decrypted_response = decrypt_data(&response, decryption_method);
            let response_str = String::from_utf8_lossy(&decrypted_response);
            let val = response_str.splitn(2, '=').nth(1).unwrap_or("").trim();
            if val != "Secret not found" {
                return Some(val.to_string());
            }
        }
    } else if verbose {
        eprintln!("Fallback connect error to {}", ip);
    }
    None
}

fn is_directory(path: &Path) -> bool {
    if path.exists() {
        path.is_dir()
    } else {
        let s = path.to_str().unwrap_or("");
        s.ends_with('/') || s.ends_with(std::path::MAIN_SEPARATOR)
    }
}

fn send_request(
    server: IpAddr,
    port: u16,
    password: String,
    request_secrets: String,
    verbose: bool,
    file_output: Option<String>,
    fallbacks: Option<Vec<IpAddr>>,
    encryption_method: EncryptionMethod,
    decryption_method: DecryptionMethod,
) {
    let socket = SocketAddr::new(server, port);
    let mut stream = match TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                eprintln!("Primary server failed: {}", e);
            }
            if let Some(ips) = &fallbacks {
                for &ip in ips {
                    if let Ok(_s) = TcpStream::connect_timeout(
                        &SocketAddr::new(ip, port),
                        Duration::from_secs(5),
                    ) {
                        if verbose {
                            println!("Connected to fallback {}", ip);
                        }
                        return send_request(
                            ip,
                            port,
                            password,
                            request_secrets,
                            verbose,
                            file_output,
                            fallbacks,
                            encryption_method,
                            decryption_method,
                        );
                    }
                }
            }
            panic!("Failed to connect to any server");
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let message = format!("{} {}", password, request_secrets);
    let encrypted_message = encrypt_data(message.as_bytes(), &encryption_method);
    let _ = stream.write_all(&encrypted_message);

    let mut response = Vec::new();
    let mut secrets = HashMap::new();

    if stream.read_to_end(&mut response).is_ok() {
        let decrypted_response = decrypt_data(&response, &decryption_method);
        let response_data = if matches!(decryption_method, DecryptionMethod::None) {
            // Response is plaintext
            response
        } else {
            // Response should be encrypted, try to decrypt
            decrypt_data(&response, &decryption_method)
        };
        
        let response_str = String::from_utf8_lossy(&response_data);

        for part in response_str.split(',') {
            let mut kv = part.splitn(2, '=');
            if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                secrets.insert(k.trim().to_string(), v.trim().to_string());
            }
        }
    } else if verbose {
        eprintln!("Read failed");
    }

    if let Some(ips) = fallbacks {
        let mut missing = Vec::new();
        for name in request_secrets.split(',').filter(|s| !s.is_empty()) {
            if !secrets.contains_key(name) {
                missing.push(name.to_string());
            }
        }
        for name in missing {
            for &ip in &ips {
                if let Some(val) = query_fallback(
                    ip,
                    port,
                    &password,
                    &name,
                    verbose,
                    &encryption_method,
                    &decryption_method,
                ) {
                    secrets.insert(name.clone(), val);
                    break;
                }
            }
        }
    }

    if let Some(ref path) = file_output {
        let out = PathBuf::from(path);
        if is_directory(&out) {
            fs::create_dir_all(&out).unwrap();
            for (k, v) in &secrets {
                let _ = fs::write(out.join(k), v);
            }
        } else {
            let content = secrets.values().cloned().collect::<Vec<_>>().join("\n");
            let _ = fs::write(&out, content);
        }
    }

    if file_output.is_none() {
        for (k, v) in &secrets {
            println!("{}={}", k, v);
        }
    }
}
fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::GenerateKeys {
            key_type,
            output_dir,
        } => {
            generate_keys(key_type, output_dir);
        }
        Commands::Send {
            server,
            port,
            password,
            password_file,
            request_secrets,
            verbose,
            file_output,
            fallbacks,
            insecure,
            rsa_public_key,
            ed25519_public_key,
            encryption_key,
        } => {
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = if let Some(pf) = password_file {
                read_password_from_file(&pf)
            } else {
                get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password")
            };
            let request = get_env_var_or_required_arg(
                "NETSECRETS_REQUEST_SECRETS",
                request_secrets,
                "request_secrets",
            );
            let ips = parse_fallbacks(fallbacks);

            let encryption_method = determine_encryption_method(
                insecure,
                rsa_public_key,
                ed25519_public_key,
                encryption_key.clone(),
            );

            let decryption_method = if insecure {
                DecryptionMethod::None
            } else if let Some(key_str) = &encryption_key {
                let key = if key_str.len() == 64 {
                    hex::decode(key_str)
                        .unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
                } else {
                    derive_symmetric_key(key_str.as_bytes())
                };
                DecryptionMethod::Symmetric(key)
            } else {
                if verbose {
                    eprintln!("Warning: Cannot decrypt responses with asymmetric encryption, using insecure mode for responses");
                }
                DecryptionMethod::None
            };

            send_request(
                server,
                port,
                password,
                request,
                verbose,
                file_output,
                ips,
                encryption_method,
                decryption_method,
            );
        }
        Commands::Receive {
            authorized_ips,
            server,
            password,
            password_file,
            port,
            secrets,
            verbose,
            insecure,
            rsa_private_key,
            ed25519_private_key,
            encryption_key,
        } => {
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = if let Some(pf) = password_file {
                read_password_from_file(&pf)
            } else {
                get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password")
            };

            let mut map = HashMap::new();
            for s in secrets {
                let mut parts = s.splitn(2, '=');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    map.insert(k.to_string(), v.to_string());
                }
            }

            let decryption_method = determine_decryption_method(
                insecure,
                rsa_private_key,
                ed25519_private_key,
                encryption_key,
            );

            start_server(
                server,
                port,
                password,
                map,
                verbose,
                authorized_ips,
                decryption_method,
            );
        }
    }
}
