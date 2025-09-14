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
use sha2::{Digest, Sha256};

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
        #[arg(long = "encryption-key")]
        encryption_key: Option<String>,
        #[arg(long = "client-name")]
        client_name: Option<String>,
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
        #[arg(long = "encryption-key")]
        encryption_key: Option<String>,
    },
    GenerateKeys {
        #[arg(short, long)]
        output_dir: Option<PathBuf>,
    },
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

fn generate_keys(output_dir: Option<PathBuf>) {
    let dir = output_dir.unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&dir).expect("Failed to create output directory");

    println!("Generating symmetric encryption key...");
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let key_hex = hex::encode(&key);
    fs::write(dir.join("encryption_key.hex"), &key_hex).expect("Failed to write encryption key");

    println!("Symmetric encryption key generated:");
    println!("  Key: {}", dir.join("encryption_key.hex").display());
    println!("  Value: {}", key_hex);
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
    }
}

fn decrypt_data(data: &[u8], method: &DecryptionMethod) -> Result<Vec<u8>, String> {
    match method {
        DecryptionMethod::None => Ok(data.to_vec()),
        DecryptionMethod::Symmetric(key) => {
            if data.len() < 12 {
                return Err("Invalid encrypted data: too short".to_string());
            }

            let nonce = Nonce::from_slice(&data[0..12]);
            let ciphertext = &data[12..];

            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| format!("AES decryption failed: {}", e))
        }
    }
}

#[derive(Debug)]
enum EncryptionMethod {
    None,
    Symmetric(Vec<u8>),
}

enum DecryptionMethod {
    None,
    Symmetric(Vec<u8>),
}

fn determine_encryption_method(insecure: bool, encryption_key: Option<String>) -> EncryptionMethod {
    if insecure {
        return EncryptionMethod::None;
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

fn determine_decryption_method(insecure: bool, encryption_key: Option<String>) -> DecryptionMethod {
    if insecure {
        return DecryptionMethod::None;
    }

    let key = if let Some(key_str) = encryption_key {
        if key_str.len() == 64 {
            hex::decode(key_str).unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
        } else {
            derive_symmetric_key(key_str.as_bytes())
        }
    } else {
        panic!("Encryption key must be provided for decryption");
    };

    DecryptionMethod::Symmetric(key)
}

use std::net::Shutdown;

pub fn start_server(
    server: String,
    port: u16,
    password: String,
    secrets: HashMap<String, String>,
    verbose: bool,
    authorized_ips: Option<Vec<IpAddr>>,
    decryption_method: DecryptionMethod,
) -> std::io::Result<()> {
    let bind = format!("{}:{}", server, port);
    let listener = TcpListener::bind(&bind)?;
    if verbose {
        println!("Server listening on {}", bind);
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let peer_addr = stream.peer_addr()?;
                if verbose {
                    println!("Connection from {}", peer_addr);
                }

                if let Some(ref ips) = &authorized_ips {
                    if !ips.is_empty() && !ips.contains(&peer_addr.ip()) {
                        eprintln!("Unauthorized IP: {}", peer_addr.ip());
                        continue;
                    }
                }

                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;

                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf) {
                    Ok(0) => {
                        if verbose {
                            println!("Client closed connection early");
                        }
                        continue;
                    }
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from client {}: {}", peer_addr, e);
                        continue;
                    }
                };

                let encrypted_request = &buf[..n];

                let request_bytes = decrypt_data(encrypted_request, &decryption_method)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

                let request_str = String::from_utf8_lossy(&request_bytes);
                let mut parts = request_str.split_whitespace();
                let recv_password = parts.next().unwrap_or("");
                let recv_secret_key = parts.next().unwrap_or("");

                if recv_password != password {
                    eprintln!("Invalid password from {}", peer_addr);
                    continue;
                }

                let response = secrets
                    .get(recv_secret_key)
                    .cloned()
                    .unwrap_or_else(|| "Not found".to_string());

                let encrypted_response: Vec<u8> = match &decryption_method {
                    DecryptionMethod::Symmetric(key) => encrypt_data(
                        response.as_bytes(),
                        &EncryptionMethod::Symmetric(key.clone()),
                    ),
                    DecryptionMethod::None => response.as_bytes().to_vec(),
                };

                if verbose {
                    println!(
                        "Sending {} bytes response to {}",
                        encrypted_response.len(),
                        peer_addr
                    );
                }

                let len_be = (encrypted_response.len() as u32).to_be_bytes();
                if let Err(e) = stream.write_all(&len_be) {
                    eprintln!("Failed to send response length: {}", e);
                    continue;
                }
                if let Err(e) = stream.write_all(&encrypted_response) {
                    eprintln!("Failed to send response body: {}", e);
                    continue;
                }
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Write);
            }
            Err(e) => {
                eprintln!("Incoming connection failed: {}", e);
            }
        }
    }

    Ok(())
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
            let decrypted_response = match decrypt_data(&response, decryption_method) {
                Ok(data) => data,
                Err(e) => {
                    if verbose {
                        eprintln!("Failed to decrypt fallback response: {}", e);
                    }
                    return None;
                }
            };
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

pub fn send_request(
    server: IpAddr,
    port: u16,
    password: String,
    request_secrets: String,
    verbose: bool,
    file_output: Option<String>,
    fallbacks: Option<Vec<IpAddr>>,
    encryption_method: EncryptionMethod,
    decryption_method: DecryptionMethod,
    client_name: Option<String>,
) {
    let socket = SocketAddr::new(server, port);
    if verbose {
        println!("Connecting to server: {}", socket);
    }

    let mut stream = match TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                eprintln!("Primary server failed: {}", e);
            }
            if let Some(ips) = &fallbacks {
                for &ip in ips {
                    if let Ok(s) = TcpStream::connect_timeout(
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
                            client_name,
                        );
                    }
                }
            }
            panic!("Failed to connect to any server");
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let message = format!("{} {}", password, request_secrets);

    if verbose {
        println!("Sending request: {}", message);
    }

    let encrypted_message = encrypt_data(message.as_bytes(), &encryption_method);

    if verbose {
        println!("Encrypted message size: {} bytes", encrypted_message.len());
    }

    if let Err(e) = stream.write_all(&encrypted_message) {
        if verbose {
            eprintln!("Failed to send request: {}", e);
        }
        return;
    }

    if verbose {
        println!("Request sent successfully, waiting for response...");
    }

    let mut len_bytes = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_bytes) {
        if verbose {
            eprintln!("Failed to read response length: {}", e);
        }
        return;
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if verbose {
        println!("Expecting {} bytes response", len);
    }

    let mut response = vec![0u8; len];
    if let Err(e) = stream.read_exact(&mut response) {
        if verbose {
            eprintln!("Failed to read response body: {}", e);
        }
        return;
    }

    if verbose {
        println!("Received {} bytes response", response.len());
    }

    let response_data = if matches!(decryption_method, DecryptionMethod::None) {
        response
    } else {
        if verbose {
            println!("Attempting to decrypt response...");
        }
        match decrypt_data(&response, &decryption_method) {
            Ok(decrypted) => {
                if verbose {
                    println!("Successfully decrypted response");
                }
                decrypted
            }
            Err(e) => {
                if verbose {
                    eprintln!("Decryption failed: {}, treating as plaintext", e);
                }
                response
            }
        }
    };

    let response_str = String::from_utf8_lossy(&response_data);

    if verbose {
        println!("Response content: {}", response_str);
    }

    let mut secrets = HashMap::new();
    for part in response_str.split(',') {
        let mut kv = part.splitn(2, '=');
        if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
            secrets.insert(k.trim().to_string(), v.trim().to_string());
            if verbose {
                println!("Parsed secret: {}={}", k.trim(), v.trim());
            }
        }
    }

    if secrets.is_empty() && verbose {
        eprintln!("Warning: No secrets found in response");
    }

    if let Some(ips) = &fallbacks {
        let mut missing = Vec::new();
        for name in request_secrets.split(',').filter(|s| !s.is_empty()) {
            if !secrets.contains_key(name) {
                missing.push(name.to_string());
                if verbose {
                    println!("Secret '{}' not found, will try fallbacks", name);
                }
            }
        }

        for name in missing {
            for &ip in ips {
                if verbose {
                    println!("Trying fallback {} for secret '{}'", ip, name);
                }
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
                    if verbose {
                        println!("Found secret '{}' from fallback {}", name, ip);
                    }
                    break;
                }
            }
        }
    }

    if let Some(ref path) = file_output {
        let out = PathBuf::from(path);
        if is_directory(&out) {
            if let Err(e) = fs::create_dir_all(&out) {
                eprintln!("Failed to create directory {}: {}", out.display(), e);
                return;
            }
            for (k, v) in &secrets {
                if let Err(e) = fs::write(out.join(k), v) {
                    eprintln!("Failed to write file {}: {}", k, e);
                } else if verbose {
                    println!("Written secret to file: {}", out.join(k).display());
                }
            }
        } else {
            let content = secrets.values().cloned().collect::<Vec<_>>().join("\n");
            if let Err(e) = fs::write(&out, content) {
                eprintln!("Failed to write file {}: {}", out.display(), e);
            } else if verbose {
                println!("Written all secrets to file: {}", out.display());
            }
        }
    }

    if file_output.is_none() {
        if secrets.is_empty() {
            eprintln!("No secrets received from server");
        } else {
            for (k, v) in &secrets {
                println!("{}={}", k, v);
            }
        }
    }
}

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenerateKeys { output_dir } => {
            generate_keys(output_dir);
            Ok(())
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
            encryption_key,
            client_name,
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
            let client_name = client_name.or_else(|| env::var("NETSECRETS_CLIENT_NAME").ok());

            let encryption_method = determine_encryption_method(insecure, encryption_key.clone());

            let decryption_method = if insecure {
                DecryptionMethod::None
            } else if let Some(key_str) = &encryption_key {
                let key = if key_str.len() == 64 {
                    hex::decode(&key_str)
                        .unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
                } else {
                    derive_symmetric_key(key_str.as_bytes())
                };
                DecryptionMethod::Symmetric(key)
            } else {
                if verbose {
                    eprintln!("Warning: Cannot decrypt responses without encryption key, using insecure mode for responses");
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
                client_name,
            );

            Ok(())
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
            encryption_key,
        } => {
            let server =
                get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server").to_string();
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

            let decryption_method = determine_decryption_method(insecure, encryption_key);

            let authorized_ips: Option<Vec<IpAddr>> = {
                let ips: Vec<IpAddr> = authorized_ips.into_iter().map(|n| n.ip()).collect();
                if ips.is_empty() {
                    None
                } else {
                    Some(ips)
                }
            };

            start_server(
                server,
                port,
                password,
                map,
                verbose,
                authorized_ips,
                decryption_method,
            )?;

            Ok(())
        }
    }
}
