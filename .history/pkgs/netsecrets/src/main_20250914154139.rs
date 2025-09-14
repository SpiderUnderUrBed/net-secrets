use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, OsRng, RngCore, Nonce};
use aes_gcm::{Aes256Gcm, Key};
use sha2::{Digest, Sha256};
use aes_gcm::aead::rand_core::rand_core::RngCore;

#[derive(Parser)]
#[command(name = "netsecrets")]
#[command(about = "A Rust CLI for secret sharing (plaintext/symmetric only)")]
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
        #[arg(short, long)]
        verbose: bool,
        #[arg(long = "file-output", alias = "output")]
        file_output: Option<String>,
        #[arg(long = "fallbacks")]
        fallbacks: Option<String>,
        #[arg(long = "insecure")]
        insecure: bool,
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
        #[arg(short, long)]
        verbose: bool,
        #[arg(long = "insecure")]
        insecure: bool,
        #[arg(long = "encryption-key")]
        encryption_key: Option<String>,
    },
}

#[derive(Debug, Clone)]
enum EncryptionMethod {
    None,
    Symmetric(Vec<u8>),
}

#[derive(Debug)]
enum DecryptionMethod {
    None,
    Symmetric(Vec<u8>),
}

// --- Helpers ---

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

fn derive_symmetric_key(key: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(key);
    hasher.finalize().to_vec()
}

fn encrypt_data(data: &[u8], method: &EncryptionMethod) -> Vec<u8> {
    match method {
        EncryptionMethod::None => data.to_vec(),
        EncryptionMethod::Symmetric(key) => {
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            let mut nonce_bytes = [0u8; 12];
            OsRng.fill_bytes(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes); // ✅ Fixed
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
            let nonce = Nonce::from_slice(&data[0..12]); // ✅ Fixed
            let ciphertext = &data[12..];
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
            cipher
                .decrypt(nonce, ciphertext)
                .map_err(|e| format!("AES decryption failed: {}", e))
        }
    }
}

fn determine_encryption_method(
    insecure: bool,
    encryption_key: Option<String>,
) -> EncryptionMethod {
    if insecure {
        return EncryptionMethod::None;
    }
    if let Some(key_str) = encryption_key {
        let key = if key_str.len() == 64 {
            hex::decode(&key_str).unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
        } else {
            derive_symmetric_key(key_str.as_bytes())
        };
        EncryptionMethod::Symmetric(key)
    } else {
        EncryptionMethod::None
    }
}

fn determine_decryption_method(
    insecure: bool,
    encryption_key: Option<String>,
) -> DecryptionMethod {
    if insecure {
        return DecryptionMethod::None;
    }
    if let Some(key_str) = encryption_key {
        let key = if key_str.len() == 64 {
            hex::decode(&key_str).unwrap_or_else(|_| derive_symmetric_key(key_str.as_bytes()))
        } else {
            derive_symmetric_key(key_str.as_bytes())
        };
        DecryptionMethod::Symmetric(key)
    } else {
        DecryptionMethod::None
    }
}

// --- Server ---

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
                    if !ips.contains(&peer_addr.ip()) {
                        eprintln!("Unauthorized IP: {}", peer_addr.ip());
                        continue;
                    }
                }

                stream.set_read_timeout(Some(Duration::from_secs(5)))?;
                stream.set_write_timeout(Some(Duration::from_secs(5)))?;

                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf) {
                    Ok(0) => continue,
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Failed to read from client {}: {}", peer_addr, e);
                        continue;
                    }
                };

                let request_bytes = decrypt_data(&buf[..n], &decryption_method)
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

                let len_be = (encrypted_response.len() as u32).to_be_bytes();
                let _ = stream.write_all(&len_be);
                let _ = stream.write_all(&encrypted_response);
                let _ = stream.flush();
                let _ = stream.shutdown(Shutdown::Write);
            }
            Err(e) => eprintln!("Incoming connection failed: {}", e),
        }
    }
    Ok(())
}

// --- Client ---

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
) {
    let socket = SocketAddr::new(server, port);
    if verbose {
        println!("Connecting to server: {}", socket);
    }

    let mut stream = TcpStream::connect_timeout(&socket, Duration::from_secs(5))
        .expect("Failed to connect to server");
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));

    let message = format!("{} {}", password, request_secrets);
    let encrypted_message = encrypt_data(message.as_bytes(), &encryption_method);

    let _ = stream.write_all(&encrypted_message);

    let mut len_bytes = [0u8; 4];
    let _ = stream.read_exact(&mut len_bytes);
    let len = u32::from_be_bytes(len_bytes) as usize;

    let mut response = vec![0u8; len];
    let _ = stream.read_exact(&mut response);

    let response_data = decrypt_data(&response, &decryption_method).unwrap_or(response);
    let response_str = String::from_utf8_lossy(&response_data);

    if let Some(ref path) = file_output {
        let out = PathBuf::from(path);
        fs::write(&out, response_str.as_bytes())
            .expect("Failed to write secrets to file");
    } else {
        println!("{}", response_str);
    }
}

// --- Main ---

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
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

            let encryption_method = determine_encryption_method(insecure, encryption_key.clone());
            let decryption_method = determine_decryption_method(insecure, encryption_key);

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

            let authorized_ips: Option<Vec<IpAddr>> =
                if authorized_ips.is_empty() { None } else { Some(authorized_ips.into_iter().map(|n| n.ip()).collect()) };

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
