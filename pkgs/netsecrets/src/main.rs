use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "netsecrets")]
#[command(about = "A Rust CLI with a default command")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Send {
        #[arg(short, long)]
        server: IpAddr,
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        #[arg(short = 'P', long)]
        password: String,
        #[arg(short = 'r', long = "request_secrets")]
        request_secrets: String,
        #[arg(short = 'v', long)]
        verbose: bool,
        #[arg(long = "file-output")]
        file_output: Option<String>,
        #[arg(long = "fallbacks")]
        fallbacks: Option<String>,
    },
    Receive {
        #[arg(short = 'a', long, value_delimiter = ',')]
        authorized_ips: Vec<IpNetwork>,
        #[arg(short, long)]
        server: IpAddr,
        #[arg(short = 'P', long)]
        password: String,
        #[arg(short, long, default_value_t = 8080)]
        port: u16,
        #[arg(short = 'S', long)]
        secrets: Vec<String>,
        #[arg(short = 'v', long)]
        verbose: bool,
    },
}

fn start_server(
    ip: IpAddr,
    port: u16,
    password: String,
    secrets: HashMap<String, String>,
    verbose: bool,
    authorized_ips: Vec<IpNetwork>,
) {
    let listener = TcpListener::bind((ip, port)).expect("Failed to bind server");
    println!("Server started on {}:{}", ip, port);
    if verbose {
        println!("Secrets stored: {:?}", secrets);
        for (key, _) in &secrets {
            println!("Stored key: {:?} -> {:?}", key, key.as_bytes());
        }
    }
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let mut buffer = [0; 1024];
                match stream.read(&mut buffer) {
                    Ok(size) => {
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        if verbose {
                            println!("Raw request: {:?}", request);
                        }
                        let mut parts = request.split_whitespace();
                        let req_password = parts.next().unwrap_or("").trim();
                        let requested_secrets = parts.next().unwrap_or("").trim();
                        if verbose {
                            println!("Requested password: {:?}", req_password);
                            println!("Requested secrets: {:?}", requested_secrets);
                        }
                        let password_auth = password.is_empty() || (req_password == password);
                        let peer_ip = stream.peer_addr().map(|addr| addr.ip()).unwrap();
                        let ip_auth = authorized_ips.is_empty() || authorized_ips
                            .iter()
                            .any(|subnet| subnet.contains(peer_ip));
                        
                        if password_auth && ip_auth {
                            let secret_names: Vec<&str> = requested_secrets
                                .split(',')
                                .map(|s| s.trim())
                                .filter(|s| !s.is_empty())
                                .collect();
                            let mut responses = Vec::new();
                            for name in secret_names {
                                if let Some(secret_value) = secrets.get(name) {
                                    if verbose {
                                        println!("Found secret for {}: {}", name, secret_value);
                                    }
                                    responses.push(format!("{}={}", name, secret_value));
                                } else {
                                    println!("Secret not found for key: {:?}", name);
                                    responses.push(format!("{}=Secret not found", name));
                                }
                            }
                            let response_str = responses.join(",");
                            let _ = stream.write_all(response_str.as_bytes());
                        } else {
                            if !password_auth && !ip_auth {
                                println!("Invalid password and IP from {:?}", peer_ip);
                                let _ = stream.write_all(b"Invalid password and IP.");
                            } else if !password_auth {
                                println!("Invalid password from {:?}", peer_ip);
                                let _ = stream.write_all(b"Invalid password.");
                            } else if !ip_auth {
                                println!("Invalid IP from {:?}", peer_ip);
                                let _ = stream.write_all(b"Invalid IP.");
                            }
                        }
                    }
                    Err(e) => eprintln!("Failed to read from stream: {}", e),
                }
            }
            Err(e) => eprintln!("Connection failed: {}", e),
        }
    }
}

fn query_fallback(ip: IpAddr, port: u16, password: &str, secret: &str, verbose: bool) -> Option<String> {
    let socket_addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2)) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
            stream.set_write_timeout(Some(Duration::from_secs(2))).ok()?;
            let message = format!("{} {}", password.trim(), secret.trim());
            if let Err(e) = stream.write_all(message.as_bytes()) {
                if verbose {
                    println!("Failed to send request to fallback {}: {}", ip, e);
                }
                return None;
            }
            let mut response = String::new();
            if let Err(e) = stream.read_to_string(&mut response) {
                if verbose {
                    println!("Failed to read response from fallback {}: {}", ip, e);
                }
                return None;
            }
            let parts: Vec<&str> = response.splitn(2, '=').collect();
            if parts.len() == 2 {
                let value = parts[1].trim().to_string();
                if verbose {
                    println!("Fallback server {} returned: {} for key: {}", ip, value, secret);
                }
                if value != "Secret not found" {
                    return Some(value);
                }
            }
            None
        }
        Err(e) => {
            if verbose {
                println!("Failed to connect to fallback server {}: {}", ip, e);
            }
            None
        }
    }
}

fn send_request(
    ip: IpAddr,
    port: u16,
    password: String,
    request_secrets: String,
    verbose: bool,
    file_output: Option<String>,
    fallbacks: Option<Vec<IpAddr>>,
) {
    let socket_addr = SocketAddr::new(ip, port);
    let mut stream_result = TcpStream::connect_timeout(&socket_addr, Duration::from_secs(2));
    if let Err(e) = &stream_result {
        if e.kind() == std::io::ErrorKind::ConnectionRefused || e.kind() == std::io::ErrorKind::TimedOut {
            if verbose {
                println!("Main server connection error ({}), trying fallback servers...", e);
            }
            if let Some(fallback_ips) = fallbacks.clone() {
                for fallback_ip in fallback_ips {
                    let fallback_socket = SocketAddr::new(fallback_ip, port);
                    match TcpStream::connect_timeout(&fallback_socket, Duration::from_secs(2)) {
                        Ok(s) => {
                            stream_result = Ok(s);
                            if verbose {
                                println!("Connected to fallback server: {}", fallback_ip);
                            }
                            break;
                        }
                        Err(e) => {
                            if verbose {
                                println!("Failed to connect to fallback server {}: {}", fallback_ip, e);
                            }
                        }
                    }
                }
            }
        }
    }
    let mut stream = stream_result.expect("Failed to connect to any server");
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok();
    stream.set_write_timeout(Some(Duration::from_secs(2))).ok();
    let message = format!("{} {}", password.trim(), request_secrets.trim());
    stream.write_all(message.as_bytes()).expect("Failed to send request");
    let mut response = String::new();
    match stream.read_to_string(&mut response) {
        Ok(_) => {}
        Err(e) => {
            if verbose {
                println!("Main request timed out or failed: {}. Using fallbacks...", e);
            }
            let keys: Vec<&str> = request_secrets
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .collect();
            response = keys
                .iter()
                .map(|key| format!("{}=Secret not found", key))
                .collect::<Vec<String>>()
                .join(",");
        }
    }
    let mut secrets_map: HashMap<String, String> = HashMap::new();
    for part in response.split(',') {
        let parts: Vec<&str> = part.splitn(2, '=').collect();
        if parts.len() == 2 {
            let key = parts[0].trim().to_string();
            let value = parts[1].trim().to_string();
            secrets_map.insert(key, value);
        }
    }
    if let Some(fallback_ips) = fallbacks {
        for (key, value) in secrets_map.clone().iter() {
            if value == "Secret not found" {
                if verbose {
                    println!("Secret for key '{}' not found on main server, checking fallbacks...", key);
                }
                for fallback_ip in &fallback_ips {
                    if verbose {
                        println!("Trying fallback server: {} for key: {}", fallback_ip, key);
                    }
                    if let Some(fallback_value) = query_fallback(*fallback_ip, port, &password, key, verbose) {
                        secrets_map.insert(key.clone(), fallback_value);
                        break;
                    }
                }
            }
        }
    }
    let final_response = secrets_map
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join(",");
    if verbose {
        println!("Final response: {}", final_response);
    }
    if let Some(directory) = file_output {
        let path = Path::new(&directory);
        if !path.exists() {
            fs::create_dir_all(path).expect("Failed to create directory");
        }
        for (key, value) in secrets_map.iter() {
            let filename = format!("{}/{}", directory, key);
            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(filename)
                .expect("Failed to open file");
            file.write_all(value.as_bytes())
                .expect("Failed to write to file");
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Send {
            server,
            port,
            password,
            request_secrets,
            verbose,
            file_output,
            fallbacks,
        } => {
            let fallback_ips: Option<Vec<IpAddr>> = fallbacks.map(|s| {
                s.split(',')
                    .filter_map(|ip_str| ip_str.trim().parse::<IpAddr>().ok())
                    .collect()
            });
            send_request(
                server,
                port,
                password,
                request_secrets,
                verbose,
                file_output,
                fallback_ips,
            );
        }
        Commands::Receive {
            authorized_ips,
            server,
            port,
            password,
            secrets,
            verbose,
        } => {
            let secrets_map: HashMap<String, String> = secrets
                .into_iter()
                .flat_map(|s| {
                    s.split(',')
                        .map(|part| {
                            let mut parts = part.splitn(2, '=');
                            let key = parts.next().unwrap_or("").trim().to_string();
                            let value = parts.next().unwrap_or("").trim().to_string();
                            (key, value)
                        })
                        .collect::<Vec<(String, String)>>()
                })
                .collect();
            println!("{:?}", secrets_map);
            start_server(server, port, password, secrets_map, verbose, authorized_ips);
        }
    }
}
