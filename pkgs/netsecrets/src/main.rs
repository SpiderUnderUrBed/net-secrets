use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Parser)]
#[command(name = "netsecrets")]
#[command(about = "A Rust CLI for secure secret sharing")]
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
        #[arg(short = 'r', long = "request_secrets")]
        request_secrets: Option<String>,
        #[arg(short = 'v', long)]
        verbose: bool,
        #[arg(long = "file-output", alias = "output")]
        file_output: Option<String>,
        #[arg(long = "fallbacks")]
        fallbacks: Option<String>,
    },
    Receive {
        #[arg(short = 'a', long, value_delimiter = ',')]
        authorized_ips: Vec<IpNetwork>,
        #[arg(short, long)]
        server: Option<IpAddr>,
        #[arg(short = 'P', long)]
        password: Option<String>,
        #[arg(short, long)]
        port: Option<u16>,
        #[arg(short = 'S', long)]
        secrets: Vec<String>,
        #[arg(short = 'v', long)]
        verbose: bool,
    },
}

fn get_env_var_or_arg<T: std::str::FromStr>(env_var: &str, arg: Option<T>) -> Option<T> {
    arg.or_else(|| env::var(env_var).ok().and_then(|s| s.parse().ok()))
}

fn get_env_var_or_required_arg<T: std::str::FromStr>(env_var: &str, arg: Option<T>, field_name: &str) -> T {
    get_env_var_or_arg(env_var, arg).unwrap_or_else(|| {
        panic!("{} must be provided either as argument or through {}", field_name, env_var)
    })
}

fn parse_fallbacks(fallbacks: Option<String>) -> Option<Vec<IpAddr>> {
    fallbacks
        .or_else(|| env::var("NETSECRETS_FALLBACKS").ok())
        .map(|s| {
            s.split(',')
                .filter_map(|ip_str| ip_str.trim().parse().ok())
                .collect()
        })
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
    }

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                let peer_ip = stream.peer_addr().unwrap().ip();
                let mut buffer = [0; 1024];
                
                match stream.read(&mut buffer) {
                    Ok(size) => {
                        let request = String::from_utf8_lossy(&buffer[..size]);
                        if verbose {
                            println!("Request from {}: {}", peer_ip, request);
                        }

                        let mut parts = request.split_whitespace();
                        let req_password = parts.next().unwrap_or("");
                        let requested_secrets = parts.next().unwrap_or("");

                        let password_ok = password.is_empty() || req_password == password;
                        let ip_ok = authorized_ips.is_empty() || 
                            authorized_ips.iter().any(|net| net.contains(peer_ip));

                        if password_ok && ip_ok {
                            let response = requested_secrets.split(',')
                                .filter(|s| !s.is_empty())
                                .map(|name| {
                                    secrets.get(name)
                                        .map(|val| format!("{}={}", name, val))
                                        .unwrap_or_else(|| format!("{}=Secret not found", name))
                                })
                                .collect::<Vec<_>>()
                                .join(",");
                            
                            stream.write_all(response.as_bytes()).unwrap();
                        } else {
                            let msg = match (password_ok, ip_ok) {
                                (false, false) => "Invalid password and IP",
                                (false, _) => "Invalid password",
                                (_, false) => "Invalid IP",
                                _ => "",
                            };
                            stream.write_all(msg.as_bytes()).unwrap();
                        }
                    }
                    Err(e) => eprintln!("Read error: {}", e),
                }
            }
            Err(e) => eprintln!("Connection error: {}", e),
        }
    }
}

fn query_fallback(ip: IpAddr, port: u16, password: &str, secret: &str, verbose: bool) -> Option<String> {
    let socket = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
            let message = format!("{} {}", password, secret);
            
            if verbose {
                println!("Querying fallback {} for {}", ip, secret);
            }

            if let Err(e) = stream.write_all(message.as_bytes()) {
                if verbose { eprintln!("Fallback write error: {}", e); }
                return None;
            }

            let mut response = String::new();
            match stream.read_to_string(&mut response) {
                Ok(_) => response.splitn(2, '=')
                    .nth(1)
                    .map(|s| s.trim().to_string())
                    .filter(|s| s != "Secret not found"),
                Err(e) => {
                    if verbose { eprintln!("Fallback read error: {}", e); }
                    None
                }
            }
        }
        Err(e) => {
            if verbose { eprintln!("Fallback connect error: {}", e); }
            None
        }
    }
}

fn is_directory(path: &Path) -> bool {
    if path.exists() {
        path.is_dir()
    } else {
        let path_str = path.to_str().unwrap_or("");
        path_str.ends_with('/') || path_str.ends_with(std::path::MAIN_SEPARATOR)
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
) {
    let socket = SocketAddr::new(server, port);
    let mut stream = match TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        Ok(s) => s,
        Err(e) => {
            if verbose {
                println!("Primary server failed: {}", e);
            }
            if let Some(fallback_ips) = &fallbacks {
                for &ip in fallback_ips {
                    let fallback_socket = SocketAddr::new(ip, port);
                    match TcpStream::connect_timeout(&fallback_socket, Duration::from_secs(5)) {
                        Ok(s) => {
                            if verbose {
                                println!("Connected to fallback {}", ip);
                            }
                            return send_request(ip, port, password, request_secrets, verbose, file_output, fallbacks);
                        }
                        Err(e) => {
                            if verbose {
                                println!("Fallback {} failed: {}", ip, e);
                            }
                        }
                    }
                }
            }
            panic!("Failed to connect to any server");
        }
    };

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let message = format!("{} {}", password, request_secrets);
    stream.write_all(message.as_bytes()).expect("Failed to send request");

    let mut response = String::new();
    let mut secrets = HashMap::new();
    
    match stream.read_to_string(&mut response) {
        Ok(_) => {
            for part in response.split(',') {
                let mut kv = part.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    secrets.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        Err(e) => {
            if verbose {
                println!("Read failed: {}", e);
            }
        }
    }

    if let Some(fallback_ips) = fallbacks {
        let missing: Vec<_> = request_secrets.split(',')
            .filter(|name| !secrets.contains_key(*name))
            .collect();

        for name in missing {
            for &ip in &fallback_ips {
                if let Some(value) = query_fallback(ip, port, &password, name, verbose) {
                    secrets.insert(name.to_string(), value);
                    break;
                }
            }
        }
    }

    if verbose {
        println!("Received secrets: {:?}", secrets);
    }

    if let Some(output_path) = file_output {
        let output_path = PathBuf::from(output_path);
        
        if is_directory(&output_path) {
            fs::create_dir_all(&output_path).unwrap_or_else(|e| {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    panic!("Failed to create output directory: {}", e);
                }
            });
            
            for (name, value) in secrets {
                let secret_path = output_path.join(name);
                let mut file = fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(&secret_path)
                    .unwrap_or_else(|e| panic!("Failed to open file {:?}: {}", secret_path, e));
                
                file.write_all(value.as_bytes())
                    .unwrap_or_else(|e| panic!("Failed to write to file {:?}: {}", secret_path, e));
            }
        } else {
            if let Some(parent) = output_path.parent() {
                fs::create_dir_all(parent).unwrap_or_else(|e| {
                    if e.kind() != std::io::ErrorKind::AlreadyExists {
                        panic!("Failed to create parent directory: {}", e);
                    }
                });
            }
            
            let mut file = fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&output_path)
                .unwrap_or_else(|e| panic!("Failed to open file {:?}: {}", output_path, e));
            
            for (_, value) in secrets {
                writeln!(file, "{}", value)
                    .unwrap_or_else(|e| panic!("Failed to write to file {:?}: {}", output_path, e));
            }
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
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password");
            let request_secrets = get_env_var_or_required_arg(
                "NETSECRETS_REQUEST_SECRETS", 
                request_secrets, 
                "request_secrets"
            );
            let fallback_ips = parse_fallbacks(fallbacks);

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
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password");

            let secrets_map: HashMap<_, _> = secrets
                .into_iter()
                .flat_map(|s| s.split(',').map(|s| s.to_string()).collect::<Vec<_>>())
                .filter(|s| !s.is_empty())
                .map(|pair| {
                    let mut kv = pair.splitn(2, '=');
                    (
                        kv.next().unwrap().trim().to_string(),
                        kv.next().unwrap_or("").trim().to_string()
                    )
                })
                .collect();

            start_server(server, port, password, secrets_map, verbose, authorized_ips);
        }
    }
}
