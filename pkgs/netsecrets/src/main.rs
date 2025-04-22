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
        .map(|s| s.split(',').filter_map(|ip| ip.trim().parse().ok()).collect())
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

    for stream in listener.incoming() {
        if let Ok(mut stream) = stream {
            let peer_ip = stream.peer_addr().unwrap().ip();
            let mut buffer = [0; 1024];

            if let Ok(size) = stream.read(&mut buffer) {
                let request = String::from_utf8_lossy(&buffer[..size]);
                let mut parts = request.split_whitespace();
                let req_password = parts.next().unwrap_or("");
                let requested = parts.next().unwrap_or("");

                if verbose {
                    println!("Authentication attempt from {} with password='{}'", peer_ip, req_password);
                }

                let password_ok = password.is_empty() || req_password == password;
                let ip_ok = authorized_ips.is_empty() || authorized_ips.iter().any(|net| net.contains(peer_ip));

                if verbose {
                    println!("Authentication {}", if password_ok && ip_ok { "succeeded" } else { "failed" });
                }

                if password_ok && ip_ok {
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
                    let response = response_parts.join(",");
                    let _ = stream.write_all(response.as_bytes());
                } else {
                    let msg = match (password_ok, ip_ok) {
                        (false, false) => "Invalid password and IP",
                        (false, _) => "Invalid password",
                        (_, false) => "Invalid IP",
                        _ => "",
                    };
                    let _ = stream.write_all(msg.as_bytes());
                }
            }
        }
    }
}

fn query_fallback(ip: IpAddr, port: u16, password: &str, secret: &str, verbose: bool) -> Option<String> {
    let socket = SocketAddr::new(ip, port);
    if verbose {
        println!("Querying fallback {} for {}", ip, secret);
    }
    if let Ok(mut stream) = TcpStream::connect_timeout(&socket, Duration::from_secs(5)) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let message = format!("{} {}", password, secret);
        if stream.write_all(message.as_bytes()).is_err() {
            if verbose { eprintln!("Fallback write error"); }
            return None;
        }
        let mut response = String::new();
        if stream.read_to_string(&mut response).is_ok() {
            let val = response.splitn(2, '=').nth(1).unwrap_or("").trim();
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
                    if let Ok(s) = TcpStream::connect_timeout(&SocketAddr::new(ip, port), Duration::from_secs(5)) {
                        if verbose { println!("Connected to fallback {}", ip); }
                        return send_request(ip, port, password, request_secrets, verbose, file_output, fallbacks);
                    }
                }
            }
            panic!("Failed to connect to any server");
        }
    };

    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let message = format!("{} {}", password, request_secrets);
    let _ = stream.write_all(message.as_bytes());

    let mut response = String::new();
    let mut secrets = HashMap::new();
    if stream.read_to_string(&mut response).is_ok() {
        for part in response.split(',') {
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
                if let Some(val) = query_fallback(ip, port, &password, &name, verbose) {
                    secrets.insert(name.clone(), val);
                    break;
                }
            }
        }
    }

    if verbose {
        for name in request_secrets.split(',').filter(|s| !s.is_empty()) {
            match secrets.get(name) {
                Some(val) => println!("Retrieved secret: {}={}", name, val),
                None => println!("Failed to retrieve secret: {}", name),
            }
        }
    }

    if let Some(path) = file_output {
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
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Send { server, port, password, request_secrets, verbose, file_output, fallbacks } => {
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password");
            let request = get_env_var_or_required_arg("NETSECRETS_REQUEST_SECRETS", request_secrets, "request_secrets");
            let ips = parse_fallbacks(fallbacks);
            send_request(server, port, password, request, verbose, file_output, ips);
        }
        Commands::Receive { authorized_ips, server, password, port, secrets, verbose } => {
            let server = get_env_var_or_required_arg("NETSECRETS_SERVER", server, "server");
            let port = get_env_var_or_arg("NETSECRETS_PORT", port).unwrap_or(8080);
            let password = get_env_var_or_required_arg("NETSECRETS_PASSWORD", password, "password");
            let mut map = HashMap::new();
            for s in secrets {
                let mut parts = s.splitn(2, '=');
                if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
                    map.insert(k.to_string(), v.to_string());
                }
            }
            start_server(server, port, password, map, verbose, authorized_ips);
        }
    }
}
