// TODO: USE PASSWORD LIBRARY AND HASH MATCHING TO PREVENT TIMING ATTACKS

use clap::{Parser, Subcommand};
use ipnetwork::IpNetwork;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, TcpListener, TcpStream};

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
    },

    Receive {
        #[arg(short = 'a', long)]
        authorized_ips: Option<IpNetwork>,

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

fn start_server(ip: IpAddr, port: u16, password: String, secrets: HashMap<String, String>, verbose: bool, authorized_ips: Option<IpNetwork>) {
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
                        let ip_auth = if let Some(subnet) = authorized_ips {
                            subnet.contains(peer_ip)
                        } else {
                            true
                        };

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

fn send_request(ip: IpAddr, port: u16, password: String, request_secrets: String, verbose: bool) {
    let mut stream = TcpStream::connect((ip, port)).expect("Failed to connect to server");
    let message = format!("{} {}", password.trim(), request_secrets.trim());
    stream.write_all(message.as_bytes()).expect("Failed to send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("Failed to read response");
    println!("{}", response);
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Send {
            server, port, password, request_secrets, verbose,
        } => {
            send_request(server, port, password, request_secrets, verbose);
        }
        Commands::Receive {
            authorized_ips, server, port, password, secrets, verbose,
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
