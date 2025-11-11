use anyhow::Result;
use clap::{Parser, Subcommand};

mod client;
mod commands;

#[derive(Parser)]
#[command(name = "hypr")]
#[command(about = "HYPR microVM orchestration CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a VM from an image
    Run {
        /// Image name (e.g., "nginx", "redis")
        image: String,

        /// VM name (optional)
        #[arg(short, long)]
        name: Option<String>,

        /// Number of CPUs
        #[arg(short, long)]
        cpus: Option<u32>,

        /// Memory in MB
        #[arg(short, long)]
        memory: Option<u32>,

        /// Port mappings (HOST:GUEST)
        #[arg(short, long)]
        port: Vec<String>,

        /// Environment variables (KEY=VALUE)
        #[arg(short, long)]
        env: Vec<String>,
    },

    /// List all VMs
    Ps,

    /// Start a VM
    Start {
        /// VM ID or name
        vm: String,
    },

    /// Stop a VM
    Stop {
        /// VM ID or name
        vm: String,

        /// Timeout in seconds
        #[arg(short, long, default_value = "30")]
        timeout: u32,
    },

    /// Delete a VM
    Rm {
        /// VM ID or name
        vm: String,

        /// Force delete even if running
        #[arg(short, long)]
        force: bool,
    },

    /// List images
    Images,

    /// Check daemon health
    Health,

    /// Manage stacks with compose files
    #[command(subcommand)]
    Compose(ComposeCommands),
}

#[derive(Subcommand)]
enum ComposeCommands {
    /// Deploy a stack from docker-compose.yml
    Up {
        /// Path to docker-compose.yml
        #[arg(short, long)]
        file: String,

        /// Stack name (optional, defaults to directory name)
        #[arg(short, long)]
        name: Option<String>,

        /// Run in background
        #[arg(short, long)]
        detach: bool,

        /// Force recreate even if exists
        #[arg(long)]
        force_recreate: bool,

        /// Build images before deploying
        #[arg(long)]
        build: bool,
    },

    /// Destroy a stack
    Down {
        /// Stack name
        stack_name: String,

        /// Force destroy without confirmation
        #[arg(short, long)]
        force: bool,
    },

    /// List all stacks or show details of specific stack
    Ps {
        /// Stack name (optional)
        stack_name: Option<String>,
    },

    /// Show logs for a service (stub for Phase 3)
    Logs {
        /// Service name
        service_name: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, name, cpus, memory, port, env } => {
            // Parse ports
            let ports: Vec<(u16, u16)> = port
                .iter()
                .map(|p| {
                    let parts: Vec<&str> = p.split(':').collect();
                    if parts.len() != 2 {
                        return Err(anyhow::anyhow!("Invalid port format: {}", p));
                    }
                    let host: u16 = parts[0].parse()?;
                    let guest: u16 = parts[1].parse()?;
                    Ok((host, guest))
                })
                .collect::<Result<Vec<_>>>()?;

            // Parse env vars
            let env_vars: Vec<(String, String)> = env
                .iter()
                .map(|e| {
                    let parts: Vec<&str> = e.splitn(2, '=').collect();
                    if parts.len() != 2 {
                        return Err(anyhow::anyhow!("Invalid env format: {}", e));
                    }
                    Ok((parts[0].to_string(), parts[1].to_string()))
                })
                .collect::<Result<Vec<_>>>()?;

            commands::run(&image, name, cpus, memory, ports, env_vars).await?;
        }

        Commands::Ps => {
            commands::ps().await?;
        }

        Commands::Start { vm } => {
            let mut client = client::HyprClient::connect().await?;
            let vm = client.start_vm(&vm).await?;
            println!("VM started: {}", vm.name);
        }

        Commands::Stop { vm, timeout } => {
            let mut client = client::HyprClient::connect().await?;
            let vm = client.stop_vm(&vm, Some(timeout)).await?;
            println!("VM stopped: {}", vm.name);
        }

        Commands::Rm { vm, force } => {
            let mut client = client::HyprClient::connect().await?;
            let success = client.delete_vm(&vm, force).await?;
            if success {
                println!("VM deleted: {}", vm);
            }
        }

        Commands::Images => {
            let mut client = client::HyprClient::connect().await?;
            let images = client.list_images().await?;

            if images.is_empty() {
                println!("No images available");
            } else {
                for image in images {
                    let size_mb = image.size_bytes as f64 / 1024.0 / 1024.0;
                    println!("{:<20} {:<10} {:.1} MB", image.name, image.tag, size_mb);
                }
            }
        }

        Commands::Health => {
            let mut client = client::HyprClient::connect().await?;
            let (status, version) = client.health().await?;
            println!("Status: {}", status);
            println!("Version: {}", version);
        }

        Commands::Compose(compose_cmd) => match compose_cmd {
            ComposeCommands::Up { file, name, detach, force_recreate, build } => {
                commands::compose::up(&file, name, detach, force_recreate, build).await?;
            }

            ComposeCommands::Down { stack_name, force } => {
                commands::compose::down(&stack_name, force).await?;
            }

            ComposeCommands::Ps { stack_name } => {
                commands::compose::ps(stack_name.as_deref()).await?;
            }

            ComposeCommands::Logs { service_name } => {
                commands::compose::logs(&service_name).await?;
            }
        },
    }

    Ok(())
}
