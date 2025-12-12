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

        /// Enable GPU passthrough.
        /// Linux: Specify PCI address (e.g., --gpu 0000:01:00.0)
        /// macOS ARM64: Use --gpu to enable Metal GPU (no address needed)
        #[arg(short, long)]
        gpu: Option<Option<String>>,
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

    /// Build an image from a Dockerfile
    Build {
        /// Path to build context directory
        #[arg(default_value = ".")]
        path: String,

        /// Name and tag for the image (e.g., "myapp:latest")
        #[arg(short, long)]
        tag: Option<String>,

        /// Path to Dockerfile (relative to context)
        #[arg(short, long, default_value = "Dockerfile")]
        file: String,

        /// Build argument (KEY=VALUE)
        #[arg(long)]
        build_arg: Vec<String>,

        /// Target build stage (for multi-stage builds)
        #[arg(long)]
        target: Option<String>,

        /// Disable build cache
        #[arg(long)]
        no_cache: bool,
    },

    /// List images
    Images,

    /// Pull an image from a registry
    Pull {
        /// Image name (e.g., "nginx", "nginx:1.25", "ghcr.io/org/repo:tag")
        image: String,
    },

    /// Remove an image
    Rmi {
        /// Image name or ID
        image: String,

        /// Force removal
        #[arg(short, long)]
        force: bool,
    },

    /// Image management commands
    #[command(subcommand)]
    Image(ImageCommands),

    /// Stream logs from a VM
    Logs {
        /// VM ID or name
        vm: String,

        /// Follow log output (like tail -f)
        #[arg(short, long)]
        follow: bool,

        /// Number of lines to show from end (default: all)
        #[arg(short, long, default_value = "0")]
        tail: u32,
    },

    /// Check daemon health
    Health,

    /// Execute a command in a running VM
    Exec {
        /// VM ID or name
        vm: String,

        /// Command to execute
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,

        /// Run interactively with TTY allocation
        #[arg(short = 'i', long)]
        interactive: bool,

        /// Run with TTY allocation (same as -i)
        #[arg(short = 't', long)]
        tty: bool,

        /// Environment variable (KEY=VALUE)
        #[arg(short, long)]
        env: Vec<String>,
    },

    /// Manage stacks with compose files
    #[command(subcommand)]
    Compose(ComposeCommands),

    /// GPU management commands
    #[command(subcommand)]
    Gpu(GpuCommands),

    /// System maintenance commands
    #[command(subcommand)]
    System(SystemCommands),

    /// Volume management commands
    #[command(subcommand)]
    Volume(VolumeCommands),

    /// Network management commands
    #[command(subcommand)]
    Network(NetworkCommands),
}

#[derive(Subcommand)]
enum VolumeCommands {
    /// List volumes
    Ls,

    /// Create a volume
    Create {
        /// Volume name
        name: String,
    },

    /// Remove a volume
    Rm {
        /// Volume name
        name: String,

        /// Force removal (don't check if in use)
        #[arg(short, long)]
        force: bool,
    },

    /// Display detailed information on a volume
    Inspect {
        /// Volume name
        name: String,
    },

    /// Remove all unused local volumes
    Prune {
        /// Do not prompt for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum NetworkCommands {
    /// List networks
    Ls,

    /// Create a network
    Create {
        /// Network name
        name: String,

        /// Subnet in CIDR notation (e.g., 10.89.0.0/16)
        #[arg(long)]
        subnet: Option<String>,

        /// Gateway IP address
        #[arg(long)]
        gateway: Option<String>,

        /// Network driver (default: bridge)
        #[arg(short, long, default_value = "bridge")]
        driver: String,
    },

    /// Remove a network
    Rm {
        /// Network name
        name: String,

        /// Force removal (don't check if in use)
        #[arg(short, long)]
        force: bool,
    },

    /// Display detailed information on a network
    Inspect {
        /// Network name
        name: String,
    },

    /// Remove all unused networks
    Prune {
        /// Do not prompt for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ImageCommands {
    /// List images
    Ls,

    /// Pull an image from registry
    Pull {
        /// Image name (e.g., "nginx", "nginx:1.25", "ghcr.io/org/repo:tag")
        image: String,
    },

    /// Remove an image
    Rm {
        /// Image name or ID
        image: String,

        /// Force removal
        #[arg(short, long)]
        force: bool,
    },

    /// Display detailed information on an image
    Inspect {
        /// Image name or ID
        image: String,
    },

    /// Remove unused images
    Prune {
        /// Remove all unused images, not just dangling ones
        #[arg(short, long)]
        all: bool,

        /// Do not prompt for confirmation
        #[arg(short, long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum ComposeCommands {
    /// Deploy a stack from docker-compose.yml
    Up {
        /// Path to docker-compose.yml (defaults to docker-compose.yml or compose.yml)
        #[arg(short, long)]
        file: Option<String>,

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

#[derive(Subcommand)]
enum GpuCommands {
    /// List available GPUs on the system
    List,
}

#[derive(Subcommand)]
enum SystemCommands {
    /// Remove unused data (stopped VMs, dangling images, orphaned resources)
    Prune {
        /// Remove all stopped VMs and unused images (not just dangling)
        #[arg(short, long)]
        all: bool,

        /// Do not prompt for confirmation
        #[arg(short, long)]
        force: bool,

        /// Also remove unused volumes
        #[arg(long)]
        volumes: bool,
    },

    /// Show disk usage information
    Df,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing if RUST_LOG is set
    if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .init();
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Run { image, name, cpus, memory, port, env, gpu } => {
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

            // Parse GPU option:
            // --gpu (no value) = auto-detect
            // --gpu=<pci-addr> = specific device
            // (absent) = no GPU
            let gpu_option = gpu.map(|opt| opt.unwrap_or_default());

            commands::run(&image, name, cpus, memory, ports, env_vars, gpu_option).await?;
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

        Commands::Build { path, tag, file, build_arg, target, no_cache } => {
            // Parse build args
            let build_args: Vec<(String, String)> = build_arg
                .iter()
                .map(|arg| {
                    let parts: Vec<&str> = arg.splitn(2, '=').collect();
                    if parts.len() != 2 {
                        return Err(anyhow::anyhow!("Invalid build-arg format: {}", arg));
                    }
                    Ok((parts[0].to_string(), parts[1].to_string()))
                })
                .collect::<Result<Vec<_>>>()?;

            commands::build::build(
                &path,
                tag.as_deref(),
                &file,
                build_args,
                target.as_deref(),
                no_cache,
            )
            .await?;
        }

        Commands::Images => {
            commands::images().await?;
        }

        Commands::Pull { image } => {
            commands::pull(&image).await?;
        }

        Commands::Rmi { image, force } => {
            let mut client = client::HyprClient::connect().await?;
            let success = client.delete_image(&image, force).await?;
            if success {
                println!("Deleted: {}", image);
            }
        }

        Commands::Image(image_cmd) => match image_cmd {
            ImageCommands::Ls => {
                commands::images().await?;
            }
            ImageCommands::Pull { image } => {
                commands::pull(&image).await?;
            }
            ImageCommands::Rm { image, force } => {
                let mut client = client::HyprClient::connect().await?;
                let success = client.delete_image(&image, force).await?;
                if success {
                    println!("Deleted: {}", image);
                }
            }
            ImageCommands::Inspect { image } => {
                commands::image::inspect(&image).await?;
            }
            ImageCommands::Prune { all, force } => {
                commands::image::prune(all, force).await?;
            }
        },

        Commands::Logs { vm, follow, tail } => {
            commands::logs(&vm, follow, tail).await?;
        }

        Commands::Health => {
            let mut client = client::HyprClient::connect().await?;
            let (status, version) = client.health().await?;
            println!("Status: {}", status);
            println!("Version: {}", version);
        }

        Commands::Exec { vm, command, interactive, tty, env } => {
            // Join command parts into a single string
            let cmd = if command.is_empty() { "/bin/sh".to_string() } else { command.join(" ") };

            // Parse env vars
            let env_vars: Vec<(String, String)> = env
                .iter()
                .filter_map(|e| {
                    let parts: Vec<&str> = e.splitn(2, '=').collect();
                    if parts.len() == 2 {
                        Some((parts[0].to_string(), parts[1].to_string()))
                    } else {
                        eprintln!("Warning: Invalid env format: {}", e);
                        None
                    }
                })
                .collect();

            // -i or -t enables interactive mode
            let is_interactive = interactive || tty;

            let exit_code = commands::exec::exec(&vm, &cmd, is_interactive, env_vars).await?;
            std::process::exit(exit_code);
        }

        Commands::Compose(compose_cmd) => match compose_cmd {
            ComposeCommands::Up { file, name, detach, force_recreate, build } => {
                // Find compose file: use provided path or search for defaults
                // Supports Docker-compatible and Hypr-specific file names
                let compose_file = match file {
                    Some(f) => f,
                    None => {
                        // Try compose file names in priority order (hypr-specific first, then Docker-compatible)
                        let candidates = [
                            "hypr-compose.yml",
                            "hypr-compose.yaml",
                            "Hyprfile",
                            "Hyprfile.yml",
                            "Hyprfile.yaml",
                            "docker-compose.yml",
                            "docker-compose.yaml",
                            "compose.yml",
                            "compose.yaml",
                        ];
                        candidates
                            .iter()
                            .find(|f| std::path::Path::new(f).exists())
                            .map(|s| s.to_string())
                            .ok_or_else(|| {
                                anyhow::anyhow!(
                                    "No compose file found. Tried: {}. Use --file to specify.",
                                    candidates.join(", ")
                                )
                            })?
                    }
                };

                // Convert to absolute path (daemon runs in different working directory)
                let compose_path = std::path::Path::new(&compose_file);
                let absolute_path = if compose_path.is_absolute() {
                    compose_file.clone()
                } else {
                    std::env::current_dir()
                        .map_err(|e| anyhow::anyhow!("Failed to get current directory: {}", e))?
                        .join(&compose_file)
                        .to_string_lossy()
                        .to_string()
                };

                commands::compose::up(&absolute_path, name, detach, force_recreate, build).await?;
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

        Commands::Gpu(gpu_cmd) => match gpu_cmd {
            GpuCommands::List => {
                commands::gpu::list()?;
            }
        },

        Commands::System(system_cmd) => match system_cmd {
            SystemCommands::Prune { all, force, volumes } => {
                commands::system::prune(all, force, volumes).await?;
            }
            SystemCommands::Df => {
                commands::system::df().await?;
            }
        },

        Commands::Volume(volume_cmd) => match volume_cmd {
            VolumeCommands::Ls => {
                commands::volume::ls().await?;
            }
            VolumeCommands::Create { name } => {
                commands::volume::create(&name).await?;
            }
            VolumeCommands::Rm { name, force } => {
                commands::volume::rm(&name, force).await?;
            }
            VolumeCommands::Inspect { name } => {
                commands::volume::inspect(&name).await?;
            }
            VolumeCommands::Prune { force } => {
                commands::volume::prune(force).await?;
            }
        },

        Commands::Network(network_cmd) => match network_cmd {
            NetworkCommands::Ls => {
                commands::network::ls().await?;
            }
            NetworkCommands::Create { name, subnet, gateway, driver } => {
                commands::network::create(&name, subnet.as_deref(), gateway.as_deref(), &driver)
                    .await?;
            }
            NetworkCommands::Rm { name, force } => {
                commands::network::rm(&name, force).await?;
            }
            NetworkCommands::Inspect { name } => {
                commands::network::inspect(&name).await?;
            }
            NetworkCommands::Prune { force } => {
                commands::network::prune(force).await?;
            }
        },
    }

    Ok(())
}
