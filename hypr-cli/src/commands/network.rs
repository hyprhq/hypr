//! Network management commands for HYPR CLI.
//!
//! Provides Docker-compatible network management:
//! - hypr network ls
//! - hypr network create
//! - hypr network rm
//! - hypr network inspect
//! - hypr network prune

use crate::client::HyprClient;
use anyhow::Result;
use tabled::{Table, Tabled};

/// List all networks
pub async fn ls() -> Result<()> {
    let mut client = HyprClient::connect().await?;

    let networks = client.list_networks().await?;

    if networks.is_empty() {
        println!("No networks found.");
        return Ok(());
    }

    #[derive(Tabled)]
    struct NetworkRow {
        #[tabled(rename = "NETWORK ID")]
        id: String,
        #[tabled(rename = "NAME")]
        name: String,
        #[tabled(rename = "DRIVER")]
        driver: String,
        #[tabled(rename = "SCOPE")]
        scope: String,
    }

    let rows: Vec<NetworkRow> = networks
        .into_iter()
        .map(|n| NetworkRow {
            id: if n.id.len() > 12 { n.id[..12].to_string() } else { n.id },
            name: n.name,
            driver: n.driver,
            scope: "local".to_string(),
        })
        .collect();

    let table = Table::new(rows).to_string();
    println!("{}", table);

    Ok(())
}

/// Create a new network
pub async fn create(
    name: &str,
    subnet: Option<&str>,
    gateway: Option<&str>,
    driver: &str,
) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    let network = client.create_network(name, subnet, gateway, driver).await?;

    println!("{}", network.id);
    Ok(())
}

/// Remove a network
pub async fn rm(name: &str, force: bool) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    client.delete_network(name, force).await?;

    println!("{}", name);
    Ok(())
}

/// Display detailed information on a network
pub async fn inspect(name: &str) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    let network = client.get_network(name).await?;

    // Output JSON-like format similar to Docker
    println!("[");
    println!("    {{");
    println!("        \"Name\": \"{}\",", network.name);
    println!("        \"Id\": \"{}\",", network.id);
    println!("        \"Created\": \"{}\",", format_timestamp(network.created_at));
    println!("        \"Scope\": \"local\",");
    println!("        \"Driver\": \"{}\",", network.driver);
    println!("        \"IPAM\": {{");
    println!("            \"Driver\": \"default\",");
    println!("            \"Config\": [");
    println!("                {{");
    println!("                    \"Subnet\": \"{}\",", network.cidr);
    println!("                    \"Gateway\": \"{}\"", network.gateway);
    println!("                }}");
    println!("            ]");
    println!("        }},");
    println!("        \"Internal\": false,");
    println!("        \"Attachable\": false,");
    println!("        \"Options\": {{");
    println!("            \"com.docker.network.bridge.name\": \"{}\"", network.bridge_name);
    println!("        }}");
    println!("    }}");
    println!("]");

    Ok(())
}

/// Remove all unused networks
pub async fn prune(force: bool) -> Result<()> {
    if !force {
        print!("WARNING! This will remove all custom networks not used by at least one container.\nAre you sure you want to continue? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let mut client = HyprClient::connect().await?;

    let networks = client.list_networks().await?;

    let mut removed = Vec::new();

    // Only prune custom networks (not the default "bridge" network)
    for network in networks {
        if network.name == "bridge" || network.name == "default" {
            continue;
        }

        // Try to delete - will fail if in use
        match client.delete_network(&network.name, false).await {
            Ok(_) => {
                removed.push(network.name);
            }
            Err(_) => {
                // Network is in use, skip
            }
        }
    }

    if removed.is_empty() {
        println!("No unused networks to remove.");
    } else {
        println!("Deleted Networks:");
        for name in &removed {
            println!("{}", name);
        }
    }

    Ok(())
}

fn format_timestamp(ts: i64) -> String {
    if ts == 0 {
        return "N/A (system default)".to_string();
    }

    use std::time::{Duration, UNIX_EPOCH};
    let datetime = UNIX_EPOCH + Duration::from_secs(ts as u64);

    // Simple ISO-like format
    format!("{:?}", datetime)
}
