//! `hypr ps` command

use crate::client::HyprClient;
use anyhow::Result;
use tabled::{settings::Style, Table, Tabled};

#[derive(Tabled)]
struct VmRow {
    #[tabled(rename = "ID")]
    id: String,
    #[tabled(rename = "NAME")]
    name: String,
    #[tabled(rename = "IMAGE")]
    image: String,
    #[tabled(rename = "STATUS")]
    status: String,
    #[tabled(rename = "IP")]
    ip: String,
    #[tabled(rename = "CPUS")]
    cpus: u32,
    #[tabled(rename = "MEMORY")]
    memory: String,
}

/// List all VMs
pub async fn ps() -> Result<()> {
    let mut client = HyprClient::connect().await?;

    let vms = client.list_vms().await?;

    if vms.is_empty() {
        println!("No VMs running");
        return Ok(());
    }

    let rows: Vec<VmRow> = vms
        .into_iter()
        .map(|vm| VmRow {
            id: vm.id[..8].to_string(),
            name: vm.name,
            image: vm.image_id,
            status: vm.status.to_string(),
            ip: vm.ip_address.unwrap_or_else(|| "-".to_string()),
            cpus: vm.config.resources.cpus,
            memory: format!("{}M", vm.config.resources.memory_mb),
        })
        .collect();

    let mut table = Table::new(rows);
    table.with(Style::modern());

    println!("{}", table);

    Ok(())
}
