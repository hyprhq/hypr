//! `hypr logs` command - stream VM logs

use crate::client::HyprClient;
use anyhow::Result;
use tokio_stream::StreamExt;

/// Stream logs from a VM
pub async fn logs(vm_id: &str, follow: bool, tail: u32) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Resolve VM ID (could be partial or name)
    let vms = client.list_vms().await?;
    let vm = vms
        .iter()
        .find(|v| v.id.starts_with(vm_id) || v.name == vm_id)
        .ok_or_else(|| anyhow::anyhow!("VM not found: {}", vm_id))?;

    let full_vm_id = vm.id.clone();

    // Stream logs
    let mut stream = client.stream_logs(&full_vm_id, follow, tail).await?;

    while let Some(entry) = stream.next().await {
        match entry {
            Ok(log_entry) => {
                println!("{}", log_entry.line);
            }
            Err(e) => {
                eprintln!("Error receiving log: {}", e);
                break;
            }
        }
    }

    Ok(())
}
