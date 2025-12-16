//! `hypr exec` command for executing commands in running VMs.

use anyhow::Result;
use hypr_core::exec::ExecClient;
use hypr_core::VmStatus;

use crate::client::HyprClient;

/// Execute a command in a running VM.
///
/// # Arguments
/// * `vm` - VM ID or name
/// * `cmd` - Command to execute
/// * `interactive` - Whether to run interactively with TTY
/// * `env` - Environment variables
pub async fn exec(
    vm: &str,
    cmd: &str,
    interactive: bool,
    env: Vec<(String, String)>,
) -> Result<i32> {
    // Connect to daemon to get VM info
    let mut client = HyprClient::connect().await?;
    let vms = client.list_vms().await?;

    // Find VM by ID or name
    let vm_info = vms
        .iter()
        .find(|v| v.id == vm || v.name == vm)
        .ok_or_else(|| anyhow::anyhow!("VM not found: {}", vm))?;

    // Check VM is running
    if vm_info.status != VmStatus::Running {
        return Err(anyhow::anyhow!(
            "VM '{}' is not running (status: {:?}). Cannot exec into a {} VM.",
            vm_info.name,
            vm_info.status,
            format!("{:?}", vm_info.status).to_lowercase()
        ));
    }

    // Try multiple vsock paths (different adapters use different locations)
    let vsock_paths = [
        // libkrun path
        hypr_core::paths::runtime_dir().join("krun").join(format!("{}.vsock", vm_info.id)),
        // cloud-hypervisor path
        hypr_core::paths::runtime_dir().join("ch").join(format!("{}.vsock", vm_info.id)),
    ];

    // Execute command
    let vsock_path = vsock_paths
        .iter()
        .find(|p| p.exists())
        .ok_or_else(|| anyhow::anyhow!("Exec socket not found for VM {}", vm_info.name))?;

    let mut exec_client = ExecClient::new(vsock_path);
    let exit_code = if interactive {
        setup_terminal()?;
        let result = exec_client.exec_interactive(cmd, env).await;
        restore_terminal()?;
        result?
    } else {
        exec_client.exec(cmd, env).await?
    };

    Ok(exit_code)
}

/// Set up terminal for raw mode (interactive sessions).
fn setup_terminal() -> Result<()> {
    // Use stty for simplicity - works on all Unix systems
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("stty").args(["-icanon", "-echo", "raw"]).status();
    }
    Ok(())
}

/// Restore terminal to normal mode.
fn restore_terminal() -> Result<()> {
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("stty").arg("sane").status();
    }
    Ok(())
}
