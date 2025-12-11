//! Compose CLI commands for managing stacks.

use crate::client::HyprClient;
use anyhow::{Context, Result};
use colored::Colorize;
use hypr_core::compose::ComposeParser;
use hypr_core::Stack;
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Write};
use std::time::Duration;
use tabled::{settings::Style, Table, Tabled};

/// Deploy a stack from a docker-compose.yml file
pub async fn up(
    compose_file: &str,
    stack_name: Option<String>,
    detach: bool,
    _force_recreate: bool,
    _build: bool,
) -> Result<()> {
    // Parse compose file locally to show what we're deploying
    let compose =
        ComposeParser::parse_file(compose_file).context("Failed to parse compose file")?;

    let service_count = compose.services.len();
    let service_names: Vec<&str> = compose.services.keys().map(|s| s.as_str()).collect();

    println!(
        "{} Deploying {} service(s): {}",
        "→".cyan().bold(),
        service_count,
        service_names.join(", ").dimmed()
    );
    println!();

    // Show each service and its image
    for (name, service) in &compose.services {
        let image = if !service.image.is_empty() {
            &service.image
        } else if service.build.is_some() {
            "(build)"
        } else {
            "(unknown)"
        };
        println!("  {} {} {}", "•".dimmed(), name.bold(), image.dimmed());
    }
    println!();

    let mut client = HyprClient::connect().await?;

    // Show deployment progress
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message("Pulling images and starting VMs (this may take a while)...".to_string());
    spinner.enable_steady_tick(Duration::from_millis(100));

    let stack = client
        .deploy_stack(compose_file, stack_name, detach, false, false)
        .await
        .context("Failed to deploy stack")?;

    spinner.finish_and_clear();

    // Display deployment result
    println!("{} Stack deployed: {}", "✓".green().bold(), stack.name.bold());
    println!();

    // Show services table
    if !stack.services.is_empty() {
        #[derive(Tabled)]
        struct ServiceRow {
            #[tabled(rename = "SERVICE")]
            name: String,
            #[tabled(rename = "VM ID")]
            vm_id: String,
            #[tabled(rename = "STATUS")]
            status: String,
        }

        let rows: Vec<ServiceRow> = stack
            .services
            .iter()
            .map(|s| ServiceRow {
                name: s.name.clone(),
                vm_id: s.vm_id[..8.min(s.vm_id.len())].to_string(),
                status: colorize_status(&s.status),
            })
            .collect();

        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{}", table);
        println!();
    }

    if detach {
        println!("{}", "Stack running in background".dimmed());
    }

    Ok(())
}

/// Destroy a stack
pub async fn down(stack_name: &str, force: bool) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    // Confirm before destroying (unless force)
    if !force {
        print!(
            "{} Are you sure you want to destroy stack '{}'? [y/N]: ",
            "⚠".yellow().bold(),
            stack_name.bold()
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.yellow} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.set_message(format!("Destroying stack '{}'...", stack_name));
    spinner.enable_steady_tick(Duration::from_millis(100));

    let success = client.destroy_stack(stack_name, force).await?;

    spinner.finish_and_clear();

    if success {
        println!("{} Stack destroyed: {}", "✓".green().bold(), stack_name.bold());
    } else {
        println!("{} Failed to destroy stack", "✗".red().bold());
    }

    Ok(())
}

/// List all stacks or show details of specific stack
pub async fn ps(stack_name: Option<&str>) -> Result<()> {
    let mut client = HyprClient::connect().await?;

    if let Some(name) = stack_name {
        // Show specific stack details
        let stack = client.get_stack(name).await?;
        display_stack_details(&stack);
    } else {
        // List all stacks
        let stacks = client.list_stacks().await?;

        if stacks.is_empty() {
            println!("No stacks deployed");
            return Ok(());
        }

        #[derive(Tabled)]
        struct StackRow {
            #[tabled(rename = "STACK NAME")]
            name: String,
            #[tabled(rename = "SERVICES")]
            services: String,
            #[tabled(rename = "STATUS")]
            status: String,
            #[tabled(rename = "CREATED")]
            created: String,
        }

        let rows: Vec<StackRow> = stacks
            .iter()
            .map(|s| {
                let service_count = s.services.len();
                let running = s.services.iter().filter(|svc| svc.status == "running").count();
                let status = if running == service_count {
                    format!("{}/{} running", running, service_count).green().to_string()
                } else if running == 0 {
                    format!("{}/{} stopped", running, service_count).red().to_string()
                } else {
                    format!("{}/{} running", running, service_count).yellow().to_string()
                };

                let elapsed = s.created_at.elapsed().unwrap_or(Duration::from_secs(0));
                let created = format_duration(elapsed);

                StackRow {
                    name: s.name.clone(),
                    services: service_count.to_string(),
                    status,
                    created,
                }
            })
            .collect();

        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{}", table);
    }

    Ok(())
}

/// Show logs for a service in a stack (stub for Phase 3)
pub async fn logs(service_name: &str) -> Result<()> {
    println!("{} Logs functionality will be available in Phase 3", "ℹ".blue().bold());
    println!("Service: {}", service_name.bold());
    println!();
    println!("{}", "For now, you can:".dimmed());
    println!("  {} Use 'hypr ps' to see VM IDs", "•".dimmed());
    println!("  {} SSH into VMs to check application logs", "•".dimmed());

    Ok(())
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Display detailed information about a stack
fn display_stack_details(stack: &Stack) {
    println!("{}", "Stack Details".bold().underline());
    println!();
    println!("{}: {}", "Name".bold(), stack.name);
    println!("{}: {}", "ID".bold(), stack.id);
    if let Some(path) = &stack.compose_path {
        println!("{}: {}", "Compose File".bold(), path);
    }

    let elapsed = stack.created_at.elapsed().unwrap_or(Duration::from_secs(0));
    println!("{}: {} ago", "Created".bold(), format_duration(elapsed));
    println!();

    if !stack.services.is_empty() {
        println!("{}", "Services:".bold());
        println!();

        #[derive(Tabled)]
        struct ServiceRow {
            #[tabled(rename = "SERVICE")]
            name: String,
            #[tabled(rename = "VM ID")]
            vm_id: String,
            #[tabled(rename = "STATUS")]
            status: String,
        }

        let rows: Vec<ServiceRow> = stack
            .services
            .iter()
            .map(|s| ServiceRow {
                name: s.name.clone(),
                vm_id: s.vm_id.clone(),
                status: colorize_status(&s.status),
            })
            .collect();

        let mut table = Table::new(rows);
        table.with(Style::rounded());
        println!("{}", table);
    }
}

/// Colorize status string based on value
fn colorize_status(status: &str) -> String {
    match status {
        "running" => status.green().to_string(),
        "stopped" => status.red().to_string(),
        "failed" => status.red().bold().to_string(),
        "creating" => status.yellow().to_string(),
        _ => status.to_string(),
    }
}

/// Format duration as human-readable string
fn format_duration(duration: Duration) -> String {
    let secs = duration.as_secs();

    if secs < 60 {
        format!("{}s", secs)
    } else if secs < 3600 {
        format!("{}m", secs / 60)
    } else if secs < 86400 {
        format!("{}h", secs / 3600)
    } else {
        format!("{}d", secs / 86400)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(30)), "30s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m");
        assert_eq!(format_duration(Duration::from_secs(3700)), "1h");
        assert_eq!(format_duration(Duration::from_secs(90000)), "1d");
    }

    #[test]
    fn test_colorize_status() {
        // Just test that it doesn't panic
        colorize_status("running");
        colorize_status("stopped");
        colorize_status("failed");
        colorize_status("creating");
        colorize_status("unknown");
    }
}
