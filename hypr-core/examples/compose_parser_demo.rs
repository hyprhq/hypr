//! Example demonstrating the Compose parser.

use hypr_core::compose::{ComposeParser, Environment};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== HYPR Compose Parser Demo ===\n");

    // Example 1: Basic compose file
    println!("Example 1: Basic single-service compose file");
    let yaml1 = r#"
version: "3"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    environment:
      - ENV=production
      - DEBUG=false
"#;

    let compose1 = ComposeParser::parse(yaml1)?;
    println!("Version: {}", compose1.version);
    println!("Services: {}", compose1.services.len());
    for (name, service) in &compose1.services {
        println!("  - {}: {}", name, service.image);
        println!("    Ports: {:?}", service.ports);
        println!("    Environment: {:?}", service.environment.to_map());
    }
    println!();

    // Example 2: Multi-service with resources
    println!("Example 2: Multi-service with resources and dependencies");
    let yaml2 = r#"
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    depends_on:
      - db
    networks:
      - frontend

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
      POSTGRES_DB: myapp
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: "2G"
    volumes:
      - db-data:/var/lib/postgresql/data
    networks:
      - backend

volumes:
  db-data:

networks:
  frontend:
  backend:
"#;

    let compose2 = ComposeParser::parse(yaml2)?;
    println!("Version: {}", compose2.version);
    println!("Services: {}", compose2.services.len());
    println!("Volumes: {}", compose2.volumes.len());
    println!("Networks: {}", compose2.networks.len());
    println!();

    for (name, service) in &compose2.services {
        println!("Service: {}", name);
        println!("  Image: {}", service.image);
        if !service.depends_on.is_empty() {
            println!("  Depends on: {:?}", service.depends_on);
        }
        if !service.networks.is_empty() {
            println!("  Networks: {:?}", service.networks);
        }
        if let Some(deploy) = &service.deploy {
            if let Some(resources) = &deploy.resources {
                if let Some(cpu) = resources.get_cpu_limit() {
                    println!("  CPU limit: {} cores", cpu);
                }
                if let Some(memory) = resources.get_memory_mb() {
                    println!("  Memory limit: {} MB", memory);
                }
            }
        }
        if let Environment::Map(env) = &service.environment {
            if !env.is_empty() {
                println!("  Environment:");
                for (key, value) in env {
                    println!("    {}: {}", key, value);
                }
            }
        }
        println!();
    }

    // Example 3: Parse from file
    println!("Example 3: Parsing from fixture files");
    let fixtures = [
        "hypr-core/src/compose/tests/fixtures/basic.yml",
        "hypr-core/src/compose/tests/fixtures/multi-service.yml",
        "hypr-core/src/compose/tests/fixtures/resources.yml",
    ];

    for fixture in &fixtures {
        match ComposeParser::parse_file(fixture) {
            Ok(compose) => {
                println!("Parsed {}: {} services", fixture, compose.services.len());
            }
            Err(e) => {
                println!("Could not parse {} (file may not exist): {}", fixture, e);
            }
        }
    }

    println!("\n=== Demo Complete ===");
    Ok(())
}
