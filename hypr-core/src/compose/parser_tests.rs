//! Tests for the Compose parser.

use super::*;

#[test]
fn test_parse_basic_compose() {
    let yaml = r#"
version: "3"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.version, "3");
    assert_eq!(compose.services.len(), 1);
    assert!(compose.services.contains_key("web"));

    let web = &compose.services["web"];
    assert_eq!(web.image, "nginx:latest");
    assert_eq!(web.ports, vec!["8080:80"]);
}

#[test]
fn test_parse_environment_list() {
    let yaml = r#"
services:
  app:
    image: myapp:latest
    environment:
      - ENV=prod
      - DEBUG=false
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    let env_map = service.environment.to_map();
    assert_eq!(env_map.get("ENV"), Some(&"prod".to_string()));
    assert_eq!(env_map.get("DEBUG"), Some(&"false".to_string()));
}

#[test]
fn test_parse_environment_map() {
    let yaml = r#"
services:
  app:
    image: myapp:latest
    environment:
      ENV: prod
      DEBUG: "false"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    let env_map = service.environment.to_map();
    assert_eq!(env_map.get("ENV"), Some(&"prod".to_string()));
    assert_eq!(env_map.get("DEBUG"), Some(&"false".to_string()));
}

#[test]
fn test_parse_resources() {
    let yaml = r#"
services:
  db:
    image: postgres:16
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: "1G"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["db"];
    let resources = service
        .deploy
        .as_ref()
        .unwrap()
        .resources
        .as_ref()
        .unwrap();
    assert_eq!(resources.get_cpu_limit(), Some(2.0));
    assert_eq!(resources.get_memory_mb(), Some(1024));
}

#[test]
fn test_parse_depends_on() {
    let yaml = r#"
services:
  web:
    image: nginx
    depends_on:
      - db
  db:
    image: postgres
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.services["web"].depends_on, vec!["db"]);
}

#[test]
fn test_parse_volumes() {
    let yaml = r#"
services:
  db:
    image: postgres:16
    volumes:
      - db-data:/var/lib/postgresql/data
      - ./config:/etc/postgresql

volumes:
  db-data:
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["db"];
    assert_eq!(service.volumes.len(), 2);
    assert!(service.volumes.contains(&"db-data:/var/lib/postgresql/data".to_string()));
    assert!(service.volumes.contains(&"./config:/etc/postgresql".to_string()));
    assert!(compose.volumes.contains_key("db-data"));
}

#[test]
fn test_parse_networks() {
    let yaml = r#"
services:
  web:
    image: nginx
    networks:
      - frontend
  db:
    image: postgres
    networks:
      - backend

networks:
  frontend:
  backend:
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.services["web"].networks, vec!["frontend"]);
    assert_eq!(compose.services["db"].networks, vec!["backend"]);
    assert!(compose.networks.contains_key("frontend"));
    assert!(compose.networks.contains_key("backend"));
}

#[test]
fn test_parse_command_and_entrypoint() {
    let yaml = r#"
services:
  app:
    image: myapp
    command: ["python", "app.py"]
    entrypoint: ["/bin/sh", "-c"]
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    assert_eq!(
        service.command,
        Some(vec!["python".to_string(), "app.py".to_string()])
    );
    assert_eq!(
        service.entrypoint,
        Some(vec!["/bin/sh".to_string(), "-c".to_string()])
    );
}

#[test]
fn test_parse_working_dir_and_user() {
    let yaml = r#"
services:
  app:
    image: myapp
    working_dir: /app
    user: "1000:1000"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    assert_eq!(service.working_dir, Some("/app".to_string()));
    assert_eq!(service.user, Some("1000:1000".to_string()));
}

#[test]
fn test_parse_labels() {
    let yaml = r#"
services:
  app:
    image: myapp
    labels:
      com.example.description: "Web application"
      com.example.version: "1.0"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    assert_eq!(service.labels.len(), 2);
    assert_eq!(
        service.labels.get("com.example.description"),
        Some(&"Web application".to_string())
    );
    assert_eq!(
        service.labels.get("com.example.version"),
        Some(&"1.0".to_string())
    );
}

#[test]
fn test_parse_multi_service() {
    let yaml = r#"
version: "3.8"
services:
  web:
    image: nginx:latest
    ports:
      - "8080:80"
    depends_on:
      - db

  db:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: secret
    volumes:
      - db-data:/var/lib/postgresql/data

volumes:
  db-data:
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.version, "3.8");
    assert_eq!(compose.services.len(), 2);
    assert!(compose.services.contains_key("web"));
    assert!(compose.services.contains_key("db"));
    assert_eq!(compose.services["web"].depends_on, vec!["db"]);
}

#[test]
fn test_invalid_version() {
    let yaml = r#"
version: "1"
services:
  web:
    image: nginx
"#;
    let result = ComposeParser::parse(yaml);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::HyprError::UnsupportedComposeVersion { version } => {
            assert_eq!(version, "1");
        }
        _ => panic!("Expected UnsupportedComposeVersion error"),
    }
}

#[test]
fn test_no_services() {
    let yaml = r#"
version: "3"
services: {}
"#;
    let result = ComposeParser::parse(yaml);
    assert!(result.is_err());
    match result.unwrap_err() {
        crate::HyprError::ComposeParseError { reason } => {
            assert!(reason.contains("No services defined"));
        }
        _ => panic!("Expected ComposeParseError"),
    }
}

#[test]
fn test_service_missing_image() {
    let yaml = r#"
services:
  web:
    ports:
      - "8080:80"
"#;
    let result = ComposeParser::parse(yaml);
    assert!(result.is_err());
}

#[test]
fn test_parse_version_2() {
    let yaml = r#"
version: "2.1"
services:
  web:
    image: nginx
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.version, "2.1");
}

#[test]
fn test_parse_no_version() {
    let yaml = r#"
services:
  web:
    image: nginx
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    assert_eq!(compose.version, "");
}

#[test]
fn test_parse_resource_reservations() {
    let yaml = r#"
services:
  app:
    image: myapp
    deploy:
      resources:
        reservations:
          cpus: "0.5"
          memory: "512M"
        limits:
          cpus: "2.0"
          memory: "2G"
"#;
    let compose = ComposeParser::parse(yaml).unwrap();
    let service = &compose.services["app"];
    let resources = service
        .deploy
        .as_ref()
        .unwrap()
        .resources
        .as_ref()
        .unwrap();

    // Test limits
    assert_eq!(resources.get_cpu_limit(), Some(2.0));
    assert_eq!(resources.get_memory_mb(), Some(2048));

    // Test reservations
    let reservations = resources.reservations.as_ref().unwrap();
    assert_eq!(reservations.cpus.as_ref().unwrap(), "0.5");
    assert_eq!(reservations.memory.as_ref().unwrap(), "512M");
}
