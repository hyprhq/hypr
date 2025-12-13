//! VM Templates for common workloads.
//!
//! Templates provide pre-configured VM settings for popular services like
//! databases, web servers, caches, and message queues. Users can create
//! VMs from templates with a single command.
//!
//! # Example
//!
//! ```ignore
//! use hypr_core::templates::TemplateRegistry;
//!
//! let registry = TemplateRegistry::new();
//! let template = registry.get("postgres-16").unwrap();
//! println!("Image: {}", template.image);
//! ```

mod builtin;

use crate::types::{PortMapping, VmResources};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub use builtin::BUILTIN_TEMPLATES;

/// Template category for organization and filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TemplateCategory {
    /// Database systems (PostgreSQL, MySQL, MongoDB, etc.)
    Database,
    /// Web servers and proxies (Nginx, Apache, Caddy, etc.)
    Web,
    /// In-memory caches (Redis, Memcached, etc.)
    Cache,
    /// Message queues (RabbitMQ, Kafka, etc.)
    Queue,
    /// Monitoring and observability (Prometheus, Grafana, etc.)
    Monitoring,
    /// Development tools and environments
    Development,
    /// Storage systems (MinIO, etc.)
    Storage,
    /// Search engines (Elasticsearch, etc.)
    Search,
    /// Other/miscellaneous
    Other,
}

impl TemplateCategory {
    /// Convert category to string representation.
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Database => "database",
            Self::Web => "web",
            Self::Cache => "cache",
            Self::Queue => "queue",
            Self::Monitoring => "monitoring",
            Self::Development => "development",
            Self::Storage => "storage",
            Self::Search => "search",
            Self::Other => "other",
        }
    }

    /// Parse category from string.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "database" => Some(Self::Database),
            "web" => Some(Self::Web),
            "cache" => Some(Self::Cache),
            "queue" => Some(Self::Queue),
            "monitoring" => Some(Self::Monitoring),
            "development" => Some(Self::Development),
            "storage" => Some(Self::Storage),
            "search" => Some(Self::Search),
            "other" => Some(Self::Other),
            _ => None,
        }
    }
}

impl std::fmt::Display for TemplateCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A VM template definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    /// Unique template identifier (e.g., "postgres-16").
    pub id: String,

    /// Human-readable name (e.g., "PostgreSQL 16").
    pub name: String,

    /// Detailed description of the template.
    pub description: String,

    /// Template category for organization.
    pub category: TemplateCategory,

    /// Base image to use (e.g., "postgres:16-alpine").
    pub image: String,

    /// Default resource allocation.
    pub default_resources: VmResources,

    /// Default port mappings.
    pub default_ports: Vec<PortMapping>,

    /// Default environment variables.
    pub default_env: HashMap<String, String>,

    /// Searchable tags.
    pub tags: Vec<String>,

    /// Optional icon URL for UI display.
    pub icon_url: Option<String>,

    /// Whether this is a built-in template.
    pub builtin: bool,
}

impl Template {
    /// Create a new template builder.
    #[must_use]
    pub fn builder(id: impl Into<String>) -> TemplateBuilder {
        TemplateBuilder::new(id)
    }

    /// Check if the template matches a search query.
    ///
    /// Searches in name, description, and tags.
    pub fn matches_search(&self, query: &str) -> bool {
        let query_lower = query.to_lowercase();

        self.name.to_lowercase().contains(&query_lower)
            || self.description.to_lowercase().contains(&query_lower)
            || self.id.to_lowercase().contains(&query_lower)
            || self.tags.iter().any(|t| t.to_lowercase().contains(&query_lower))
    }
}

/// Builder for creating templates.
#[derive(Debug)]
pub struct TemplateBuilder {
    id: String,
    name: String,
    description: String,
    category: TemplateCategory,
    image: String,
    resources: VmResources,
    ports: Vec<PortMapping>,
    env: HashMap<String, String>,
    tags: Vec<String>,
    icon_url: Option<String>,
    builtin: bool,
}

impl TemplateBuilder {
    /// Create a new template builder with the given ID.
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: String::new(),
            description: String::new(),
            category: TemplateCategory::Other,
            image: String::new(),
            resources: VmResources { cpus: 2, memory_mb: 512, balloon_enabled: true },
            ports: Vec::new(),
            env: HashMap::new(),
            tags: Vec::new(),
            icon_url: None,
            builtin: true,
        }
    }

    /// Set the template name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }

    /// Set the template description.
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = description.into();
        self
    }

    /// Set the template category.
    pub fn category(mut self, category: TemplateCategory) -> Self {
        self.category = category;
        self
    }

    /// Set the base image.
    pub fn image(mut self, image: impl Into<String>) -> Self {
        self.image = image.into();
        self
    }

    /// Set the default resources.
    pub fn resources(mut self, cpus: u32, memory_mb: u32) -> Self {
        self.resources = VmResources { cpus, memory_mb, balloon_enabled: true };
        self
    }

    /// Add a port mapping.
    pub fn port(mut self, host: u16, guest: u16) -> Self {
        self.ports.push(PortMapping {
            host_port: host,
            vm_port: guest,
            protocol: crate::types::network::Protocol::Tcp,
        });
        self
    }

    /// Add an environment variable.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add multiple environment variables.
    pub fn envs(mut self, vars: impl IntoIterator<Item = (String, String)>) -> Self {
        self.env.extend(vars);
        self
    }

    /// Add a tag.
    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags.
    pub fn tags(mut self, tags: impl IntoIterator<Item = String>) -> Self {
        self.tags.extend(tags);
        self
    }

    /// Set the icon URL.
    pub fn icon(mut self, url: impl Into<String>) -> Self {
        self.icon_url = Some(url.into());
        self
    }

    /// Mark as user-defined (not built-in).
    pub fn user_defined(mut self) -> Self {
        self.builtin = false;
        self
    }

    /// Build the template.
    #[must_use]
    pub fn build(self) -> Template {
        Template {
            id: self.id,
            name: self.name,
            description: self.description,
            category: self.category,
            image: self.image,
            default_resources: self.resources,
            default_ports: self.ports,
            default_env: self.env,
            tags: self.tags,
            icon_url: self.icon_url,
            builtin: self.builtin,
        }
    }
}

/// Registry for managing templates.
#[derive(Debug, Clone)]
pub struct TemplateRegistry {
    templates: HashMap<String, Template>,
}

impl Default for TemplateRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TemplateRegistry {
    /// Create a new registry with built-in templates.
    #[must_use]
    pub fn new() -> Self {
        let mut templates = HashMap::new();
        for template in BUILTIN_TEMPLATES.iter() {
            templates.insert(template.id.clone(), template.clone());
        }
        Self { templates }
    }

    /// Create an empty registry (for testing).
    #[must_use]
    pub fn empty() -> Self {
        Self { templates: HashMap::new() }
    }

    /// Get a template by ID.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Template> {
        self.templates.get(id)
    }

    /// List all templates.
    #[must_use]
    pub fn list(&self) -> Vec<&Template> {
        self.templates.values().collect()
    }

    /// List templates filtered by category.
    #[must_use]
    pub fn list_by_category(&self, category: TemplateCategory) -> Vec<&Template> {
        self.templates.values().filter(|t| t.category == category).collect()
    }

    /// Search templates by query.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&Template> {
        if query.is_empty() {
            return self.list();
        }
        self.templates.values().filter(|t| t.matches_search(query)).collect()
    }

    /// Add a custom template.
    pub fn add(&mut self, template: Template) {
        self.templates.insert(template.id.clone(), template);
    }

    /// Remove a template by ID.
    pub fn remove(&mut self, id: &str) -> Option<Template> {
        self.templates.remove(id)
    }

    /// Get the number of templates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.len()
    }

    /// Check if the registry is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_builder() {
        let template = Template::builder("test-template")
            .name("Test Template")
            .description("A test template")
            .category(TemplateCategory::Database)
            .image("test:latest")
            .resources(2, 1024)
            .port(5432, 5432)
            .env("TEST_VAR", "test_value")
            .tag("test")
            .build();

        assert_eq!(template.id, "test-template");
        assert_eq!(template.name, "Test Template");
        assert_eq!(template.category, TemplateCategory::Database);
        assert_eq!(template.image, "test:latest");
        assert_eq!(template.default_resources.cpus, 2);
        assert_eq!(template.default_resources.memory_mb, 1024);
        assert_eq!(template.default_ports.len(), 1);
        assert_eq!(template.default_env.get("TEST_VAR"), Some(&"test_value".to_string()));
        assert!(template.tags.contains(&"test".to_string()));
    }

    #[test]
    fn test_template_search() {
        let template = Template::builder("postgres-16")
            .name("PostgreSQL 16")
            .description("PostgreSQL database server")
            .tag("sql")
            .tag("relational")
            .build();

        assert!(template.matches_search("postgres"));
        assert!(template.matches_search("PostgreSQL"));
        assert!(template.matches_search("sql"));
        assert!(template.matches_search("database"));
        assert!(!template.matches_search("mongodb"));
    }

    #[test]
    fn test_registry() {
        let registry = TemplateRegistry::new();

        // Should have built-in templates
        assert!(!registry.is_empty());

        // Should be able to find postgres
        assert!(registry.get("postgres-16").is_some());

        // Should be able to list by category
        let databases = registry.list_by_category(TemplateCategory::Database);
        assert!(!databases.is_empty());
    }

    #[test]
    fn test_category_conversion() {
        assert_eq!(TemplateCategory::Database.as_str(), "database");
        assert_eq!(TemplateCategory::parse("database"), Some(TemplateCategory::Database));
        assert_eq!(TemplateCategory::parse("Database"), Some(TemplateCategory::Database));
        assert_eq!(TemplateCategory::parse("invalid"), None);
    }
}
