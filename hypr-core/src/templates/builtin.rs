//! Built-in VM templates for common workloads.
//!
//! These templates provide optimized configurations for popular services.

use super::{Template, TemplateBuilder, TemplateCategory};
use once_cell::sync::Lazy;

/// Collection of all built-in templates.
pub static BUILTIN_TEMPLATES: Lazy<Vec<Template>> = Lazy::new(|| {
    vec![
        // =========================================================================
        // Databases
        // =========================================================================
        TemplateBuilder::new("postgres-16")
            .name("PostgreSQL 16")
            .description(
                "PostgreSQL is a powerful, open source object-relational database system \
                 with over 35 years of active development.",
            )
            .category(TemplateCategory::Database)
            .image("postgres:16-alpine")
            .resources(2, 1024)
            .port(5432, 5432)
            .env("POSTGRES_PASSWORD", "postgres")
            .env("POSTGRES_USER", "postgres")
            .env("POSTGRES_DB", "postgres")
            .tags(["sql", "relational", "acid", "postgresql"].map(String::from))
            .build(),
        TemplateBuilder::new("postgres-15")
            .name("PostgreSQL 15")
            .description("PostgreSQL 15 - stable release with JSON path queries and more.")
            .category(TemplateCategory::Database)
            .image("postgres:15-alpine")
            .resources(2, 1024)
            .port(5432, 5432)
            .env("POSTGRES_PASSWORD", "postgres")
            .env("POSTGRES_USER", "postgres")
            .env("POSTGRES_DB", "postgres")
            .tags(["sql", "relational", "acid", "postgresql"].map(String::from))
            .build(),
        TemplateBuilder::new("mysql-8")
            .name("MySQL 8")
            .description(
                "MySQL is a fast, reliable, scalable, and easy to use open-source \
                 relational database system.",
            )
            .category(TemplateCategory::Database)
            .image("mysql:8")
            .resources(2, 1024)
            .port(3306, 3306)
            .env("MYSQL_ROOT_PASSWORD", "mysql")
            .env("MYSQL_DATABASE", "mysql")
            .tags(["sql", "relational", "mysql"].map(String::from))
            .build(),
        TemplateBuilder::new("mariadb-11")
            .name("MariaDB 11")
            .description("MariaDB is a community-developed, commercially supported fork of MySQL.")
            .category(TemplateCategory::Database)
            .image("mariadb:11")
            .resources(2, 1024)
            .port(3306, 3306)
            .env("MARIADB_ROOT_PASSWORD", "mariadb")
            .env("MARIADB_DATABASE", "mariadb")
            .tags(["sql", "relational", "mariadb", "mysql-compatible"].map(String::from))
            .build(),
        TemplateBuilder::new("mongodb-7")
            .name("MongoDB 7")
            .description(
                "MongoDB is a general purpose, document-based, distributed database \
                 built for modern application developers.",
            )
            .category(TemplateCategory::Database)
            .image("mongo:7")
            .resources(2, 1024)
            .port(27017, 27017)
            .env("MONGO_INITDB_ROOT_USERNAME", "mongo")
            .env("MONGO_INITDB_ROOT_PASSWORD", "mongo")
            .tags(["nosql", "document", "mongodb"].map(String::from))
            .build(),
        TemplateBuilder::new("clickhouse-24")
            .name("ClickHouse 24")
            .description(
                "ClickHouse is an open-source column-oriented DBMS for online \
                 analytical processing (OLAP).",
            )
            .category(TemplateCategory::Database)
            .image("clickhouse/clickhouse-server:24")
            .resources(4, 2048)
            .port(8123, 8123)
            .port(9000, 9000)
            .tags(["olap", "analytics", "columnar", "clickhouse"].map(String::from))
            .build(),
        // =========================================================================
        // Web Servers
        // =========================================================================
        TemplateBuilder::new("nginx-latest")
            .name("Nginx")
            .description(
                "Nginx is a high-performance HTTP and reverse proxy server, \
                 as well as an IMAP/POP3 proxy server.",
            )
            .category(TemplateCategory::Web)
            .image("nginx:alpine")
            .resources(1, 256)
            .port(80, 80)
            .port(443, 443)
            .tags(["http", "proxy", "web-server", "nginx"].map(String::from))
            .build(),
        TemplateBuilder::new("caddy-latest")
            .name("Caddy")
            .description(
                "Caddy is a powerful, enterprise-ready, open source web server \
                 with automatic HTTPS written in Go.",
            )
            .category(TemplateCategory::Web)
            .image("caddy:alpine")
            .resources(1, 256)
            .port(80, 80)
            .port(443, 443)
            .tags(["http", "proxy", "web-server", "caddy", "auto-https"].map(String::from))
            .build(),
        TemplateBuilder::new("traefik-3")
            .name("Traefik 3")
            .description(
                "Traefik is a modern HTTP reverse proxy and load balancer \
                 that makes deploying microservices easy.",
            )
            .category(TemplateCategory::Web)
            .image("traefik:v3.0")
            .resources(1, 512)
            .port(80, 80)
            .port(443, 443)
            .port(8080, 8080)
            .tags(["http", "proxy", "load-balancer", "traefik"].map(String::from))
            .build(),
        // =========================================================================
        // Caches
        // =========================================================================
        TemplateBuilder::new("redis-7")
            .name("Redis 7")
            .description(
                "Redis is an open source, in-memory data structure store, used as \
                 a database, cache, and message broker.",
            )
            .category(TemplateCategory::Cache)
            .image("redis:7-alpine")
            .resources(1, 512)
            .port(6379, 6379)
            .tags(["cache", "key-value", "in-memory", "redis"].map(String::from))
            .build(),
        TemplateBuilder::new("valkey-8")
            .name("Valkey 8")
            .description(
                "Valkey is an open source, high-performance key/value datastore, \
                 a community-driven fork of Redis.",
            )
            .category(TemplateCategory::Cache)
            .image("valkey/valkey:8-alpine")
            .resources(1, 512)
            .port(6379, 6379)
            .tags(
                ["cache", "key-value", "in-memory", "valkey", "redis-compatible"].map(String::from),
            )
            .build(),
        TemplateBuilder::new("memcached-latest")
            .name("Memcached")
            .description(
                "Memcached is a high-performance, distributed memory object caching system.",
            )
            .category(TemplateCategory::Cache)
            .image("memcached:alpine")
            .resources(1, 512)
            .port(11211, 11211)
            .tags(["cache", "key-value", "in-memory", "memcached"].map(String::from))
            .build(),
        TemplateBuilder::new("dragonfly-latest")
            .name("Dragonfly")
            .description(
                "Dragonfly is a modern replacement for Redis and Memcached, \
                 25x faster and more memory efficient.",
            )
            .category(TemplateCategory::Cache)
            .image("docker.dragonflydb.io/dragonflydb/dragonfly")
            .resources(2, 1024)
            .port(6379, 6379)
            .tags(
                ["cache", "key-value", "in-memory", "dragonfly", "redis-compatible"]
                    .map(String::from),
            )
            .build(),
        // =========================================================================
        // Message Queues
        // =========================================================================
        TemplateBuilder::new("rabbitmq-3")
            .name("RabbitMQ 3")
            .description("RabbitMQ is a reliable and mature messaging and streaming broker.")
            .category(TemplateCategory::Queue)
            .image("rabbitmq:3-management-alpine")
            .resources(2, 1024)
            .port(5672, 5672)
            .port(15672, 15672)
            .env("RABBITMQ_DEFAULT_USER", "rabbitmq")
            .env("RABBITMQ_DEFAULT_PASS", "rabbitmq")
            .tags(["amqp", "message-queue", "rabbitmq"].map(String::from))
            .build(),
        TemplateBuilder::new("nats-latest")
            .name("NATS")
            .description(
                "NATS is a simple, secure and performant communications system for \
                 digital systems, services and devices.",
            )
            .category(TemplateCategory::Queue)
            .image("nats:alpine")
            .resources(1, 256)
            .port(4222, 4222)
            .port(8222, 8222)
            .tags(["message-queue", "pub-sub", "nats"].map(String::from))
            .build(),
        // =========================================================================
        // Monitoring
        // =========================================================================
        TemplateBuilder::new("prometheus-latest")
            .name("Prometheus")
            .description("Prometheus is an open-source systems monitoring and alerting toolkit.")
            .category(TemplateCategory::Monitoring)
            .image("prom/prometheus:latest")
            .resources(2, 1024)
            .port(9090, 9090)
            .tags(["monitoring", "metrics", "alerting", "prometheus"].map(String::from))
            .build(),
        TemplateBuilder::new("grafana-latest")
            .name("Grafana")
            .description(
                "Grafana is a multi-platform open source analytics and interactive \
                 visualization web application.",
            )
            .category(TemplateCategory::Monitoring)
            .image("grafana/grafana:latest")
            .resources(2, 512)
            .port(3000, 3000)
            .env("GF_SECURITY_ADMIN_PASSWORD", "admin")
            .tags(["monitoring", "visualization", "dashboards", "grafana"].map(String::from))
            .build(),
        TemplateBuilder::new("jaeger-latest")
            .name("Jaeger")
            .description(
                "Jaeger is open source, end-to-end distributed tracing for monitoring \
                 and troubleshooting microservices.",
            )
            .category(TemplateCategory::Monitoring)
            .image("jaegertracing/all-in-one:latest")
            .resources(2, 1024)
            .port(16686, 16686)
            .port(6831, 6831)
            .tags(["tracing", "observability", "jaeger"].map(String::from))
            .build(),
        // =========================================================================
        // Storage
        // =========================================================================
        TemplateBuilder::new("minio-latest")
            .name("MinIO")
            .description(
                "MinIO is a high-performance, S3 compatible object storage. \
                 Built for large scale AI/ML, data lake and database workloads.",
            )
            .category(TemplateCategory::Storage)
            .image("minio/minio:latest")
            .resources(2, 1024)
            .port(9000, 9000)
            .port(9001, 9001)
            .env("MINIO_ROOT_USER", "minio")
            .env("MINIO_ROOT_PASSWORD", "minio123")
            .tags(["s3", "object-storage", "minio"].map(String::from))
            .build(),
        // =========================================================================
        // Search
        // =========================================================================
        TemplateBuilder::new("elasticsearch-8")
            .name("Elasticsearch 8")
            .description("Elasticsearch is a distributed, RESTful search and analytics engine.")
            .category(TemplateCategory::Search)
            .image("docker.elastic.co/elasticsearch/elasticsearch:8.12.0")
            .resources(4, 2048)
            .port(9200, 9200)
            .port(9300, 9300)
            .env("discovery.type", "single-node")
            .env("xpack.security.enabled", "false")
            .tags(["search", "analytics", "elasticsearch", "lucene"].map(String::from))
            .build(),
        TemplateBuilder::new("meilisearch-latest")
            .name("Meilisearch")
            .description(
                "Meilisearch is a lightning-fast search engine that fits effortlessly \
                 into your apps, websites, and workflow.",
            )
            .category(TemplateCategory::Search)
            .image("getmeili/meilisearch:latest")
            .resources(2, 1024)
            .port(7700, 7700)
            .env("MEILI_ENV", "development")
            .tags(["search", "full-text", "meilisearch"].map(String::from))
            .build(),
        TemplateBuilder::new("typesense-latest")
            .name("Typesense")
            .description("Typesense is a fast, typo tolerant, in-memory fuzzy search engine.")
            .category(TemplateCategory::Search)
            .image("typesense/typesense:latest")
            .resources(2, 1024)
            .port(8108, 8108)
            .env("TYPESENSE_API_KEY", "xyz")
            .env("TYPESENSE_DATA_DIR", "/data")
            .tags(["search", "full-text", "typesense"].map(String::from))
            .build(),
        // =========================================================================
        // Development
        // =========================================================================
        TemplateBuilder::new("mailhog-latest")
            .name("MailHog")
            .description(
                "MailHog is an email testing tool for developers. \
                 Configure your app to use MailHog for SMTP delivery.",
            )
            .category(TemplateCategory::Development)
            .image("mailhog/mailhog:latest")
            .resources(1, 256)
            .port(1025, 1025)
            .port(8025, 8025)
            .tags(["email", "smtp", "testing", "development"].map(String::from))
            .build(),
        TemplateBuilder::new("localstack-latest")
            .name("LocalStack")
            .description(
                "LocalStack provides an easy-to-use test/mocking framework for \
                 developing cloud applications on AWS.",
            )
            .category(TemplateCategory::Development)
            .image("localstack/localstack:latest")
            .resources(2, 2048)
            .port(4566, 4566)
            .env("SERVICES", "s3,sqs,sns,dynamodb,lambda")
            .tags(["aws", "cloud", "mocking", "testing", "development"].map(String::from))
            .build(),
    ]
});
