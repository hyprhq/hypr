//! Event bus for HYPR system events.
//!
//! Provides a publish/subscribe mechanism for system events like
//! VM lifecycle changes, image operations, and stack deployments.
//!
//! # Example
//!
//! ```ignore
//! let bus = EventBus::new();
//!
//! // Subscribe to VM events
//! let mut rx = bus.subscribe(vec!["vm.*".to_string()]);
//!
//! // Publish an event
//! bus.publish(Event::new(
//!     EventType::VmStarted,
//!     "vm",
//!     "vm-123",
//!     "started",
//!     "VM myapp started successfully",
//! ));
//!
//! // Receive events
//! while let Ok(event) = rx.recv().await {
//!     println!("Received: {:?}", event);
//! }
//! ```

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::debug;

/// Maximum number of events buffered in the broadcast channel.
const EVENT_BUFFER_SIZE: usize = 256;

/// Event types for filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
    // VM events
    VmCreated,
    VmStarted,
    VmStopped,
    VmDeleted,
    VmFailed,

    // Image events
    ImagePulled,
    ImageBuilt,
    ImageDeleted,
    ImagePushStarted,
    ImagePushCompleted,

    // Stack events
    StackDeployed,
    StackDestroyed,
    StackFailed,
    StackUpdated,

    // Network events
    NetworkCreated,
    NetworkDeleted,

    // Volume events
    VolumeCreated,
    VolumeDeleted,
}

impl EventType {
    /// Get the event type string (e.g., "vm.started").
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::VmCreated => "vm.created",
            EventType::VmStarted => "vm.started",
            EventType::VmStopped => "vm.stopped",
            EventType::VmDeleted => "vm.deleted",
            EventType::VmFailed => "vm.failed",
            EventType::ImagePulled => "image.pulled",
            EventType::ImageBuilt => "image.built",
            EventType::ImageDeleted => "image.deleted",
            EventType::ImagePushStarted => "image.push_started",
            EventType::ImagePushCompleted => "image.push_completed",
            EventType::StackDeployed => "stack.deployed",
            EventType::StackDestroyed => "stack.destroyed",
            EventType::StackFailed => "stack.failed",
            EventType::StackUpdated => "stack.updated",
            EventType::NetworkCreated => "network.created",
            EventType::NetworkDeleted => "network.deleted",
            EventType::VolumeCreated => "volume.created",
            EventType::VolumeDeleted => "volume.deleted",
        }
    }

    /// Get the resource type (e.g., "vm", "image").
    pub fn resource_type(&self) -> &'static str {
        match self {
            EventType::VmCreated
            | EventType::VmStarted
            | EventType::VmStopped
            | EventType::VmDeleted
            | EventType::VmFailed => "vm",
            EventType::ImagePulled
            | EventType::ImageBuilt
            | EventType::ImageDeleted
            | EventType::ImagePushStarted
            | EventType::ImagePushCompleted => "image",
            EventType::StackDeployed
            | EventType::StackDestroyed
            | EventType::StackFailed
            | EventType::StackUpdated => "stack",
            EventType::NetworkCreated | EventType::NetworkDeleted => "network",
            EventType::VolumeCreated | EventType::VolumeDeleted => "volume",
        }
    }

    /// Get the action (e.g., "created", "started").
    pub fn action(&self) -> &'static str {
        match self {
            EventType::VmCreated | EventType::NetworkCreated | EventType::VolumeCreated => {
                "created"
            }
            EventType::VmStarted => "started",
            EventType::VmStopped => "stopped",
            EventType::VmDeleted | EventType::NetworkDeleted | EventType::VolumeDeleted => {
                "deleted"
            }
            EventType::VmFailed | EventType::StackFailed => "failed",
            EventType::ImagePulled => "pulled",
            EventType::ImageBuilt => "built",
            EventType::ImageDeleted => "deleted",
            EventType::ImagePushStarted => "push_started",
            EventType::ImagePushCompleted => "push_completed",
            EventType::StackDeployed => "deployed",
            EventType::StackDestroyed => "destroyed",
            EventType::StackUpdated => "updated",
        }
    }
}

/// A system event.
#[derive(Debug, Clone)]
pub struct Event {
    /// Unix timestamp in milliseconds
    pub timestamp: i64,
    /// Event type string (e.g., "vm.started")
    pub event_type: String,
    /// Resource type (e.g., "vm", "image")
    pub resource_type: String,
    /// Resource ID
    pub resource_id: String,
    /// Action (e.g., "started", "deleted")
    pub action: String,
    /// Human-readable message
    pub message: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Event {
    /// Create a new event.
    pub fn new(
        event_type: EventType,
        resource_id: &str,
        message: &str,
    ) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64,
            event_type: event_type.as_str().to_string(),
            resource_type: event_type.resource_type().to_string(),
            resource_id: resource_id.to_string(),
            action: event_type.action().to_string(),
            message: message.to_string(),
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the event.
    pub fn with_metadata(mut self, key: &str, value: &str) -> Self {
        self.metadata.insert(key.to_string(), value.to_string());
        self
    }
}

/// Event bus for publishing and subscribing to system events.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a new event bus.
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(EVENT_BUFFER_SIZE);
        Self { sender }
    }

    /// Publish an event to all subscribers.
    pub fn publish(&self, event: Event) {
        debug!(event_type = %event.event_type, resource_id = %event.resource_id, "Publishing event");
        // Ignore send errors (no subscribers)
        let _ = self.sender.send(event);
    }

    /// Subscribe to events, optionally filtered by event type patterns.
    ///
    /// # Filter patterns
    ///
    /// - `"vm.*"` - All VM events
    /// - `"image.*"` - All image events
    /// - `"vm.started"` - Only VM started events
    /// - Empty list - All events
    pub fn subscribe(&self, filters: Vec<String>) -> EventSubscriber {
        EventSubscriber { receiver: self.sender.subscribe(), filters }
    }

    /// Get the number of current subscribers.
    pub fn subscriber_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

/// Event subscriber with optional filtering.
pub struct EventSubscriber {
    receiver: broadcast::Receiver<Event>,
    filters: Vec<String>,
}

impl EventSubscriber {
    /// Receive the next event (blocking).
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    if self.matches(&event) {
                        return Some(event);
                    }
                    // Event doesn't match filters, continue
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    debug!("Event subscriber lagged by {} events", n);
                    // Continue receiving
                }
                Err(broadcast::error::RecvError::Closed) => {
                    return None;
                }
            }
        }
    }

    /// Check if an event matches the filters.
    fn matches(&self, event: &Event) -> bool {
        // Empty filters = all events
        if self.filters.is_empty() {
            return true;
        }

        for filter in &self.filters {
            // Exact match
            if filter == &event.event_type {
                return true;
            }

            // Wildcard match (e.g., "vm.*")
            if filter.ends_with(".*") {
                let prefix = &filter[..filter.len() - 2];
                if event.event_type.starts_with(prefix) {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_publish_subscribe() {
        let bus = EventBus::new();

        let mut subscriber = bus.subscribe(vec![]);

        bus.publish(Event::new(EventType::VmStarted, "vm-123", "VM started"));

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), subscriber.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event.event_type, "vm.started");
        assert_eq!(event.resource_id, "vm-123");
    }

    #[tokio::test]
    async fn test_filter_match() {
        let bus = EventBus::new();

        let mut subscriber = bus.subscribe(vec!["vm.*".to_string()]);

        // Should receive VM event
        bus.publish(Event::new(EventType::VmStarted, "vm-123", "VM started"));

        // Should NOT receive image event
        bus.publish(Event::new(EventType::ImagePulled, "img-456", "Image pulled"));

        let event = tokio::time::timeout(std::time::Duration::from_millis(100), subscriber.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event.event_type, "vm.started");
    }

    #[test]
    fn test_event_type_strings() {
        assert_eq!(EventType::VmStarted.as_str(), "vm.started");
        assert_eq!(EventType::VmStarted.resource_type(), "vm");
        assert_eq!(EventType::VmStarted.action(), "started");
    }
}
