//! TAP device allocation and tracking.
//!
//! This module manages the allocation and deallocation of TAP device names
//! to ensure no conflicts occur when creating network interfaces for VMs.

use std::collections::HashSet;
use std::sync::Mutex;
use tracing::{debug, info, instrument, warn};

/// Manages allocation of TAP device names.
///
/// This allocator ensures that each VM gets a unique TAP device name
/// and tracks which devices are currently in use to prevent conflicts.
#[derive(Debug)]
pub struct TapAllocator {
    /// Set of currently allocated TAP device names
    allocated: Mutex<HashSet<String>>,
    /// Prefix for TAP device names (default: "tap")
    prefix: String,
}

impl TapAllocator {
    /// Create a new TAP allocator with the default prefix ("tap").
    #[instrument]
    pub fn new() -> Self {
        info!("Creating TAP allocator with default prefix: tap");
        Self {
            allocated: Mutex::new(HashSet::new()),
            prefix: "tap".to_string(),
        }
    }

    /// Create a new TAP allocator with a custom prefix.
    ///
    /// # Arguments
    /// * `prefix` - The prefix to use for TAP device names (e.g., "hypr-tap")
    #[instrument(skip(prefix), fields(prefix = %prefix.as_ref()))]
    pub fn with_prefix(prefix: impl Into<String> + AsRef<str>) -> Self {
        let prefix_str = prefix.as_ref().to_string();
        info!("Creating TAP allocator with custom prefix: {}", prefix_str);
        Self {
            allocated: Mutex::new(HashSet::new()),
            prefix: prefix_str,
        }
    }

    /// Allocate a TAP device name for a VM.
    ///
    /// # Arguments
    /// * `vm_id` - The ID of the VM requesting a TAP device
    ///
    /// # Returns
    /// A unique TAP device name that has been reserved
    ///
    /// # Panics
    /// Panics if no TAP devices are available (all 1000 slots are in use)
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub fn allocate(&self, vm_id: &str) -> String {
        let mut allocated = self.allocated.lock().unwrap();

        // Find next available tap device
        for i in 0..1000 {
            let name = format!("{}{}", self.prefix, i);
            if !allocated.contains(&name) {
                allocated.insert(name.clone());
                info!(
                    "Allocated TAP device {} for VM {}",
                    name, vm_id
                );
                metrics::gauge!("hypr.tap.allocated.count").set(allocated.len() as f64);
                return name;
            }
        }

        // If we get here, all 1000 TAP devices are in use
        warn!("No TAP devices available - all 1000 slots in use");
        panic!("No TAP devices available - maximum allocation reached");
    }

    /// Release a TAP device name back to the pool.
    ///
    /// # Arguments
    /// * `name` - The name of the TAP device to release
    ///
    /// # Returns
    /// `true` if the device was released, `false` if it wasn't allocated
    #[instrument(skip(self), fields(tap = %name))]
    pub fn release(&self, name: &str) -> bool {
        let mut allocated = self.allocated.lock().unwrap();
        let was_allocated = allocated.remove(name);

        if was_allocated {
            info!("Released TAP device {}", name);
            metrics::gauge!("hypr.tap.allocated.count").set(allocated.len() as f64);
        } else {
            debug!("Attempted to release TAP device {} which was not allocated", name);
        }

        was_allocated
    }

    /// Check if a TAP device name is currently allocated.
    ///
    /// # Arguments
    /// * `name` - The name of the TAP device to check
    ///
    /// # Returns
    /// `true` if the device is allocated, `false` otherwise
    pub fn is_allocated(&self, name: &str) -> bool {
        let allocated = self.allocated.lock().unwrap();
        allocated.contains(name)
    }

    /// Get the number of currently allocated TAP devices.
    ///
    /// # Returns
    /// The count of allocated TAP devices
    pub fn allocated_count(&self) -> usize {
        let allocated = self.allocated.lock().unwrap();
        allocated.len()
    }

    /// Get a list of all currently allocated TAP device names.
    ///
    /// # Returns
    /// A vector of allocated TAP device names
    pub fn allocated_devices(&self) -> Vec<String> {
        let allocated = self.allocated.lock().unwrap();
        allocated.iter().cloned().collect()
    }

    /// Clear all allocations.
    ///
    /// This is primarily useful for testing or resetting state.
    #[instrument(skip(self))]
    pub fn clear(&self) {
        let mut allocated = self.allocated.lock().unwrap();
        let count = allocated.len();
        allocated.clear();
        info!("Cleared {} TAP device allocations", count);
        metrics::gauge!("hypr.tap.allocated.count").set(0.0);
    }
}

impl Default for TapAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tap_allocator_basic() {
        let allocator = TapAllocator::new();

        let tap1 = allocator.allocate("vm1");
        assert_eq!(tap1, "tap0");

        let tap2 = allocator.allocate("vm2");
        assert_eq!(tap2, "tap1");

        let tap3 = allocator.allocate("vm3");
        assert_eq!(tap3, "tap2");

        assert_eq!(allocator.allocated_count(), 3);
    }

    #[test]
    fn test_tap_allocator_release() {
        let allocator = TapAllocator::new();

        let tap1 = allocator.allocate("vm1");
        assert_eq!(tap1, "tap0");

        let tap2 = allocator.allocate("vm2");
        assert_eq!(tap2, "tap1");

        // Release tap0
        assert!(allocator.release(&tap1));
        assert_eq!(allocator.allocated_count(), 1);

        // Allocate again - should reuse tap0
        let tap3 = allocator.allocate("vm3");
        assert_eq!(tap3, "tap0");

        assert_eq!(allocator.allocated_count(), 2);
    }

    #[test]
    fn test_tap_allocator_is_allocated() {
        let allocator = TapAllocator::new();

        assert!(!allocator.is_allocated("tap0"));

        let tap1 = allocator.allocate("vm1");
        assert_eq!(tap1, "tap0");

        assert!(allocator.is_allocated("tap0"));
        assert!(!allocator.is_allocated("tap1"));

        allocator.release(&tap1);
        assert!(!allocator.is_allocated("tap0"));
    }

    #[test]
    fn test_tap_allocator_release_unallocated() {
        let allocator = TapAllocator::new();

        // Releasing an unallocated device should return false
        assert!(!allocator.release("tap0"));
    }

    #[test]
    fn test_tap_allocator_custom_prefix() {
        let allocator = TapAllocator::with_prefix("hypr-tap");

        let tap1 = allocator.allocate("vm1");
        assert_eq!(tap1, "hypr-tap0");

        let tap2 = allocator.allocate("vm2");
        assert_eq!(tap2, "hypr-tap1");
    }

    #[test]
    fn test_tap_allocator_allocated_devices() {
        let allocator = TapAllocator::new();

        let tap1 = allocator.allocate("vm1");
        let tap2 = allocator.allocate("vm2");
        let tap3 = allocator.allocate("vm3");

        let devices = allocator.allocated_devices();
        assert_eq!(devices.len(), 3);
        assert!(devices.contains(&tap1));
        assert!(devices.contains(&tap2));
        assert!(devices.contains(&tap3));
    }

    #[test]
    fn test_tap_allocator_clear() {
        let allocator = TapAllocator::new();

        allocator.allocate("vm1");
        allocator.allocate("vm2");
        allocator.allocate("vm3");

        assert_eq!(allocator.allocated_count(), 3);

        allocator.clear();

        assert_eq!(allocator.allocated_count(), 0);
        assert!(!allocator.is_allocated("tap0"));
        assert!(!allocator.is_allocated("tap1"));
        assert!(!allocator.is_allocated("tap2"));
    }

    #[test]
    fn test_tap_allocator_sequential_allocation() {
        let allocator = TapAllocator::new();

        // Allocate many devices
        for i in 0..10 {
            let tap = allocator.allocate(&format!("vm{}", i));
            assert_eq!(tap, format!("tap{}", i));
        }

        assert_eq!(allocator.allocated_count(), 10);

        // Release some in the middle
        allocator.release("tap3");
        allocator.release("tap7");

        assert_eq!(allocator.allocated_count(), 8);

        // Next allocation should reuse tap3 (first available)
        let tap = allocator.allocate("vm-new");
        assert_eq!(tap, "tap3");
    }

    #[test]
    fn test_tap_allocator_default() {
        let allocator = TapAllocator::default();

        let tap = allocator.allocate("vm1");
        assert_eq!(tap, "tap0");
    }

    #[test]
    #[should_panic(expected = "No TAP devices available")]
    fn test_tap_allocator_exhaustion() {
        let allocator = TapAllocator::new();

        // Allocate all 1000 devices
        for i in 0..1000 {
            allocator.allocate(&format!("vm{}", i));
        }

        // This should panic
        allocator.allocate("vm-overflow");
    }
}
