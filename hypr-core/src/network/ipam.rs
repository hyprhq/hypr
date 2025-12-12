//! IP Address Management (IPAM) for VM networking.
//!
//! Manages allocation of IP addresses with platform-specific ranges.
//! See [`crate::network::defaults`] for platform-specific configuration.

use super::defaults;
use crate::error::{HyprError, Result};
use crate::state::StateManager;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{info, instrument};

/// IP address allocator for VMs.
///
/// Allocates IPs from platform-specific ranges with persistent tracking.
/// Uses centralized network defaults from [`crate::network::defaults`].
pub struct IpAllocator {
    state: Arc<StateManager>,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl IpAllocator {
    /// Create a new IP allocator with platform-specific IP ranges.
    ///
    /// Uses the centralized network defaults for the current platform.
    ///
    /// # Arguments
    ///
    /// * `state` - State manager for persistent storage
    #[instrument(skip(state))]
    pub fn new(state: Arc<StateManager>) -> Self {
        let net_defaults = defaults::defaults();
        info!(
            "Creating IP allocator (pool: {} - {})",
            net_defaults.pool_start, net_defaults.pool_end
        );
        Self {
            state,
            pool_start: net_defaults.pool_start,
            pool_end: net_defaults.pool_end,
            gateway: net_defaults.gateway,
        }
    }

    /// Allocate an IP address for a VM.
    ///
    /// # Arguments
    ///
    /// * `vm_id` - ID of the VM to allocate an IP for
    ///
    /// # Returns
    ///
    /// The allocated IP address
    ///
    /// # Errors
    ///
    /// Returns `HyprError::IpPoolExhausted` if no IPs are available
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub async fn allocate(&self, vm_id: &str) -> Result<Ipv4Addr> {
        info!("Allocating IP for VM: {}", vm_id);

        // Get all allocated IPs
        let allocated = self.state.list_allocated_ips().await?;

        // Find next available IP
        let mut current = self.pool_start;

        while current <= self.pool_end {
            if !allocated.contains(&current) {
                // Found available IP, allocate it
                self.state.insert_ip_allocation(vm_id, current).await?;

                info!("Allocated IP {} to VM {}", current, vm_id);
                metrics::counter!("hypr_ip_allocated_total", "status" => "success").increment(1);
                metrics::gauge!("hypr_ip_pool_available")
                    .set((self.pool_size() - allocated.len() - 1) as f64);

                return Ok(current);
            }

            current = Self::next_ip(current);
        }

        Err(HyprError::IpPoolExhausted)
    }

    /// Release an IP address allocation for a VM.
    ///
    /// # Arguments
    ///
    /// * `vm_id` - ID of the VM to release the IP for
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub async fn release(&self, vm_id: &str) -> Result<()> {
        info!("Releasing IP for VM: {}", vm_id);

        self.state.delete_ip_allocation(vm_id).await?;

        metrics::counter!("hypr_ip_released_total", "status" => "success").increment(1);

        Ok(())
    }

    /// Get the current IP allocation for a VM.
    ///
    /// # Arguments
    ///
    /// * `vm_id` - ID of the VM to get the allocation for
    ///
    /// # Returns
    ///
    /// The allocated IP address, or None if not allocated
    #[instrument(skip(self), fields(vm_id = %vm_id))]
    pub async fn get_allocation(&self, vm_id: &str) -> Result<Option<Ipv4Addr>> {
        self.state.get_ip_allocation(vm_id).await
    }

    /// Get the gateway IP address.
    pub fn gateway(&self) -> Ipv4Addr {
        self.gateway
    }

    /// Calculate the next IP address.
    fn next_ip(ip: Ipv4Addr) -> Ipv4Addr {
        let octets = ip.octets();
        let mut value = u32::from_be_bytes(octets);
        value += 1;
        Ipv4Addr::from(value)
    }

    /// Get the total pool size based on platform defaults.
    fn pool_size(&self) -> usize {
        defaults::pool_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_state() -> Arc<StateManager> {
        let state = StateManager::new_in_memory().await.unwrap();
        Arc::new(state)
    }

    /// Get expected IP at offset from pool start
    fn expected_ip(offset: u32) -> Ipv4Addr {
        let net = defaults::defaults();
        let octets = net.pool_start.octets();
        let base = u32::from_be_bytes(octets);
        Ipv4Addr::from(base + offset)
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        // Allocate first IP (should be pool_start)
        let ip1 = ipam.allocate("vm1").await.unwrap();
        assert_eq!(ip1, expected_ip(0));

        // Allocate second IP (should be pool_start + 1)
        let ip2 = ipam.allocate("vm2").await.unwrap();
        assert_eq!(ip2, expected_ip(1));

        // Verify allocation persists
        let retrieved = ipam.get_allocation("vm1").await.unwrap();
        assert_eq!(retrieved, Some(ip1));
    }

    #[tokio::test]
    async fn test_ip_release() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        let ip = ipam.allocate("vm1").await.unwrap();

        ipam.release("vm1").await.unwrap();

        // IP should be available again
        let allocation = ipam.get_allocation("vm1").await.unwrap();
        assert_eq!(allocation, None);

        // Should be able to allocate same IP again
        let ip2 = ipam.allocate("vm2").await.unwrap();
        assert_eq!(ip, ip2);
    }

    #[tokio::test]
    async fn test_gateway() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        let net = defaults::defaults();
        assert_eq!(ipam.gateway(), net.gateway);
    }

    #[test]
    fn test_next_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let next = IpAllocator::next_ip(ip);
        assert_eq!(next, Ipv4Addr::new(192, 168, 1, 2));

        // Test overflow within octet
        let ip = Ipv4Addr::new(192, 168, 1, 255);
        let next = IpAllocator::next_ip(ip);
        assert_eq!(next, Ipv4Addr::new(192, 168, 2, 0));
    }

    #[tokio::test]
    async fn test_multiple_allocations() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        // Allocate multiple IPs
        let ip1 = ipam.allocate("vm1").await.unwrap();
        let ip2 = ipam.allocate("vm2").await.unwrap();
        let ip3 = ipam.allocate("vm3").await.unwrap();

        assert_eq!(ip1, expected_ip(0));
        assert_eq!(ip2, expected_ip(1));
        assert_eq!(ip3, expected_ip(2));

        // Release middle IP
        ipam.release("vm2").await.unwrap();

        // Next allocation should reuse released IP
        let ip4 = ipam.allocate("vm4").await.unwrap();
        assert_eq!(ip4, expected_ip(1));
    }

    #[tokio::test]
    async fn test_pool_size() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        assert_eq!(ipam.pool_size(), defaults::pool_size());
    }
}
