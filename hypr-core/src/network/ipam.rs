//! IP Address Management (IPAM) for VM networking.
//!
//! Manages allocation of IP addresses from the 100.64.0.0/10 CGNAT range.

use crate::error::{HyprError, Result};
use crate::state::StateManager;
use std::net::Ipv4Addr;
use std::sync::Arc;
use tracing::{info, instrument};

/// IP address allocator for VMs.
///
/// Allocates IPs from the 100.64.0.0/10 CGNAT range with persistent tracking.
pub struct IpAllocator {
    state: Arc<StateManager>,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    gateway: Ipv4Addr,
}

impl IpAllocator {
    /// Create a new IP allocator.
    ///
    /// # Arguments
    ///
    /// * `state` - State manager for persistent storage
    pub fn new(state: Arc<StateManager>) -> Self {
        Self {
            state,
            pool_start: Ipv4Addr::new(100, 64, 0, 2), // Reserve .1 for gateway
            pool_end: Ipv4Addr::new(103, 255, 255, 254),
            gateway: Ipv4Addr::new(100, 64, 0, 1),
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
                metrics::gauge!("hypr_ip_pool_available").set((self.pool_size() - allocated.len() - 1) as f64);

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

    /// Get the total pool size.
    fn pool_size(&self) -> usize {
        // 100.64.0.0/10 = 4,194,304 addresses
        // Minus gateway = 4,194,303 available
        4_194_303
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_state() -> Arc<StateManager> {
        let state = StateManager::new_in_memory().await.unwrap();
        Arc::new(state)
    }

    #[tokio::test]
    async fn test_ip_allocation() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        // Allocate first IP
        let ip1 = ipam.allocate("vm1").await.unwrap();
        assert_eq!(ip1, Ipv4Addr::new(100, 64, 0, 2));

        // Allocate second IP
        let ip2 = ipam.allocate("vm2").await.unwrap();
        assert_eq!(ip2, Ipv4Addr::new(100, 64, 0, 3));

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

        assert_eq!(ipam.gateway(), Ipv4Addr::new(100, 64, 0, 1));
    }

    #[test]
    fn test_next_ip() {
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        let next = IpAllocator::next_ip(ip);
        assert_eq!(next, Ipv4Addr::new(192, 168, 1, 2));

        // Test overflow
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

        assert_eq!(ip1, Ipv4Addr::new(100, 64, 0, 2));
        assert_eq!(ip2, Ipv4Addr::new(100, 64, 0, 3));
        assert_eq!(ip3, Ipv4Addr::new(100, 64, 0, 4));

        // Release middle IP
        ipam.release("vm2").await.unwrap();

        // Next allocation should reuse released IP
        let ip4 = ipam.allocate("vm4").await.unwrap();
        assert_eq!(ip4, Ipv4Addr::new(100, 64, 0, 3));
    }

    #[tokio::test]
    async fn test_pool_size() {
        let state = create_test_state().await;
        let ipam = IpAllocator::new(state);

        assert_eq!(ipam.pool_size(), 4_194_303);
    }
}
