# GPU Passthrough

HYPR supports GPU passthrough for running GPU-accelerated workloads in VMs.

## Platform Support

| Platform | Method | Supported GPUs |
|----------|--------|----------------|
| Linux | VFIO | NVIDIA, AMD, Intel |
| macOS Apple Silicon | Metal via Venus | Integrated GPU |
| macOS Intel | Not supported | - |

## Linux: VFIO Passthrough

On Linux, GPUs are passed through using VFIO (Virtual Function I/O), which provides direct hardware access to the VM.

### Prerequisites

1. **IOMMU Enabled**: Add to kernel command line:
   - Intel: `intel_iommu=on`
   - AMD: `amd_iommu=on`

2. **VFIO Modules**: Ensure modules are loaded:
   ```sh
   sudo modprobe vfio-pci
   ```

### List Available GPUs

```sh
hypr gpu list
```

Output:
```
PCI ADDRESS     VENDOR     MODEL                          DRIVER       IOMMU      STATUS
0000:01:00.0    Nvidia     NVIDIA GeForce RTX 4090        nvidia       1          available
0000:02:00.0    Amd        AMD Radeon RX 7900 XTX         amdgpu       2          available
```

**Status values:**
- `available` - GPU can be used for passthrough
- `vfio-ready` - GPU is already bound to vfio-pci driver
- `boot-vga` - GPU is the primary display (cannot unbind without --force)

### Run with GPU

```sh
hypr run --gpu 0000:01:00.0 pytorch/pytorch:latest
```

This:
1. Validates the PCI address
2. Checks IOMMU group isolation
3. Binds the GPU to vfio-pci driver
4. Passes the GPU to the VM
5. Restores the original driver when VM stops

### IOMMU Groups

All devices in an IOMMU group must be passed through together. HYPR validates this automatically.

If validation fails:
```
GPU 0000:01:00.0 not in isolated IOMMU group.
Other devices in group: 0000:01:00.1 (audio)
```

Pass all devices in the group:
```sh
hypr run --gpu 0000:01:00.0 --gpu 0000:01:00.1 pytorch
```

### Boot VGA Protection

The boot VGA device (primary GPU driving the display) is protected by default. Unbinding it can hang the system.

To override (use with caution):
```sh
# Only if you have another GPU or headless setup
hypr run --gpu 0000:00:02.0 --force-gpu pytorch
```

### NVIDIA-Specific Notes

**Driver Installation in VM:**
The VM needs NVIDIA drivers. Use an image with drivers pre-installed:
```sh
hypr run --gpu 0000:01:00.0 nvidia/cuda:12.0-runtime-ubuntu22.04
```

**SR-IOV (Virtual Functions):**
Some enterprise GPUs (A100, H100) support SR-IOV for sharing a GPU across multiple VMs. HYPR will detect and use virtual functions when available.

## macOS: Metal GPU

On Apple Silicon Macs, HYPR uses Metal GPU virtualization via the Venus Vulkan driver.

### How It Works

1. krunkit creates a VM with virtio-gpu device
2. Guest uses Venus driver (Vulkan over virtio-gpu)
3. Host translates Vulkan to Metal
4. GPU operations run on Apple GPU

### Enable Metal GPU

```sh
hypr run --gpu tensorflow/tensorflow:latest-gpu
```

No PCI address needed - the integrated GPU is used automatically.

### List GPU

```sh
hypr gpu list
```

Output:
```
VENDOR     MODEL                                    MEMORY          STATUS
Apple      Apple M3 Max                             48.0 GB         available
```

### Performance

Metal passthrough achieves approximately 60-80% of native performance, depending on workload:
- Compute (matrix ops): ~75-80%
- Graphics rendering: ~60-70%
- Memory bandwidth: ~70-75%

### Supported Frameworks

Frameworks using Metal Compute or MPS work automatically:
- TensorFlow with Metal plugin
- PyTorch with MPS backend
- MLX
- Core ML

## Troubleshooting

### Linux: GPU Not Available

**IOMMU not enabled:**
```sh
dmesg | grep -i iommu
```
Should show IOMMU initialization. If not, check kernel command line.

**VFIO module not loaded:**
```sh
lsmod | grep vfio
```
Load manually: `sudo modprobe vfio-pci`

**GPU in use by host:**
Stop display manager and unload GPU driver:
```sh
sudo systemctl stop gdm
sudo rmmod nvidia_drm nvidia_modeset nvidia
```

### macOS: Metal Not Working

**Check krunkit version:**
```sh
krunkit --version
```
Requires krunkit with Metal support.

**Verify macOS version:**
Metal GPU requires macOS 14 (Sonoma) or later.

**Check VM configuration:**
GPU must be enabled at VM creation. Cannot be hot-added.

### Check GPU Usage in VM

**NVIDIA (Linux):**
```sh
hypr exec myvm -- nvidia-smi
```

**AMD (Linux):**
```sh
hypr exec myvm -- rocm-smi
```

**Metal (macOS guest):**
```sh
hypr exec myvm -- python -c "import torch; print(torch.backends.mps.is_available())"
```
