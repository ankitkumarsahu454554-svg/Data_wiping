// detect.rs — Drive enumeration via /sys/block and /proc/partitions
// Detects all block devices, classifies interface type (NVMe, SATA, USB, SAS),
// reads capacity, model, serial, firmware, and rotation status.

use std::fs;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use crate::{DriveInfo, DriveInterface, WipeError};

/// Enumerate all physical block devices on the system.
/// Skips partitions, loop devices, device-mapper, and ram disks.
pub fn enumerate_drives() -> Result<Vec<DriveInfo>, WipeError> {
    let sys_block = Path::new("/sys/block");
    if !sys_block.exists() {
        return Err(WipeError::DetectionFailed(
            "/sys/block not found — is this Linux?".into(),
        ));
    }

    let mut drives = Vec::new();

    for entry in fs::read_dir(sys_block)
        .map_err(|e| WipeError::DetectionFailed(format!("read_dir /sys/block: {}", e)))?
    {
        let entry = entry.map_err(|e| WipeError::DetectionFailed(e.to_string()))?;
        let name = entry.file_name().to_string_lossy().into_owned();

        // Skip non-physical devices
        if should_skip_device(&name) {
            continue;
        }

        let sys_path = entry.path();
        let dev_path = format!("/dev/{}", name);

        if !Path::new(&dev_path).exists() {
            continue;
        }

        match read_drive_info(&name, &sys_path, &dev_path) {
            Ok(info) => drives.push(info),
            Err(e) => {
                tracing::warn!("Skipping {}: {}", name, e);
            }
        }
    }

    drives.sort_by(|a, b| a.device_path.cmp(&b.device_path));
    Ok(drives)
}

/// Returns true if this block device name should be skipped.
fn should_skip_device(name: &str) -> bool {
    // Skip loop devices
    if name.starts_with("loop") { return true; }
    // Skip device-mapper
    if name.starts_with("dm-") { return true; }
    // Skip ram disks
    if name.starts_with("ram") { return true; }
    // Skip zram
    if name.starts_with("zram") { return true; }
    // Skip md (software RAID) arrays — handle separately
    if name.starts_with("md") && name.len() > 2 && name.chars().nth(2).map_or(false, |c| c.is_ascii_digit()) {
        return true;
    }
    // Skip sr/cdrom
    if name.starts_with("sr") { return true; }
    false
}

/// Read all available information for a single block device.
fn read_drive_info(name: &str, sys_path: &Path, dev_path: &str) -> Result<DriveInfo, WipeError> {
    // Capacity from /sys/block/<dev>/size (in 512-byte sectors)
    let size_sectors: u64 = read_sysfs_u64(sys_path, "size")
        .unwrap_or(0);
    let size_bytes = size_sectors * 512;

    // Interface / subsystem detection
    let interface = detect_interface(name, sys_path);

    // Model string
    let model = read_sysfs_string(sys_path, "device/model")
        .or_else(|| read_sysfs_string(sys_path, "device/name"))
        .unwrap_or_else(|| "Unknown".into());

    // Serial number — different paths for different subsystems
    let serial = read_serial(name, sys_path);

    // Firmware revision
    let firmware = read_sysfs_string(sys_path, "device/firmware_rev")
        .or_else(|| read_sysfs_string(sys_path, "device/firmware_version"))
        .unwrap_or_else(|| "N/A".into());

    // Rotation rate: 0 = SSD/NVMe, >1 = HDD RPM, 1 = unknown
    let rotational = read_sysfs_u64(sys_path, "queue/rotational")
        .unwrap_or(1);
    let is_rotational = rotational != 0;

    // Logical and physical sector sizes
    let logical_sector_size = read_sysfs_u64(sys_path, "queue/logical_block_size")
        .unwrap_or(512) as u32;
    let physical_sector_size = read_sysfs_u64(sys_path, "queue/physical_block_size")
        .unwrap_or(512) as u32;

    // Check if device is currently mounted (safety check)
    let is_mounted = check_mounted(dev_path);

    // Check if removable
    let is_removable = read_sysfs_u64(sys_path, "removable")
        .map(|v| v != 0)
        .unwrap_or(false);

    // Vendor
    let vendor = read_sysfs_string(sys_path, "device/vendor")
        .unwrap_or_else(|| extract_vendor_from_model(&model));

    // WWN (World Wide Name) for enterprise drives
    let wwn = read_sysfs_string(sys_path, "device/wwid")
        .or_else(|| read_sysfs_string(sys_path, "wwid"));

    // Transport (for NVMe: pcie, for SATA: ata, etc.)
    let transport = detect_transport(sys_path);

    // Partitions
    let partitions = enumerate_partitions(name, sys_path);

    Ok(DriveInfo {
        device_path: dev_path.to_string(),
        model: model.trim().to_string(),
        serial: serial.trim().to_string(),
        firmware: firmware.trim().to_string(),
        vendor: vendor.trim().to_string(),
        size_bytes,
        interface,
        is_rotational,
        logical_sector_size,
        physical_sector_size,
        is_mounted,
        is_removable,
        wwn,
        transport,
        partitions,
    })
}

/// Detect the storage interface type.
fn detect_interface(name: &str, sys_path: &Path) -> DriveInterface {
    // NVMe: device name starts with "nvme"
    if name.starts_with("nvme") {
        return DriveInterface::NVMe;
    }

    // USB: check if the device has a usb subsystem parent
    if is_usb_device(sys_path) {
        return DriveInterface::USB;
    }

    // Check driver binding for SAS vs SATA
    let driver = read_driver(sys_path);
    match driver.as_deref() {
        Some("ahci") | Some("libata") | Some("ata_piix") => DriveInterface::SATA,
        Some("mpt3sas") | Some("mpt2sas") | Some("hpsa") | Some("megaraid_sas") => {
            DriveInterface::SAS
        }
        Some("virtio-blk") | Some("virtio_blk") => DriveInterface::VirtIO,
        _ => {
            // Fall back to name-based heuristics
            if name.starts_with("sd") {
                // Could be SATA, SAS, or USB — already checked USB above
                DriveInterface::SATA
            } else if name.starts_with("hd") {
                DriveInterface::IDE
            } else if name.starts_with("vd") {
                DriveInterface::VirtIO
            } else {
                DriveInterface::Unknown
            }
        }
    }
}

/// Walk the sysfs device tree upward looking for a USB subsystem link.
fn is_usb_device(sys_path: &Path) -> bool {
    let mut current = sys_path.to_path_buf();
    for _ in 0..10 {
        // Check if 'subsystem' symlink points to usb
        let subsystem_link = current.join("subsystem");
        if let Ok(target) = fs::read_link(&subsystem_link) {
            if target.to_string_lossy().contains("usb") {
                return true;
            }
        }
        // Check for idVendor (USB-specific attribute)
        if current.join("idVendor").exists() {
            return true;
        }
        // Walk up
        match current.parent() {
            Some(p) => current = p.to_path_buf(),
            None => break,
        }
    }
    false
}

/// Read the driver name for a device.
fn read_driver(sys_path: &Path) -> Option<String> {
    let driver_link = sys_path.join("device/driver");
    if let Ok(target) = fs::read_link(&driver_link) {
        return target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
    }
    // Try one level deeper for some devices
    let driver_link2 = sys_path.join("device/device/driver");
    if let Ok(target) = fs::read_link(&driver_link2) {
        return target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
    }
    None
}

/// Detect transport protocol string.
fn detect_transport(sys_path: &Path) -> String {
    // NVMe transport type
    if let Some(transport) = read_sysfs_string(sys_path, "device/transport") {
        return transport;
    }
    // SATA/SAS: read host link speed
    if let Some(speed) = read_sysfs_string(sys_path, "device/host/target*/*/device/ata*/link/ata_link*/sata_spd") {
        return format!("SATA {}", speed);
    }
    String::from("unknown")
}

/// Serial number from various sysfs locations.
fn read_serial(name: &str, sys_path: &Path) -> String {
    // NVMe: /sys/block/nvme0n1/device/serial
    if let Some(s) = read_sysfs_string(sys_path, "device/serial") {
        return s;
    }
    // SATA: /sys/block/sda/device/vpd_pg80 (binary, skip)
    // Try the simpler path first
    if let Some(s) = read_sysfs_string(sys_path, "device/device/serial") {
        return s;
    }
    // Parse from /sys/class/block/<dev>/../../../serial (USB storage)
    let class_path = format!("/sys/class/block/{}", name);
    if let Ok(real) = fs::canonicalize(&class_path) {
        for ancestor in real.ancestors().take(6) {
            let serial_file = ancestor.join("serial");
            if serial_file.exists() {
                if let Ok(s) = fs::read_to_string(&serial_file) {
                    return s.trim().to_string();
                }
            }
        }
    }
    "N/A".to_string()
}

/// Check if block device or any of its partitions is mounted.
fn check_mounted(dev_path: &str) -> bool {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    let dev_name = dev_path.trim_start_matches("/dev/");
    for line in mounts.lines() {
        let mounted_dev = line.split_whitespace().next().unwrap_or("");
        if mounted_dev.starts_with(dev_path)
            || mounted_dev.trim_start_matches("/dev/").starts_with(dev_name)
        {
            return true;
        }
    }
    false
}

/// List partitions for a device.
fn enumerate_partitions(name: &str, sys_path: &Path) -> Vec<PartitionInfo> {
    let mut partitions = Vec::new();
    if let Ok(entries) = fs::read_dir(sys_path) {
        for entry in entries.flatten() {
            let part_name = entry.file_name().to_string_lossy().into_owned();
            // Partitions are subdirs that start with the parent device name
            if part_name.starts_with(name)
                && part_name.len() > name.len()
                && entry.path().join("partition").exists()
            {
                let part_path = format!("/dev/{}", part_name);
                let size = read_sysfs_u64(&entry.path(), "size")
                    .unwrap_or(0) * 512;
                let partition_num = read_sysfs_u64(&entry.path(), "partition")
                    .unwrap_or(0) as u32;
                let fs_type = read_filesystem_type(&part_path);
                let mount_point = get_mount_point(&part_path);

                partitions.push(PartitionInfo {
                    device_path: part_path,
                    partition_number: partition_num,
                    size_bytes: size,
                    filesystem: fs_type,
                    mount_point,
                });
            }
        }
    }
    partitions.sort_by_key(|p| p.partition_number);
    partitions
}

/// Read filesystem type from /proc/mounts.
fn read_filesystem_type(dev_path: &str) -> Option<String> {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let dev = parts.next().unwrap_or("");
        let _mount = parts.next();
        let fs = parts.next().unwrap_or("");
        if dev == dev_path {
            return Some(fs.to_string());
        }
    }
    // Try blkid output cache (read-only, may not have all devices)
    None
}

/// Get the mount point for a partition.
fn get_mount_point(dev_path: &str) -> Option<String> {
    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let dev = parts.next().unwrap_or("");
        let mount = parts.next().unwrap_or("");
        if dev == dev_path {
            return Some(mount.to_string());
        }
    }
    None
}

fn extract_vendor_from_model(model: &str) -> String {
    // Use first word of model as vendor approximation
    model.split_whitespace().next().unwrap_or("Unknown").to_string()
}

// ─── sysfs helpers ────────────────────────────────────────────────────────────

fn read_sysfs_string(base: &Path, relative: &str) -> Option<String> {
    let path = base.join(relative);
    fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn read_sysfs_u64(base: &Path, relative: &str) -> Option<u64> {
    read_sysfs_string(base, relative)?.parse().ok()
}

// ─── Additional public types ──────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PartitionInfo {
    pub device_path: String,
    pub partition_number: u32,
    pub size_bytes: u64,
    pub filesystem: Option<String>,
    pub mount_point: Option<String>,
}

/// Get detailed drive attributes for a single device (used for pre-wipe audit).
pub fn get_drive_attributes(dev_path: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    let name = dev_path.trim_start_matches("/dev/");
    let sys_path = PathBuf::from(format!("/sys/block/{}", name));

    // Collect all interesting attributes
    let fields = [
        ("queue/rotational", "rotational"),
        ("queue/logical_block_size", "logical_block_size"),
        ("queue/physical_block_size", "physical_block_size"),
        ("queue/max_hw_sectors_kb", "max_hw_sectors_kb"),
        ("queue/optimal_io_size", "optimal_io_size"),
        ("queue/discard_granularity", "discard_granularity"),
        ("queue/discard_max_bytes", "discard_max_bytes"),
        ("device/model", "model"),
        ("device/vendor", "vendor"),
        ("device/serial", "serial"),
        ("device/firmware_rev", "firmware"),
        ("device/queue_depth", "queue_depth"),
        ("device/state", "state"),
        ("size", "size_sectors"),
    ];

    for (sysfs_path, key) in &fields {
        if let Some(val) = read_sysfs_string(&sys_path, sysfs_path) {
            attrs.insert(key.to_string(), val);
        }
    }

    // Compute size in bytes
    if let Some(sectors) = attrs.get("size_sectors").and_then(|s| s.parse::<u64>().ok()) {
        attrs.insert("size_bytes".to_string(), (sectors * 512).to_string());
    }

    attrs
}

/// Verify that a device path refers to a physical block device (not a partition).
pub fn is_whole_disk(dev_path: &str) -> bool {
    let name = dev_path.trim_start_matches("/dev/");
    let sys_path = PathBuf::from(format!("/sys/block/{}", name));
    // Whole disks are directly under /sys/block; partitions are not
    sys_path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_skip_loop_devices() {
        assert!(should_skip_device("loop0"));
        assert!(should_skip_device("loop10"));
    }

    #[test]
    fn test_skip_dm_devices() {
        assert!(should_skip_device("dm-0"));
        assert!(should_skip_device("dm-15"));
    }

    #[test]
    fn test_skip_zram() {
        assert!(should_skip_device("zram0"));
    }

    #[test]
    fn test_no_skip_nvme() {
        assert!(!should_skip_device("nvme0n1"));
        assert!(!should_skip_device("sda"));
        assert!(!should_skip_device("sdb"));
    }

    #[test]
    fn test_is_whole_disk() {
        // These will only pass on a system with real block devices
        // but at minimum the function shouldn't panic
        let _ = is_whole_disk("/dev/sda");
        let _ = is_whole_disk("/dev/nvme0n1");
    }

    #[test]
    fn test_check_mounted() {
        // /dev/nonexistent should not be mounted
        assert!(!check_mounted("/dev/nonexistent_xyz"));
    }
}
