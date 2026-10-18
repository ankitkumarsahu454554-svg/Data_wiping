// hpa_dco.rs — Host Protected Area (HPA) and Device Configuration Overlay (DCO)
// Detection and removal via ATA commands (IDENTIFY DEVICE, SET MAX, DCO IDENTIFY).
//
// HPA allows a drive to report a smaller capacity than its true capacity.
// DCO allows OEMs to permanently disable drive features/capacity.
// Both must be cleared before wiping to ensure full media coverage (NIST SP 800-88).

use std::fs::{File, OpenOptions};
use std::os::unix::io::AsRawFd;
use libc::{c_int, ioctl};
use crate::WipeError;

// ─── ATA command constants ────────────────────────────────────────────────────

const ATA_CMD_IDENTIFY: u8 = 0xEC;
const ATA_CMD_READ_NATIVE_MAX: u8 = 0xF8;      // READ NATIVE MAX ADDRESS
const ATA_CMD_SET_MAX: u8 = 0xF9;              // SET MAX ADDRESS (disable HPA)
const ATA_CMD_READ_NATIVE_MAX_EXT: u8 = 0x27;  // 48-bit LBA version
const ATA_CMD_SET_MAX_EXT: u8 = 0x37;          // 48-bit LBA version

// DCO commands
const ATA_CMD_DCO_IDENTIFY: u16 = 0xB1;        // Device Configuration Identify
const ATA_CMD_DCO_RESTORE: u16 = 0xB1;         // Device Configuration Restore
const DCO_IDENTIFY_FEATURE: u8 = 0xC2;
const DCO_RESTORE_FEATURE: u8 = 0xC0;

// HDIO ioctl codes
const HDIO_DRIVE_CMD: u64 = 0x031f;
const HDIO_DRIVE_TASK: u64 = 0x031e;

// SG_IO (SCSI Generic) for ATA PASSTHROUGH
const SG_IO: u64 = 0x2285;
const ATA_16_CMD_LEN: usize = 16;
const SG_DXFER_FROM_DEV: i32 = -3;
const SG_DXFER_TO_DEV: i32 = -2;

/// HPA and DCO status for a drive.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HpaDcoStatus {
    /// Reported capacity (sectors) — what OS sees
    pub reported_sectors: u64,
    /// Native maximum address — true capacity without HPA
    pub native_max_sectors: u64,
    /// Whether HPA is active (reported < native)
    pub hpa_active: bool,
    /// HPA size in bytes (0 if not active)
    pub hpa_hidden_bytes: u64,
    /// Whether DCO has been applied
    pub dco_active: bool,
    /// DCO max LBA if available
    pub dco_max_lba: Option<u64>,
    /// Whether the drive supports 48-bit LBA
    pub lba48_supported: bool,
    /// Whether HPA security feature is enabled (password-protected HPA)
    pub hpa_security: bool,
}

/// Check HPA and DCO status for a device.
pub fn check_hpa_dco(dev_path: &str) -> Result<HpaDcoStatus, WipeError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| WipeError::DeviceOpenFailed(format!("{}: {}", dev_path, e)))?;

    let fd = file.as_raw_fd();
    let identify_data = ata_identify(fd)?;

    let lba48 = is_lba48_supported(&identify_data);
    let reported = get_reported_capacity(&identify_data, lba48);
    let native_max = read_native_max_address(fd, lba48)?;
    let hpa_active = native_max > reported;
    let hpa_hidden = if hpa_active {
        (native_max - reported) * 512
    } else {
        0
    };

    // Check DCO — word 83 bit 11 indicates DCO support
    let dco_supported = (identify_data[83] & (1 << 11)) != 0;
    let (dco_active, dco_max_lba) = if dco_supported {
        match dco_identify(fd) {
            Ok((active, max_lba)) => (active, Some(max_lba)),
            Err(_) => (false, None),
        }
    } else {
        (false, None)
    };

    // HPA security: word 128 bit 10
    let hpa_security = (identify_data[128] & (1 << 10)) != 0;

    Ok(HpaDcoStatus {
        reported_sectors: reported,
        native_max_sectors: native_max,
        hpa_active,
        hpa_hidden_bytes: hpa_hidden,
        dco_active,
        dco_max_lba,
        lba48_supported: lba48,
        hpa_security,
    })
}

/// Disable HPA by issuing SET MAX ADDRESS to the native maximum.
/// Returns the new reported capacity in sectors.
pub fn disable_hpa(dev_path: &str) -> Result<u64, WipeError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| WipeError::DeviceOpenFailed(format!("{}: {}", dev_path, e)))?;

    let fd = file.as_raw_fd();
    let identify_data = ata_identify(fd)?;
    let lba48 = is_lba48_supported(&identify_data);
    let native_max = read_native_max_address(fd, lba48)?;
    let reported = get_reported_capacity(&identify_data, lba48);

    if native_max <= reported {
        tracing::info!("HPA not active on {} (reported={}, native={})", dev_path, reported, native_max);
        return Ok(reported);
    }

    tracing::info!(
        "Disabling HPA on {}: extending from {} to {} sectors (+{} MB)",
        dev_path,
        reported,
        native_max,
        (native_max - reported) * 512 / 1_048_576
    );

    set_max_address(fd, native_max - 1, lba48, false)?;

    // Verify the change took effect
    let identify_after = ata_identify(fd)?;
    let new_capacity = get_reported_capacity(&identify_after, lba48);

    if new_capacity < native_max {
        tracing::warn!(
            "HPA disable may be incomplete: new={}, native={}", new_capacity, native_max
        );
    }

    Ok(new_capacity)
}

/// Restore DCO to factory defaults.
/// WARNING: This is irreversible and may change drive features permanently.
pub fn restore_dco(dev_path: &str) -> Result<(), WipeError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(dev_path)
        .map_err(|e| WipeError::DeviceOpenFailed(format!("{}: {}", dev_path, e)))?;

    let fd = file.as_raw_fd();
    let identify_data = ata_identify(fd)?;

    // Verify DCO is supported (word 83 bit 11)
    if (identify_data[83] & (1 << 11)) == 0 {
        return Err(WipeError::UnsupportedFeature(
            "DCO not supported on this drive".into(),
        ));
    }

    tracing::info!("Restoring DCO on {} — this is irreversible", dev_path);
    dco_restore(fd)?;

    tracing::info!("DCO restore completed for {}", dev_path);
    Ok(())
}

// ─── Low-level ATA commands ───────────────────────────────────────────────────

/// Issue ATA IDENTIFY DEVICE and return the 256-word result.
fn ata_identify(fd: c_int) -> Result<[u16; 256], WipeError> {
    // HDIO_DRIVE_CMD layout: [cmd, nsect, feature, sector, buf...]
    // For IDENTIFY: cmd=0xEC, nsect=1 (read 512 bytes)
    let mut buf = [0u8; 4 + 512];
    buf[0] = ATA_CMD_IDENTIFY; // command
    buf[1] = 1;                 // sector count (1 = 512 bytes)
    buf[2] = 0;                 // feature
    buf[3] = 0;                 // sector number

    let ret = unsafe { ioctl(fd, HDIO_DRIVE_CMD, buf.as_mut_ptr()) };
    if ret < 0 {
        // HDIO_DRIVE_CMD failed — try SG_IO ATA PASSTHROUGH
        return ata_identify_sg(fd);
    }

    // Parse the 512-byte IDENTIFY response into u16 words
    let mut words = [0u16; 256];
    for (i, w) in words.iter_mut().enumerate() {
        let off = 4 + i * 2;
        *w = u16::from_le_bytes([buf[off], buf[off + 1]]);
    }
    Ok(words)
}

/// ATA IDENTIFY via SG_IO PASS-THROUGH (fallback for SATA/SAS controllers
/// that don't support HDIO_DRIVE_CMD directly).
fn ata_identify_sg(fd: c_int) -> Result<[u16; 256], WipeError> {
    let mut data_buf = [0u8; 512];

    // ATA16 CDB: [operation_code, protocol/multiple_count, flags,
    //             features_high, features_low, count_high, count_low,
    //             lba_low_high, lba_low_low, lba_mid_high, lba_mid_low,
    //             lba_high_high, lba_high_low, device, command, control]
    let cdb: [u8; ATA_16_CMD_LEN] = [
        0x85,          // ATA PASS-THROUGH (16)
        0x08,          // protocol: PIO Data-In
        0x0e,          // CK_COND=0, T_DIR=1 (to host), BYT_BLOK=1, T_LENGTH=2
        0x00, 0x00,    // features
        0x00, 0x01,    // sector count = 1
        0x00, 0x00,    // LBA low
        0x00, 0x00,    // LBA mid
        0x00, 0x00,    // LBA high
        0x00,          // device
        ATA_CMD_IDENTIFY, // command
        0x00,          // control
    ];

    issue_sg_io(fd, &cdb, &mut data_buf, SG_DXFER_FROM_DEV)?;

    let mut words = [0u16; 256];
    for (i, w) in words.iter_mut().enumerate() {
        let off = i * 2;
        *w = u16::from_le_bytes([data_buf[off], data_buf[off + 1]]);
    }
    Ok(words)
}

/// READ NATIVE MAX ADDRESS (28-bit or 48-bit).
fn read_native_max_address(fd: c_int, lba48: bool) -> Result<u64, WipeError> {
    if lba48 {
        read_native_max_ext(fd)
    } else {
        read_native_max_28(fd)
    }
}

fn read_native_max_28(fd: c_int) -> Result<u64, WipeError> {
    // HDIO_DRIVE_TASK: [cmd, feature, nsect, sect, lcyl, hcyl, sel, status, ...]
    let mut regs = [0u8; 7];
    regs[0] = ATA_CMD_READ_NATIVE_MAX; // command
    regs[1] = 0;                        // feature
    regs[2] = 0;                        // sector count
    regs[3] = 0;                        // sector (LBA bits 0-7)
    regs[4] = 0;                        // lcyl (LBA bits 8-15)
    regs[5] = 0;                        // hcyl (LBA bits 16-23)
    regs[6] = 0x40;                     // sel: LBA=1

    let ret = unsafe { ioctl(fd, HDIO_DRIVE_TASK, regs.as_mut_ptr()) };
    if ret < 0 {
        return Err(WipeError::IoctlFailed(
            format!("READ NATIVE MAX ADDRESS failed: errno={}", unsafe { *libc::__errno_location() })
        ));
    }

    // sector, lcyl, hcyl, device contain the result
    let lba = (regs[3] as u64)
        | ((regs[4] as u64) << 8)
        | ((regs[5] as u64) << 16)
        | (((regs[6] & 0x0F) as u64) << 24);

    Ok(lba + 1) // native max LBA is 0-based, convert to sector count
}

fn read_native_max_ext(fd: c_int) -> Result<u64, WipeError> {
    // Must use SG_IO for 48-bit commands
    let mut data_buf = [0u8; 512]; // dummy, no data transfer

    let cdb: [u8; ATA_16_CMD_LEN] = [
        0x85,
        0x04,          // protocol: Non-data
        0x00,
        0x00, 0x00,    // features
        0x00, 0x00,    // count
        0x00, 0x00,    // LBA low
        0x00, 0x00,    // LBA mid
        0x00, 0x00,    // LBA high
        0x40,          // device: LBA=1
        ATA_CMD_READ_NATIVE_MAX_EXT,
        0x00,
    ];

    // We need status registers back — use CHECK_CONDITION
    // For simplicity, use the sense buffer to recover LBA
    let mut sense = [0u8; 32];
    issue_sg_io_with_sense(fd, &cdb, &mut data_buf, SG_DXFER_FROM_DEV, &mut sense)?;

    // ATA Status Return sense descriptor (sense[0]=0x72, sense[7]>=0x0e, descriptor at sense[8])
    // descriptor type 0x09 = ATA Return Descriptor
    if sense[0] == 0x72 && sense[8] == 0x09 {
        let lba_low_48 = sense[11] as u64;
        let lba_mid_48 = sense[13] as u64;
        let lba_high_48 = sense[15] as u64;
        let lba_low_lsb = sense[12] as u64;
        let lba_mid_lsb = sense[14] as u64;
        let lba_high_lsb = sense[16] as u64;

        let lba = lba_low_lsb
            | (lba_mid_lsb << 8)
            | (lba_high_lsb << 16)
            | (lba_low_48 << 24)
            | (lba_mid_48 << 32)
            | (lba_high_48 << 40);

        return Ok(lba + 1);
    }

    Err(WipeError::IoctlFailed("Could not parse READ NATIVE MAX EXT response".into()))
}

/// SET MAX ADDRESS to disable HPA.
/// `volatile_flag`: if true, the change is lost on power cycle.
fn set_max_address(fd: c_int, max_lba: u64, lba48: bool, volatile_flag: bool) -> Result<(), WipeError> {
    let feature: u8 = if volatile_flag { 0x01 } else { 0x00 };

    let cdb: [u8; ATA_16_CMD_LEN] = if lba48 {
        let lba_bytes = max_lba.to_le_bytes();
        [
            0x85,
            0x06,          // protocol: Non-data
            0x00,
            feature, 0x00, // features
            0x00, 0x00,    // count
            lba_bytes[3], lba_bytes[0], // LBA low (high, low)
            lba_bytes[4], lba_bytes[1], // LBA mid
            lba_bytes[5], lba_bytes[2], // LBA high
            0x40,
            ATA_CMD_SET_MAX_EXT,
            0x00,
        ]
    } else {
        let lba_bytes = (max_lba as u32).to_le_bytes();
        [
            0x85,
            0x04,
            0x00,
            feature, 0x00,
            0x00, 0x00,
            0x00, lba_bytes[0],
            0x00, lba_bytes[1],
            0x00, lba_bytes[2],
            0x40 | (lba_bytes[3] & 0x0F),
            ATA_CMD_SET_MAX,
            0x00,
        ]
    };

    let mut dummy = [0u8; 512];
    issue_sg_io(fd, &cdb, &mut dummy, SG_DXFER_TO_DEV)
        .map_err(|_| WipeError::IoctlFailed("SET MAX ADDRESS failed".into()))?;

    Ok(())
}

/// DCO IDENTIFY — returns (dco_active, dco_max_lba).
fn dco_identify(fd: c_int) -> Result<(bool, u64), WipeError> {
    let mut data_buf = [0u8; 512];

    let cdb: [u8; ATA_16_CMD_LEN] = [
        0x85,
        0x08,          // PIO Data-In
        0x0e,
        DCO_IDENTIFY_FEATURE, 0x00,
        0x00, 0x01,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xA0,
        ATA_CMD_DCO_IDENTIFY as u8,
        0x00,
    ];

    issue_sg_io(fd, &cdb, &mut data_buf, SG_DXFER_FROM_DEV)
        .map_err(|_| WipeError::UnsupportedFeature("DCO IDENTIFY failed".into()))?;

    // Words in DCO IDENTIFY response:
    // Word 1: revision
    // Words 5-6: maximum LBA (48-bit)
    let max_lba = (data_buf[10] as u64)
        | ((data_buf[11] as u64) << 8)
        | ((data_buf[12] as u64) << 16)
        | ((data_buf[13] as u64) << 24);

    // Word 0 != 0 indicates DCO is active
    let dco_active = u16::from_le_bytes([data_buf[0], data_buf[1]]) != 0;

    Ok((dco_active, max_lba))
}

/// DCO RESTORE — resets all DCO changes to factory defaults.
fn dco_restore(fd: c_int) -> Result<(), WipeError> {
    let cdb: [u8; ATA_16_CMD_LEN] = [
        0x85,
        0x04,          // Non-data
        0x00,
        DCO_RESTORE_FEATURE, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0x00, 0x00,
        0xA0,
        ATA_CMD_DCO_RESTORE as u8,
        0x00,
    ];

    let mut dummy = [0u8; 512];
    issue_sg_io(fd, &cdb, &mut dummy, SG_DXFER_TO_DEV)
        .map_err(|_| WipeError::IoctlFailed("DCO RESTORE failed".into()))
}

// ─── SG_IO wrapper ────────────────────────────────────────────────────────────

#[repr(C)]
struct SgIoHdr {
    interface_id: c_int,         // 'S'
    dxfer_direction: c_int,
    cmd_len: u8,
    mx_sb_len: u8,
    iovec_count: u16,
    dxfer_len: u32,
    dxferp: *mut u8,
    cmdp: *const u8,
    sbp: *mut u8,
    timeout: u32,
    flags: u32,
    pack_id: c_int,
    usr_ptr: *mut libc::c_void,
    status: u8,
    masked_status: u8,
    msg_status: u8,
    sb_len_wr: u8,
    host_status: u16,
    driver_status: u16,
    resid: c_int,
    duration: u32,
    info: u32,
}

fn issue_sg_io(
    fd: c_int,
    cdb: &[u8; ATA_16_CMD_LEN],
    data: &mut [u8],
    direction: i32,
) -> Result<(), WipeError> {
    let mut sense = [0u8; 32];
    issue_sg_io_with_sense(fd, cdb, data, direction, &mut sense)
}

fn issue_sg_io_with_sense(
    fd: c_int,
    cdb: &[u8; ATA_16_CMD_LEN],
    data: &mut [u8],
    direction: i32,
    sense: &mut [u8; 32],
) -> Result<(), WipeError> {
    let mut hdr = SgIoHdr {
        interface_id: b'S' as c_int,
        dxfer_direction: direction,
        cmd_len: ATA_16_CMD_LEN as u8,
        mx_sb_len: 32,
        iovec_count: 0,
        dxfer_len: data.len() as u32,
        dxferp: data.as_mut_ptr(),
        cmdp: cdb.as_ptr(),
        sbp: sense.as_mut_ptr(),
        timeout: 30_000, // 30 second timeout
        flags: 0,
        pack_id: 0,
        usr_ptr: std::ptr::null_mut(),
        status: 0,
        masked_status: 0,
        msg_status: 0,
        sb_len_wr: 0,
        host_status: 0,
        driver_status: 0,
        resid: 0,
        duration: 0,
        info: 0,
    };

    let ret = unsafe { ioctl(fd, SG_IO, &mut hdr as *mut SgIoHdr) };
    if ret < 0 {
        return Err(WipeError::IoctlFailed(format!(
            "SG_IO ioctl failed: errno={}",
            unsafe { *libc::__errno_location() }
        )));
    }

    if hdr.host_status != 0 {
        return Err(WipeError::IoctlFailed(format!(
            "SG_IO host error: host_status=0x{:04x}",
            hdr.host_status
        )));
    }

    // Allow CHECK_CONDITION for ATA Status Return
    if hdr.status != 0 && hdr.status != 0x02 {
        return Err(WipeError::IoctlFailed(format!(
            "SG_IO command error: status=0x{:02x}",
            hdr.status
        )));
    }

    Ok(())
}

// ─── IDENTIFY DEVICE field helpers ───────────────────────────────────────────

/// Check if drive supports 48-bit LBA addressing (word 83 bit 10).
fn is_lba48_supported(identify: &[u16; 256]) -> bool {
    (identify[83] & (1 << 10)) != 0
}

/// Get the reported capacity from IDENTIFY DEVICE.
fn get_reported_capacity(identify: &[u16; 256], lba48: bool) -> u64 {
    if lba48 {
        // Words 100-103: total sectors (48-bit)
        (identify[100] as u64)
            | ((identify[101] as u64) << 16)
            | ((identify[102] as u64) << 32)
            | ((identify[103] as u64) << 48)
    } else {
        // Words 60-61: total sectors (28-bit)
        (identify[60] as u64) | ((identify[61] as u64) << 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lba48_detection() {
        let mut id = [0u16; 256];
        id[83] = 1 << 10;
        assert!(is_lba48_supported(&id));

        id[83] = 0;
        assert!(!is_lba48_supported(&id));
    }

    #[test]
    fn test_reported_capacity_28bit() {
        let mut id = [0u16; 256];
        id[60] = 0x0800;
        id[61] = 0x0000;
        let cap = get_reported_capacity(&id, false);
        assert_eq!(cap, 0x0800);
    }

    #[test]
    fn test_reported_capacity_48bit() {
        let mut id = [0u16; 256];
        id[100] = 0xFFFF;
        id[101] = 0x0001;
        let cap = get_reported_capacity(&id, true);
        assert_eq!(cap, 0x0001_FFFF);
    }
}
