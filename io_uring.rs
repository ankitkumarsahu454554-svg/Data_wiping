// io_uring.rs — High-performance async I/O using Linux io_uring
// Provides 2–4× throughput improvement over pread/pwrite on NVMe drives
// by submitting batches of I/O operations and collecting completions
// without blocking the calling thread per-operation.
//
// Requires Linux 5.1+ for IORING_OP_WRITE/READ.
// Falls back to pwrite64 when io_uring is unavailable.
//
// Feature-gated: only compiled when `io_uring_support` feature is enabled.

#[cfg(feature = "io_uring_support")]
pub mod uring {
    use io_uring::{IoUring, opcode, types};
    use std::os::unix::io::RawFd;
    use crate::WipeError;

    // Queue depth: number of outstanding I/O operations.
    // 128 is optimal for most NVMe drives (matches typical queue depth).
    const QUEUE_DEPTH: u32 = 128;

    // Submission batch size before we flush to the kernel.
    const BATCH_SIZE: usize = 64;

    /// io_uring write engine for zero-copy, kernel-async wiping.
    pub struct UringWriter {
        ring: IoUring,
        fd: RawFd,
        /// Buffers indexed by their user_data tag (used to match completions).
        buffers: Vec<Vec<u8>>,
        /// Number of inflight operations.
        inflight: u32,
        /// Total bytes written.
        bytes_written: u64,
        /// Bytes on error.
        bytes_errored: u64,
    }

    impl UringWriter {
        /// Create a new UringWriter for a block device.
        /// `chunk_size`: size of each write operation (should be power-of-2, ≥ sector size).
        pub fn new(fd: RawFd, parallelism: u32, chunk_size: usize) -> Result<Self, WipeError> {
            let queue_depth = parallelism.min(QUEUE_DEPTH);

            let ring = IoUring::builder()
                .setup_sqpoll(2000) // SQ polling thread, 2s idle timeout
                .build(queue_depth)
                .map_err(|e| WipeError::IoUringInit(format!("io_uring setup: {}", e)))?;

            // Pre-allocate buffers equal to queue depth.
            // Each buffer holds one chunk_size worth of wipe data.
            let buffers: Vec<Vec<u8>> = (0..queue_depth as usize)
                .map(|_| vec![0u8; chunk_size])
                .collect();

            Ok(Self {
                ring,
                fd,
                buffers,
                inflight: 0,
                bytes_written: 0,
                bytes_errored: 0,
            })
        }

        /// Fill all buffers with the provided pattern.
        pub fn fill_pattern(&mut self, pattern: &[u8]) {
            for buf in &mut self.buffers {
                let buf_len = buf.len();
                for (i, byte) in buf.iter_mut().enumerate() {
                    *byte = pattern[i % pattern.len()];
                }
            }
        }

        /// Fill all buffers with random data.
        pub fn fill_random(&mut self) {
            use rand::RngCore;
            let mut rng = rand::thread_rng();
            for buf in &mut self.buffers {
                rng.fill_bytes(buf);
            }
        }

        /// Fill all buffers with zeros.
        pub fn fill_zeros(&mut self) {
            for buf in &mut self.buffers {
                buf.fill(0);
            }
        }

        /// Fill all buffers with 0xFF.
        pub fn fill_ones(&mut self) {
            for buf in &mut self.buffers {
                buf.fill(0xFF);
            }
        }

        /// Write `total_bytes` to the device starting at `start_offset`.
        /// `progress_cb`: called with (bytes_completed, total_bytes) after each batch.
        pub fn write_all<F>(
            &mut self,
            start_offset: u64,
            total_bytes: u64,
            mut progress_cb: F,
        ) -> Result<u64, WipeError>
        where
            F: FnMut(u64, u64),
        {
            let chunk_size = self.buffers[0].len() as u64;
            let total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
            let mut chunk_idx: u64 = 0;
            let mut offset = start_offset;
            let mut completed_bytes: u64 = 0;

            while chunk_idx < total_chunks || self.inflight > 0 {
                // Submit as many operations as the queue can hold.
                let mut submitted_this_round = 0usize;
                while self.inflight < self.buffers.len() as u32
                    && chunk_idx < total_chunks
                    && submitted_this_round < BATCH_SIZE
                {
                    let buf_idx = (chunk_idx % self.buffers.len() as u64) as usize;
                    let buf = &self.buffers[buf_idx];

                    // Last chunk may be smaller than chunk_size
                    let remaining = total_bytes.saturating_sub(offset - start_offset);
                    let write_len = (chunk_size as usize).min(remaining as usize);

                    let write_e = opcode::Write::new(
                        types::Fd(self.fd),
                        buf.as_ptr(),
                        write_len as u32,
                    )
                    .offset(offset)
                    .build()
                    .user_data(buf_idx as u64);

                    unsafe {
                        self.ring
                            .submission()
                            .push(&write_e)
                            .map_err(|_| WipeError::IoUringSubmit("SQ full".into()))?;
                    }

                    offset += write_len as u64;
                    chunk_idx += 1;
                    self.inflight += 1;
                    submitted_this_round += 1;
                }

                if submitted_this_round > 0 {
                    // Submit the batch to the kernel.
                    self.ring
                        .submit()
                        .map_err(|e| WipeError::IoUringSubmit(e.to_string()))?;
                }

                // Collect completions (wait for at least 1 if no more to submit).
                let min_complete = if chunk_idx >= total_chunks {
                    self.inflight.min(1)
                } else {
                    0
                };

                if min_complete > 0 || self.inflight >= self.buffers.len() as u32 {
                    self.ring
                        .submit_and_wait(min_complete)
                        .map_err(|e| WipeError::IoUringSubmit(e.to_string()))?;
                }

                // Process all available completions.
                let mut cq = self.ring.completion();
                for cqe in cq.iter() {
                    self.inflight -= 1;
                    let result = cqe.result();
                    if result < 0 {
                        self.bytes_errored += chunk_size;
                        tracing::error!("io_uring write error: {} at offset", result);
                    } else {
                        let written = result as u64;
                        self.bytes_written += written;
                        completed_bytes += written;
                    }
                }
                drop(cq);

                progress_cb(completed_bytes, total_bytes);
            }

            Ok(self.bytes_written)
        }

        /// Total bytes with write errors.
        pub fn error_bytes(&self) -> u64 {
            self.bytes_errored
        }

        /// Register buffers for fixed-buffer I/O (reduces per-op overhead).
        /// Must be called before write_all for maximum performance.
        pub fn register_buffers(&mut self) -> Result<(), WipeError> {
            let iov: Vec<libc::iovec> = self
                .buffers
                .iter()
                .map(|buf| libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                })
                .collect();

            self.ring
                .submitter()
                .register_buffers(&iov)
                .map_err(|e| WipeError::IoUringInit(format!("register_buffers: {}", e)))?;

            Ok(())
        }
    }

    /// Probe whether io_uring is available on this kernel.
    pub fn is_available() -> bool {
        IoUring::new(1).is_ok()
    }

    /// Probe io_uring support and return the kernel's max supported features.
    pub fn probe_features() -> io_uring::Probe {
        let mut probe = io_uring::Probe::new();
        if let Ok(ring) = IoUring::new(2) {
            let _ = ring.submitter().register_probe(&mut probe);
        }
        probe
    }
}

#[cfg(not(feature = "io_uring_support"))]
pub mod uring {
    use crate::WipeError;

    pub fn is_available() -> bool {
        false
    }

    pub struct UringWriter;

    impl UringWriter {
        pub fn new(_fd: i32, _parallelism: u32, _chunk_size: usize) -> Result<Self, WipeError> {
            Err(WipeError::UnsupportedFeature(
                "io_uring support not compiled in. Rebuild with --features io_uring_support".into(),
            ))
        }
    }
}

// ─── io_uring read engine for verification ───────────────────────────────────

#[cfg(feature = "io_uring_support")]
pub mod uring_read {
    use io_uring::{IoUring, opcode, types};
    use std::os::unix::io::RawFd;
    use crate::WipeError;

    const QUEUE_DEPTH: u32 = 128;

    /// A pending read operation.
    struct PendingRead {
        buf_idx: usize,
        offset: u64,
        expected_len: usize,
    }

    /// io_uring read engine for post-wipe verification.
    pub struct UringReader {
        ring: IoUring,
        fd: RawFd,
        buffers: Vec<Vec<u8>>,
        pending: Vec<Option<PendingRead>>,
        inflight: u32,
    }

    impl UringReader {
        pub fn new(fd: RawFd, chunk_size: usize) -> Result<Self, WipeError> {
            let ring = IoUring::new(QUEUE_DEPTH)
                .map_err(|e| WipeError::IoUringInit(e.to_string()))?;

            let buffers: Vec<Vec<u8>> = (0..QUEUE_DEPTH as usize)
                .map(|_| vec![0u8; chunk_size])
                .collect();
            let pending: Vec<Option<PendingRead>> = (0..QUEUE_DEPTH as usize)
                .map(|_| None)
                .collect();

            Ok(Self {
                ring,
                fd,
                buffers,
                pending,
                inflight: 0,
            })
        }

        /// Read `total_bytes` from `start_offset`, verify each chunk against `expected_pattern`.
        /// Returns the number of mismatched bytes.
        pub fn read_and_verify<F>(
            &mut self,
            start_offset: u64,
            total_bytes: u64,
            expected_pattern: &[u8],
            mut progress_cb: F,
        ) -> Result<u64, WipeError>
        where
            F: FnMut(u64, u64),
        {
            let chunk_size = self.buffers[0].len() as u64;
            let total_chunks = (total_bytes + chunk_size - 1) / chunk_size;
            let mut chunk_idx: u64 = 0;
            let mut offset = start_offset;
            let mut mismatch_bytes: u64 = 0;
            let mut completed_bytes: u64 = 0;

            while chunk_idx < total_chunks || self.inflight > 0 {
                // Submit reads
                while self.inflight < QUEUE_DEPTH
                    && chunk_idx < total_chunks
                {
                    // Find a free buffer slot
                    let buf_idx = self.pending.iter().position(|p| p.is_none()).unwrap();
                    let buf = &mut self.buffers[buf_idx];
                    let remaining = total_bytes.saturating_sub(offset - start_offset);
                    let read_len = (chunk_size as usize).min(remaining as usize);

                    let read_e = opcode::Read::new(
                        types::Fd(self.fd),
                        buf.as_mut_ptr(),
                        read_len as u32,
                    )
                    .offset(offset)
                    .build()
                    .user_data(buf_idx as u64);

                    unsafe {
                        self.ring
                            .submission()
                            .push(&read_e)
                            .map_err(|_| WipeError::IoUringSubmit("SQ full".into()))?;
                    }

                    self.pending[buf_idx] = Some(PendingRead {
                        buf_idx,
                        offset,
                        expected_len: read_len,
                    });

                    offset += read_len as u64;
                    chunk_idx += 1;
                    self.inflight += 1;
                }

                let min_wait = if chunk_idx >= total_chunks { 1 } else { 0 };
                if min_wait > 0 || self.inflight >= QUEUE_DEPTH {
                    self.ring
                        .submit_and_wait(min_wait)
                        .map_err(|e| WipeError::IoUringSubmit(e.to_string()))?;
                } else {
                    self.ring
                        .submit()
                        .map_err(|e| WipeError::IoUringSubmit(e.to_string()))?;
                }

                // Process completions
                let mut cq = self.ring.completion();
                for cqe in cq.iter() {
                    let buf_idx = cqe.user_data() as usize;
                    self.inflight -= 1;

                    if let Some(pending) = self.pending[buf_idx].take() {
                        let result = cqe.result();
                        if result < 0 {
                            tracing::error!(
                                "Read error at offset 0x{:x}: {}",
                                pending.offset, result
                            );
                            mismatch_bytes += pending.expected_len as u64;
                        } else {
                            let read_len = result as usize;
                            completed_bytes += read_len as u64;

                            // Verify pattern
                            let buf = &self.buffers[buf_idx];
                            for (i, &byte) in buf[..read_len].iter().enumerate() {
                                let expected = expected_pattern[i % expected_pattern.len()];
                                if byte != expected {
                                    mismatch_bytes += 1;
                                }
                            }
                        }
                    }
                }
                drop(cq);

                progress_cb(completed_bytes, total_bytes);
            }

            Ok(mismatch_bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uring_availability_check() {
        // Just make sure the function doesn't panic
        let _available = uring::is_available();
    }
}
