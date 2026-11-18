//! Owning-thread, synchronous fixed-capacity blocks. No event allocation or lock.
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::os::unix::{fs::OpenOptionsExt, io::IntoRawFd};
use std::path::Path;
use traceq_core::wire::{self, Event, Header, MAX_RECORDS};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Flat,
    Buffered,
    Chunked,
}

pub struct Storage {
    file: Option<BufWriter<File>>,
    events: Vec<Event>,
    bytes: Vec<u8>,
    mode: Mode,
}
unsafe extern "C" {
    fn close(fd: i32) -> i32;
}
impl Storage {
    pub fn open(path: &Path, header: Header, mode: Mode) -> io::Result<Self> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let mut writer = BufWriter::with_capacity(65536, file);
        let mut b = [0; 64];
        b[..8].copy_from_slice(if mode == Mode::Chunked {
            wire::CHUNK_MAGIC
        } else {
            wire::FLAT_MAGIC
        });
        for (dst, v) in b[8..].chunks_exact_mut(8).zip([
            header.code_base,
            header.code_size,
            header.data_base,
            header.data_size,
            header.thread_id,
            header.profile,
            64,
        ]) {
            dst.copy_from_slice(&v.to_le_bytes());
        }
        writer.write_all(&b)?;
        let records = if mode == Mode::Flat { 0 } else { MAX_RECORDS };
        Ok(Self {
            file: Some(writer),
            events: Vec::with_capacity(records),
            bytes: vec![0; records * 64],
            mode,
        })
    }
    #[inline]
    pub fn append(&mut self, e: Event) -> io::Result<()> {
        let Some(writer) = &mut self.file else {
            return Err(io::Error::other("closed capture"));
        };
        let result = if self.mode == Mode::Flat {
            let mut b = [0; 64];
            for (dst, v) in b.chunks_exact_mut(8).zip(e.words()) {
                dst.copy_from_slice(&v.to_le_bytes());
            }
            writer.write_all(&b)
        } else {
            self.events.push(e);
            if self.events.len() < MAX_RECORDS {
                return Ok(());
            }
            self.flush_block()
        };
        if result.is_err() {
            // A partial write may already be on disk. Discard the pending
            // block and close without a second write from finish or Drop.
            self.events.clear();
            if let Some(writer) = self.file.take() {
                drop(writer.into_parts());
            }
        }
        result
    }
    #[inline(never)]
    fn flush_block(&mut self) -> io::Result<()> {
        if self.events.is_empty() {
            return Ok(());
        }
        let size = if self.mode == Mode::Chunked {
            wire::encode_block_into(&self.events, &mut self.bytes).map_err(io::Error::other)?
        } else {
            for (dst, e) in self.bytes.chunks_exact_mut(64).zip(&self.events) {
                for (field, v) in dst.chunks_exact_mut(8).zip(e.words()) {
                    field.copy_from_slice(&v.to_le_bytes());
                }
            }
            self.events.len() * 64
        };
        let writer = self
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("closed capture"))?;
        if self.mode == Mode::Chunked {
            let mut h = [0; 16];
            h[..8].copy_from_slice(wire::BLOCK_MAGIC);
            h[8..12].copy_from_slice(&(self.events.len() as u32).to_le_bytes());
            h[12..].copy_from_slice(&(size as u32).to_le_bytes());
            writer.write_all(&h)?;
        }
        writer.write_all(&self.bytes[..size])?;
        self.events.clear();
        Ok(())
    }
    pub fn finish(&mut self) -> io::Result<()> {
        let flushed = self.flush_block();
        let Some(mut writer) = self.file.take() else {
            return Err(io::Error::other("closed capture"));
        };
        let flushed = flushed.and_then(|()| writer.flush());
        // Explicit close preserves the old finish failure contract. On a flush
        // error, into_parts avoids a second implicit retry during Drop.
        let (file, _) = writer.into_parts();
        let fd = file.into_raw_fd();
        let closed = unsafe { close(fd) };
        flushed.and(if closed == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use traceq_core::wire::{Input, Kind};
    static ID: AtomicU64 = AtomicU64::new(0);
    #[test]
    fn fixed_blocks_restore_and_file_errors() {
        for mode in [Mode::Flat, Mode::Buffered, Mode::Chunked] {
            let path = std::env::temp_dir().join(format!(
                "traceq-storage-{}-{}",
                std::process::id(),
                ID.fetch_add(1, Ordering::Relaxed)
            ));
            let h = Header {
                code_base: 4096,
                code_size: 64,
                data_base: 8192,
                data_size: 64,
                thread_id: 1,
                profile: 2,
            };
            let mut writer = Storage::open(&path, h, mode).unwrap();
            assert!(Storage::open(&path, h, mode).is_err());
            let expected: Vec<_> = (0..MAX_RECORDS + 1)
                .map(|i| Event {
                    kind: Kind::Exec,
                    seq: i as u64,
                    pc: 4096,
                    address: i as u64,
                    size: 0,
                    low: u64::MAX,
                    high: 0,
                    detail: 0,
                })
                .collect();
            let capacity = writer.events.capacity();
            for &e in &expected {
                writer.append(e).unwrap();
                assert_eq!(writer.events.capacity(), capacity);
            }
            writer.finish().unwrap();
            assert!(writer.append(expected[0]).is_err());
            assert!(writer.finish().is_err());
            let mut input = Input::new(File::open(&path).unwrap()).unwrap();
            for e in expected {
                assert_eq!(input.next_event().unwrap(), e);
            }
            input.finish().unwrap();
            std::fs::remove_file(path).unwrap();
        }
    }

    #[test]
    fn failed_write_closes_storage_and_never_retries_pending_records() {
        let path = std::env::temp_dir().join(format!(
            "traceq-storage-write-error-{}-{}",
            std::process::id(),
            ID.fetch_add(1, Ordering::Relaxed)
        ));
        File::create_new(&path).unwrap();
        let event = Event::from_words([1, 0, 4096, 0, 0, 0, 0, 0]).unwrap();
        for mode in [Mode::Flat, Mode::Buffered, Mode::Chunked] {
            let mut storage = Storage {
                file: Some(BufWriter::with_capacity(0, File::open(&path).unwrap())),
                events: Vec::with_capacity(MAX_RECORDS),
                bytes: vec![0; MAX_RECORDS * 64],
                mode,
            };
            if mode != Mode::Flat {
                for _ in 0..MAX_RECORDS - 1 {
                    storage.append(event).unwrap();
                }
            }
            assert!(storage.append(event).is_err());
            assert!(storage.file.is_none() && storage.events.is_empty());
            assert!(storage.append(event).is_err());
            assert!(storage.finish().is_err());
        }
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_file(path).unwrap();
    }
}
