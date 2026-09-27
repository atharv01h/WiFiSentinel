// wifisentinel-capture/src/pcap_io.rs
// PCAP and PCAPNG file reader/writer.
//
// PCAP format reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
// PCAPNG format reference: https://pcapng.com/

use std::io::{self, BufReader, Read, Write};
use std::path::Path;
use std::fs::File;

use wifisentinel_core::Error;

// ──────────────────────────────────────────────
// PCAP Magic Numbers
// ──────────────────────────────────────────────

const PCAP_MAGIC_LE: u32 = 0xA1B2C3D4;
const PCAP_MAGIC_LE_NS: u32 = 0xA1B23C4D;
const PCAP_MAGIC_BE: u32 = 0xD4C3B2A1;
const PCAP_LINK_IEEE80211: u32 = 105;
const PCAP_LINK_IEEE80211_RADIOTAP: u32 = 127;

// ──────────────────────────────────────────────
// PCAP Reader
// ──────────────────────────────────────────────

pub struct PcapReader {
    pub link_type: u32,
    pub timestamps_nanoseconds: bool,
    /// Whether byte-swapping is needed (BE pcap).
    swap_bytes: bool,
    reader: BufReader<File>,
    pub global_header: PcapGlobalHeader,
}

#[derive(Debug)]
pub struct PcapGlobalHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    pub snaplen: u32,
    pub link_type: u32,
}

#[derive(Debug)]
pub struct PcapRecord {
    pub timestamp_sec: u32,
    pub timestamp_frac: u32,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}

impl PcapReader {
    /// Open a PCAP file for reading.
    ///
    /// Returns an error on malformed headers rather than panicking.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let file = File::open(path)
            .map_err(|e| Error::Io(e))?;
        let mut reader = BufReader::new(file);

        // Read magic number to determine endianness.
        let magic = read_u32_le(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read magic number".into() })?;

        let (swap_bytes, ns_timestamps) = match magic {
            PCAP_MAGIC_LE => (false, false),
            PCAP_MAGIC_LE_NS => (false, true),
            PCAP_MAGIC_BE => (true, false),
            other => {
                return Err(Error::PcapMalformed {
                    reason: format!("Unknown PCAP magic: 0x{:08X}. This may be a PCAPNG file or a non-PCAP format.", other),
                });
            }
        };

        let read_u16 = |r: &mut BufReader<File>| -> io::Result<u16> {
            let mut buf = [0u8; 2];
            r.read_exact(&mut buf)?;
            let v = u16::from_le_bytes(buf);
            Ok(if swap_bytes { v.swap_bytes() } else { v })
        };
        let read_u32 = |r: &mut BufReader<File>| -> io::Result<u32> {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            let v = u32::from_le_bytes(buf);
            Ok(if swap_bytes { v.swap_bytes() } else { v })
        };
        let read_i32 = |r: &mut BufReader<File>| -> io::Result<i32> {
            let mut buf = [0u8; 4];
            r.read_exact(&mut buf)?;
            let v = i32::from_le_bytes(buf);
            Ok(if swap_bytes { v.swap_bytes() } else { v })
        };

        let version_major = read_u16(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read version_major".into() })?;
        let version_minor = read_u16(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read version_minor".into() })?;
        let thiszone = read_i32(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read thiszone".into() })?;
        let sigfigs = read_u32(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read sigfigs".into() })?;
        let snaplen = read_u32(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read snaplen".into() })?;
        let link_type = read_u32(&mut reader)
            .map_err(|_| Error::PcapMalformed { reason: "Could not read link_type".into() })?;

        // Validate link type.
        if link_type != PCAP_LINK_IEEE80211 && link_type != PCAP_LINK_IEEE80211_RADIOTAP {
            tracing::warn!(
                "PCAP link type {} may not be 802.11. \
                 Expected {} (IEEE 802.11) or {} (Radiotap + 802.11).",
                link_type, PCAP_LINK_IEEE80211, PCAP_LINK_IEEE80211_RADIOTAP
            );
        }

        Ok(Self {
            link_type,
            timestamps_nanoseconds: ns_timestamps,
            swap_bytes,
            reader,
            global_header: PcapGlobalHeader {
                magic,
                version_major,
                version_minor,
                thiszone,
                sigfigs,
                snaplen,
                link_type,
            },
        })
    }

    /// Read the next packet record. Returns None on EOF.
    pub fn next_record(&mut self) -> Result<Option<PcapRecord>, Error> {
        let mut hdr = [0u8; 16];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(Error::Io(e)),
        }

        let ts_sec = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let ts_frac = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
        let cap_len = u32::from_le_bytes([hdr[8], hdr[9], hdr[10], hdr[11]]);
        let orig_len = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]);

        let (ts_sec, ts_frac, cap_len, orig_len) = if self.swap_bytes {
            (ts_sec.swap_bytes(), ts_frac.swap_bytes(), cap_len.swap_bytes(), orig_len.swap_bytes())
        } else {
            (ts_sec, ts_frac, cap_len, orig_len)
        };

        // Sanity check: reject absurdly large frames.
        if cap_len > 65536 {
            return Err(Error::PcapMalformed {
                reason: format!(
                    "Packet captured length {} is unreasonably large. File may be corrupted.",
                    cap_len
                ),
            });
        }

        let mut data = vec![0u8; cap_len as usize];
        self.reader.read_exact(&mut data)
            .map_err(|e| Error::PcapMalformed {
                reason: format!("Truncated packet data: {}", e),
            })?;

        Ok(Some(PcapRecord {
            timestamp_sec: ts_sec,
            timestamp_frac: ts_frac,
            captured_len: cap_len,
            original_len: orig_len,
            data,
        }))
    }

    pub fn has_radiotap(&self) -> bool {
        self.link_type == PCAP_LINK_IEEE80211_RADIOTAP
    }
}

// ──────────────────────────────────────────────
// PCAP Writer
// ──────────────────────────────────────────────

pub struct PcapWriter {
    writer: io::BufWriter<File>,
}

impl PcapWriter {
    /// Create a new PCAP file with Radiotap link type.
    pub fn create(path: &Path) -> Result<Self, Error> {
        let file = File::create(path).map_err(Error::Io)?;
        let mut writer = io::BufWriter::new(file);

        // Global header.
        write_u32_le(&mut writer, PCAP_MAGIC_LE)?;
        write_u16_le(&mut writer, 2)?; // major
        write_u16_le(&mut writer, 4)?; // minor
        write_i32_le(&mut writer, 0)?; // thiszone
        write_u32_le(&mut writer, 0)?; // sigfigs
        write_u32_le(&mut writer, 65535)?; // snaplen
        write_u32_le(&mut writer, PCAP_LINK_IEEE80211_RADIOTAP)?; // link type

        Ok(Self { writer })
    }

    /// Write a packet record.
    pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> Result<(), Error> {
        let cap_len = data.len() as u32;
        write_u32_le(&mut self.writer, ts_sec)?;
        write_u32_le(&mut self.writer, ts_usec)?;
        write_u32_le(&mut self.writer, cap_len)?;
        write_u32_le(&mut self.writer, cap_len)?;
        self.writer.write_all(data).map_err(Error::Io)?;
        Ok(())
    }

    /// Flush the write buffer.
    pub fn flush(&mut self) -> Result<(), Error> {
        self.writer.flush().map_err(Error::Io)
    }
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

fn read_u32_le(r: &mut impl Read) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    r.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn write_u32_le(w: &mut impl Write, v: u32) -> Result<(), Error> {
    w.write_all(&v.to_le_bytes()).map_err(Error::Io)
}

fn write_u16_le(w: &mut impl Write, v: u16) -> Result<(), Error> {
    w.write_all(&v.to_le_bytes()).map_err(Error::Io)
}

fn write_i32_le(w: &mut impl Write, v: i32) -> Result<(), Error> {
    w.write_all(&v.to_le_bytes()).map_err(Error::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_pcap_writer_creates_valid_header() {
        let path = std::env::temp_dir().join("test_pcap_write.pcap");
        {
            let mut writer = PcapWriter::create(&path).unwrap();
            writer.write_packet(1000, 0, &[0x80, 0x00, 0x00, 0x00, 0xFF, 0xFF]).unwrap();
            writer.flush().unwrap();
        }

        // Read back and verify.
        let mut reader = PcapReader::open(&path).unwrap();
        assert_eq!(reader.link_type, 127); // Radiotap
        let record = reader.next_record().unwrap();
        assert!(record.is_some());
        let rec = record.unwrap();
        assert_eq!(rec.captured_len, 6);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_pcap_malformed_magic() {
        let path = std::env::temp_dir().join("test_pcap_bad_magic.pcap");
        std::fs::write(&path, &[0xFF, 0xFF, 0xFF, 0xFF]).unwrap();
        let result = PcapReader::open(&path);
        assert!(result.is_err());
        if let Err(Error::PcapMalformed { reason }) = result {
            assert!(reason.contains("Unknown PCAP magic"));
        } else {
            panic!("Expected PcapMalformed error");
        }
        std::fs::remove_file(&path).ok();
    }
}
