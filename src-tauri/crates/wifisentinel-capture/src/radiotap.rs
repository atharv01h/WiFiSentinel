// wifisentinel-capture/src/radiotap.rs
// Radiotap header parser.
//
// Reference: https://www.radiotap.org/

/// Parsed Radiotap header.
#[derive(Debug, Clone, Default)]
pub struct RadiotapHeader {
    pub revision: u8,
    pub length: u16,
    pub present_flags: u32,
    /// TSFT: timestamp in microseconds.
    pub tsft: Option<u64>,
    /// Flags field.
    pub flags: Option<u8>,
    /// Data rate in 500 Kbps units.
    pub rate: Option<u8>,
    /// Channel frequency (MHz) and flags.
    pub channel: Option<(u16, u16)>,
    /// FHSS hop set/pattern.
    pub fhss: Option<(u8, u8)>,
    /// Antenna signal in dBm (signed).
    pub antenna_signal: Option<i8>,
    /// Antenna noise in dBm.
    pub antenna_noise: Option<i8>,
    /// Lock quality.
    pub lock_quality: Option<u16>,
    /// TX attenuation (in 0.5 dB steps).
    pub tx_attenuation: Option<u16>,
    /// Antenna index.
    pub antenna: Option<u8>,
    /// MCS information.
    pub mcs: Option<McsInfo>,
}

#[derive(Debug, Clone)]
pub struct McsInfo {
    pub known: u8,
    pub flags: u8,
    pub mcs_index: u8,
}

impl RadiotapHeader {
    /// Parse a Radiotap header from raw bytes.
    /// Returns (header, payload_offset) or an error string.
    pub fn parse(data: &[u8]) -> Result<(Self, usize), String> {
        if data.len() < 8 {
            return Err(format!("Radiotap: too short ({} bytes)", data.len()));
        }

        let revision = data[0];
        if revision != 0 {
            return Err(format!("Unsupported Radiotap revision: {}", revision));
        }

        let length = u16::from_le_bytes([data[2], data[3]]) as usize;
        if length > data.len() {
            return Err(format!(
                "Radiotap length {} exceeds frame size {}",
                length, data.len()
            ));
        }

        let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        let mut header = RadiotapHeader {
            revision,
            length: length as u16,
            present_flags: present,
            ..Default::default()
        };

        // Parse fields based on present bitmap.
        // We use a cursor over the header body (after the fixed 8-byte prefix
        // and any extended present words).
        let mut cursor = 8usize;

        // Skip extended present words (bit 31 = "another present word follows").
        while cursor + 4 <= length {
            let word = u32::from_le_bytes([
                data[cursor], data[cursor + 1], data[cursor + 2], data[cursor + 3],
            ]);
            cursor += 4;
            if word & (1 << 31) == 0 { break; }
        }

        // Helper: align cursor to `align` bytes.
        macro_rules! align {
            ($align:expr) => {
                let rem = cursor % $align;
                if rem != 0 { cursor += $align - rem; }
            };
        }

        // Bit 0: TSFT (8 bytes, 8-byte aligned).
        if present & (1 << 0) != 0 {
            align!(8);
            if cursor + 8 <= length {
                let v = u64::from_le_bytes(data[cursor..cursor + 8].try_into().unwrap_or([0; 8]));
                header.tsft = Some(v);
                cursor += 8;
            }
        }

        // Bit 1: Flags (1 byte).
        if present & (1 << 1) != 0 && cursor < length {
            header.flags = Some(data[cursor]);
            cursor += 1;
        }

        // Bit 2: Rate (1 byte).
        if present & (1 << 2) != 0 && cursor < length {
            header.rate = Some(data[cursor]);
            cursor += 1;
        }

        // Bit 3: Channel (4 bytes, 2-byte aligned).
        if present & (1 << 3) != 0 {
            align!(2);
            if cursor + 4 <= length {
                let freq = u16::from_le_bytes([data[cursor], data[cursor + 1]]);
                let flags = u16::from_le_bytes([data[cursor + 2], data[cursor + 3]]);
                header.channel = Some((freq, flags));
                cursor += 4;
            }
        }

        // Bit 4: FHSS (2 bytes).
        if present & (1 << 4) != 0 && cursor + 2 <= length {
            header.fhss = Some((data[cursor], data[cursor + 1]));
            cursor += 2;
        }

        // Bit 5: Antenna signal (1 byte, signed).
        if present & (1 << 5) != 0 && cursor < length {
            header.antenna_signal = Some(data[cursor] as i8);
            cursor += 1;
        }

        // Bit 6: Antenna noise (1 byte, signed).
        if present & (1 << 6) != 0 && cursor < length {
            header.antenna_noise = Some(data[cursor] as i8);
            cursor += 1;
        }

        // Bit 7: Lock quality (2 bytes, 2-byte aligned).
        if present & (1 << 7) != 0 {
            align!(2);
            if cursor + 2 <= length {
                header.lock_quality = Some(u16::from_le_bytes([data[cursor], data[cursor + 1]]));
                cursor += 2;
            }
        }

        // Skip bits 8-10 (TX attenuation fields, 2 bytes each).
        if present & (1 << 8) != 0 { align!(2); cursor += 2; }
        if present & (1 << 9) != 0 { align!(2); cursor += 2; }
        if present & (1 << 10) != 0 { align!(2); cursor += 2; }

        // Bit 11: Antenna (1 byte).
        if present & (1 << 11) != 0 && cursor < length {
            header.antenna = Some(data[cursor]);
            cursor += 1;
        }

        // Skip bit 12: Antenna signal in dB.
        if present & (1 << 12) != 0 && cursor < length { cursor += 1; }

        // Bit 19: MCS (3 bytes).
        if present & (1 << 19) != 0 && cursor + 3 <= length {
            header.mcs = Some(McsInfo {
                known: data[cursor],
                flags: data[cursor + 1],
                mcs_index: data[cursor + 2],
            });
            // cursor += 3;
        }

        Ok((header, length))
    }

    /// Returns signal strength in dBm if available.
    pub fn signal_dbm(&self) -> Option<i16> {
        self.antenna_signal.map(|s| s as i16)
    }

    /// Returns channel frequency in MHz if available.
    pub fn frequency_mhz(&self) -> Option<u16> {
        self.channel.map(|(freq, _)| freq)
    }

    /// Returns data rate in Mbps if available.
    pub fn rate_mbps(&self) -> Option<f32> {
        self.rate.map(|r| r as f32 * 0.5)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_radiotap_too_short() {
        let result = RadiotapHeader::parse(&[0, 0, 8, 0]);
        assert!(result.is_err());
    }

    #[test]
    fn test_radiotap_minimal() {
        // Minimal valid Radiotap: revision=0, pad=0, length=8, present=0
        let data = [0u8, 0, 8, 0, 0, 0, 0, 0];
        let (header, offset) = RadiotapHeader::parse(&data).unwrap();
        assert_eq!(header.revision, 0);
        assert_eq!(header.length, 8);
        assert_eq!(offset, 8);
        assert!(header.antenna_signal.is_none());
    }

    #[test]
    fn test_radiotap_with_signal() {
        // Radiotap with signal field (bit 5 set, value = -70 dBm = 0xBA as i8).
        // present = 0x00000020 (bit 5)
        let mut data = vec![0u8, 0, 9, 0, 0x20, 0, 0, 0, 0xBA];
        let (header, _) = RadiotapHeader::parse(&data).unwrap();
        assert_eq!(header.antenna_signal, Some(-70));
        assert_eq!(header.signal_dbm(), Some(-70));
    }
}
