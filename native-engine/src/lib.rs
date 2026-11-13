//! Bounded, in-memory static inspection for the AntiOS scan worker.
//!
//! The native core never opens files or assigns threat verdicts. The caller
//! retains file identity validation, catalog lookup, archive budgets and policy.

#![deny(unsafe_op_in_unsafe_fn)]

use memchr::memmem;
use sha2::{Digest, Sha256};

const ABI_VERSION: u32 = 1;
const INVALID_INPUT: u32 = u32::MAX;
// Largest complete buffer allowed by the heavy profile.
const MAX_INPUT: usize = 96 * 1024 * 1024;
const SCRIPT_PREVIEW: usize = 16 * 1024 * 1024;
const SCRIPT_REVIEW: u32 = 1;
const SCRIPT_PARTIAL: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum Executable {
    Clear = 0,
    TruncatedPe = 1,
    UnrecognizedPe = 2,
    InvalidPeTable = 3,
    TruncatedPeTable = 4,
    PeSectionBounds = 5,
    PeSectionReview = 6,
    InvalidElfIdentification = 7,
    TruncatedElf = 8,
    InvalidElfSize = 9,
    PythonEntropy = 10,
}

#[no_mangle]
pub extern "C" fn antios_core_abi_version() -> u32 {
    ABI_VERSION
}

/// Calculate the SHA-256 digest of at most 96 MiB.
///
/// # Safety
/// For nonempty input, 'input' must point to 'len' initialized bytes readable
/// for the call. 'output' must point to 32 writable bytes. The input must not
/// be concurrently mutated and the two buffers must not overlap.
#[no_mangle]
pub unsafe extern "C" fn antios_sha256(input: *const u8, len: usize, output: *mut u8) -> u32 {
    if output.is_null() {
        return INVALID_INPUT;
    }
    let Some(data) = (unsafe { input_slice(input, len) }) else {
        return INVALID_INPUT;
    };
    let digest = Sha256::digest(data);
    // SAFETY: digest is a separate, initialized local array. The caller
    // guarantees a writable 32-byte output.
    unsafe { std::ptr::copy_nonoverlapping(digest.as_ptr(), output, digest.len()) };
    0
}

/// Return script flags in bits 0..7 and an executable classification in bits
/// 8..15. Higher bits are zero on success.
///
/// # Safety
/// For nonempty input, 'input' must point to 'len' initialized bytes readable
/// for the call. The input must not be concurrently mutated.
#[no_mangle]
pub unsafe extern "C" fn antios_static_scan(input: *const u8, len: usize, is_script: u8) -> u32 {
    if is_script > 1 {
        return INVALID_INPUT;
    }
    let Some(data) = (unsafe { input_slice(input, len) }) else {
        return INVALID_INPUT;
    };
    let script = if is_script == 1 {
        script_flags(data)
    } else {
        0
    };
    script | ((executable_signal(data) as u32) << 8)
}

// The slice borrows foreign memory for the duration of one FFI call.
unsafe fn input_slice<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if len > MAX_INPUT || ptr.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees the allocation and lifetime. MAX_INPUT
    // fits within isize::MAX on the supported platforms.
    Some(unsafe { std::slice::from_raw_parts(ptr, len) })
}

fn script_flags(data: &[u8]) -> u32 {
    let sample = &data[..data.len().min(SCRIPT_PREVIEW)];
    let mut normalized = if sample.starts_with(b"\xff\xfe") || sample.starts_with(b"\xfe\xff") {
        let little_endian = sample[0] == 0xff;
        let units = sample[2..].chunks_exact(2).map(|chunk| {
            let bytes = [chunk[0], chunk[1]];
            if little_endian {
                u16::from_le_bytes(bytes)
            } else {
                u16::from_be_bytes(bytes)
            }
        });
        char::decode_utf16(units)
            .filter_map(Result::ok)
            .collect::<String>()
            .into_bytes()
    } else {
        sample.to_vec()
    };
    normalized.make_ascii_lowercase();
    let sample = normalized.as_slice();
    let contains = |needle: &[u8]| memmem::find(sample, needle).is_some();
    let signals = [
        contains(b"-encodedcommand") || contains(b"frombase64string("),
        contains(b"invoke-expression") || has_iex_call(sample),
        contains(b"downloadstring(") || contains(b"downloadfile("),
        contains(b"set-mppreference") || contains(b"add-mppreference"),
    ];
    let review = if signals.into_iter().filter(|signal| *signal).count() >= 2 {
        SCRIPT_REVIEW
    } else {
        0
    };
    let partial = if data.len() > SCRIPT_PREVIEW {
        SCRIPT_PARTIAL
    } else {
        0
    };
    review | partial
}

fn has_iex_call(sample: &[u8]) -> bool {
    memmem::find_iter(sample, b"iex").any(|index| {
        if index > 0 {
            let before = sample[index - 1];
            if before.is_ascii_alphanumeric() || before == b'_' {
                return false;
            }
        }
        sample[index + 3..]
            .iter()
            .copied()
            .find(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | b'\x0b' | b'\x0c'))
            == Some(b'(')
    })
}

fn executable_signal(data: &[u8]) -> Executable {
    if data.starts_with(b"\x7fELF") {
        return elf_signal(data);
    }
    if data.starts_with(b"MZ") {
        return pe_signal(data);
    }
    Executable::Clear
}

fn elf_signal(data: &[u8]) -> Executable {
    if data.len() < 16 || !matches!(data[4], 1 | 2) || !matches!(data[5], 1 | 2) || data[6] != 1 {
        return Executable::InvalidElfIdentification;
    }
    let (header_size, size_field) = if data[4] == 1 { (52, 40) } else { (64, 52) };
    if data.len() < header_size {
        return Executable::TruncatedElf;
    }
    let field = [data[size_field], data[size_field + 1]];
    let size = if data[5] == 1 {
        u16::from_le_bytes(field)
    } else {
        u16::from_be_bytes(field)
    };
    if (header_size..=data.len()).contains(&usize::from(size)) {
        Executable::Clear
    } else {
        Executable::InvalidElfSize
    }
}

fn pe_signal(data: &[u8]) -> Executable {
    if data.len() < 64 {
        return Executable::TruncatedPe;
    }
    let offset = le_u32(data, 0x3c) as usize;
    if offset > data.len() - 24 || &data[offset..offset + 4] != b"PE\0\0" {
        return Executable::UnrecognizedPe;
    }
    let sections = usize::from(le_u16(data, offset + 6));
    let optional_size = usize::from(le_u16(data, offset + 20));
    if !(1..=96).contains(&sections) || optional_size < 2 {
        return Executable::InvalidPeTable;
    }
    let Some(table) = offset.checked_add(24 + optional_size) else {
        return Executable::TruncatedPeTable;
    };
    if table > data.len() || sections > (data.len() - table) / 40 {
        return Executable::TruncatedPeTable;
    }
    for index in 0..sections {
        let entry = table + index * 40;
        let raw_size = le_u32(data, entry + 16) as usize;
        let raw_offset = le_u32(data, entry + 20) as usize;
        let flags = le_u32(data, entry + 36);
        if raw_size != 0 && (raw_offset > data.len() || raw_size > data.len() - raw_offset) {
            return Executable::PeSectionBounds;
        }
        const EXECUTE_WRITE: u32 = 0x2000_0000 | 0x8000_0000;
        if flags & EXECUTE_WRITE != EXECUTE_WRITE || raw_size < 4096 {
            continue;
        }
        let score = entropy(&data[raw_offset..raw_offset + raw_size.min(32768)]);
        // libm implementations and summation order can differ by a few ULPs.
        // Preserve the Python threshold decision in that narrow interval.
        if (score - 7.5).abs() <= 1e-10 {
            return Executable::PythonEntropy;
        }
        if score > 7.5 {
            return Executable::PeSectionReview;
        }
    }
    Executable::Clear
}

fn le_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn entropy(sample: &[u8]) -> f64 {
    let mut counts = [0_u32; 256];
    for byte in sample {
        counts[usize::from(*byte)] += 1;
    }
    let length = sample.len() as f64;
    -counts
        .into_iter()
        .filter(|count| *count > 0)
        .map(|count| {
            let probability = f64::from(count) / length;
            probability * probability.log2()
        })
        .sum::<f64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_uses_versioned_layout_and_validates_inputs() {
        assert_eq!(antios_core_abi_version(), 1);
        let null = std::ptr::null();
        let mut digest = [0; 32];
        unsafe {
            assert_eq!(antios_static_scan(null, 0, 0), 0);
            assert_eq!(antios_static_scan(null, 1, 0), INVALID_INPUT);
            assert_eq!(antios_static_scan(null, 0, 2), INVALID_INPUT);
            assert_eq!(antios_static_scan(null, MAX_INPUT + 1, 0), INVALID_INPUT);
            assert_eq!(antios_static_scan(b"MZ".as_ptr(), 2, 0), 1 << 8);
            assert_eq!(antios_sha256(null, 1, digest.as_mut_ptr()), INVALID_INPUT);
            assert_eq!(antios_sha256(null, 0, std::ptr::null_mut()), INVALID_INPUT);
            assert_eq!(antios_sha256(b"abc".as_ptr(), 3, digest.as_mut_ptr()), 0);
        }
        assert_eq!(
            digest,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn script_indicators_respect_ascii_boundaries_and_utf16() {
        assert_eq!(script_flags(b"# -encodedcommand xIEX ("), 0);
        assert_eq!(script_flags(b"# -encodedcommand _IEX ("), 0);
        assert_eq!(script_flags(b"# -encodedcommand IEX \x0b ("), SCRIPT_REVIEW);
        let mut utf16 = vec![0xff, 0xfe, 0x00, 0xd8];
        for unit in "# FROMBASE64STRING( IEX (".encode_utf16() {
            utf16.extend_from_slice(&unit.to_le_bytes());
        }
        utf16.push(0x00); // Incomplete trailing code unit is ignored.
        assert_eq!(script_flags(&utf16), SCRIPT_REVIEW);
    }

    #[test]
    fn script_preview_is_limited() {
        let mut data = vec![b' '; SCRIPT_PREVIEW + 1];
        let fixture = b"# -encodedcommand IEX (";
        data[..fixture.len()].copy_from_slice(fixture);
        assert_eq!(script_flags(&data), SCRIPT_REVIEW | SCRIPT_PARTIAL);
    }

    #[test]
    fn elf_class_and_endianness_are_checked() {
        assert_eq!(
            executable_signal(b"\x7fELF"),
            Executable::InvalidElfIdentification
        );
        let mut data = vec![0; 64];
        data[..7].copy_from_slice(b"\x7fELF\x02\x02\x01");
        data[52..54].copy_from_slice(&64_u16.to_be_bytes());
        assert_eq!(executable_signal(&data), Executable::Clear);
        assert_eq!(executable_signal(&data[..63]), Executable::TruncatedElf);
        data[53] = 65;
        assert_eq!(executable_signal(&data), Executable::InvalidElfSize);
    }

    #[test]
    fn pe_table_bounds_and_section_entropy_are_checked() {
        let mut data = vec![0; 4096 + 144];
        data[..2].copy_from_slice(b"MZ");
        data[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        assert_eq!(executable_signal(&data), Executable::UnrecognizedPe);
        data[64..68].copy_from_slice(b"PE\0\0");
        assert_eq!(executable_signal(&data), Executable::InvalidPeTable);
        data[70..72].copy_from_slice(&1_u16.to_le_bytes());
        data[84..86].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            executable_signal(&data[..129]),
            Executable::TruncatedPeTable
        );
        data[106..110].copy_from_slice(&4096_u32.to_le_bytes());
        data[110..114].copy_from_slice(&144_u32.to_le_bytes());
        assert_eq!(
            executable_signal(&data[..4100]),
            Executable::PeSectionBounds
        );
        data[126..130].copy_from_slice(&0xa000_0000_u32.to_le_bytes());
        for (index, value) in data[144..].iter_mut().enumerate() {
            *value = index as u8;
        }
        assert_eq!(executable_signal(&data), Executable::PeSectionReview);
    }
}
