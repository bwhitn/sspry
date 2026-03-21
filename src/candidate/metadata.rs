use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::{Result, SspryError};

const METADATA_VERSION: u8 = 1;
const MAX_MACHO_ARCHES: usize = 32;
const MAX_MACHO_COMMAND_BYTES: usize = 256 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoolField {
    CrxIsCrx = 0,
    PeIsPe = 1,
    PeIs32Bit = 2,
    PeIs64Bit = 3,
    PeIsDll = 4,
    PeIsSigned = 5,
    DotnetIsDotnet = 6,
    DexIsDex = 7,
    LnkIsLnk = 8,
    ElfIsElf = 9,
    MachoIsMacho = 10,
    ZipIsZip = 11,
    MzIsMz = 12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntField {
    PeMachine = 0,
    PeSubsystem = 1,
    PeTimestamp = 2,
    ElfType = 3,
    ElfOsAbi = 4,
    ElfMachine = 5,
    MachoCpuType = 6,
    MachoDeviceType = 7,
    DexVersion = 8,
    LnkCreationTime = 9,
    LnkAccessTime = 10,
    LnkWriteTime = 11,
}

#[derive(Clone, Debug, Default)]
struct MetadataBuilder {
    bool_known: u16,
    bool_values: u16,
    ints: [Vec<u64>; 12],
}

#[derive(Clone, Debug, Default)]
struct DecodedMetadata {
    bool_known: u16,
    bool_values: u16,
    ints: [Vec<u64>; 12],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByteOrder {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ThinMachOKind {
    Bits32,
    Bits64,
}

impl MetadataBuilder {
    fn set_bool(&mut self, field: BoolField, value: bool) {
        let bit = 1u16 << (field as u16);
        self.bool_known |= bit;
        if value {
            self.bool_values |= bit;
        } else {
            self.bool_values &= !bit;
        }
    }

    fn push_int(&mut self, field: IntField, value: u64) {
        let slot = &mut self.ints[field as usize];
        if !slot.contains(&value) {
            slot.push(value);
        }
    }

    fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.push(METADATA_VERSION);
        out.extend_from_slice(&self.bool_known.to_le_bytes());
        out.extend_from_slice(&self.bool_values.to_le_bytes());
        let mut int_presence = 0u16;
        for (idx, values) in self.ints.iter().enumerate() {
            if !values.is_empty() {
                int_presence |= 1u16 << idx;
            }
        }
        out.extend_from_slice(&int_presence.to_le_bytes());
        for values in self.ints {
            if values.is_empty() {
                continue;
            }
            encode_varint(values.len() as u64, &mut out);
            for value in values {
                encode_varint(value, &mut out);
            }
        }
        out
    }
}

fn decode(bytes: &[u8]) -> Result<DecodedMetadata> {
    if bytes.is_empty() {
        return Ok(DecodedMetadata::default());
    }
    if bytes.len() < 7 {
        return Err(SspryError::from("Invalid compact document metadata."));
    }
    if bytes[0] != METADATA_VERSION {
        return Err(SspryError::from(format!(
            "Unsupported compact document metadata version: {}",
            bytes[0]
        )));
    }
    let bool_known = u16::from_le_bytes(bytes[1..3].try_into().expect("bool_known"));
    let bool_values = u16::from_le_bytes(bytes[3..5].try_into().expect("bool_values"));
    let int_presence = u16::from_le_bytes(bytes[5..7].try_into().expect("int_presence"));
    let mut offset = 7usize;
    let mut ints: [Vec<u64>; 12] = Default::default();
    for idx in 0..ints.len() {
        if (int_presence & (1u16 << idx)) == 0 {
            continue;
        }
        let count = decode_varint(bytes, &mut offset)? as usize;
        let mut values = Vec::with_capacity(count);
        for _ in 0..count {
            values.push(decode_varint(bytes, &mut offset)?);
        }
        ints[idx] = values;
    }
    if offset != bytes.len() {
        return Err(SspryError::from(
            "Trailing compact document metadata bytes.",
        ));
    }
    Ok(DecodedMetadata {
        bool_known,
        bool_values,
        ints,
    })
}

fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

fn decode_varint(bytes: &[u8], offset: &mut usize) -> Result<u64> {
    let mut shift = 0u32;
    let mut value = 0u64;
    loop {
        let byte = *bytes
            .get(*offset)
            .ok_or_else(|| SspryError::from("Truncated compact document metadata."))?;
        *offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if (byte & 0x80) == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            return Err(SspryError::from(
                "Invalid compact document metadata varint.",
            ));
        }
    }
}

fn read_prefix(file: &mut File, len: usize) -> Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let available = file.metadata()?.len().min(len as u64) as usize;
    let mut bytes = vec![0u8; available];
    if available > 0 {
        file.read_exact(&mut bytes)?;
    }
    Ok(bytes)
}

fn read_at(file: &mut File, offset: u64, len: usize) -> Result<Option<Vec<u8>>> {
    let total_len = file.metadata()?.len();
    if offset > total_len || total_len - offset < len as u64 {
        return Ok(None);
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut bytes = vec![0u8; len];
    file.read_exact(&mut bytes)?;
    Ok(Some(bytes))
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().expect("u16"))
}

fn be_u16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("u16"))
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().expect("u32"))
}

fn be_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("u32"))
}

fn le_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().expect("u64"))
}

fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes.try_into().expect("u64"))
}

fn read_u32(bytes: &[u8], order: ByteOrder) -> u32 {
    match order {
        ByteOrder::Little => le_u32(bytes),
        ByteOrder::Big => be_u32(bytes),
    }
}

fn filetime_to_unix_timestamp(filetime: u64) -> Option<u64> {
    (filetime / 10_000_000).checked_sub(11_644_473_600)
}

fn extract_crx_metadata(prefix: &[u8], builder: &mut MetadataBuilder) {
    builder.set_bool(BoolField::CrxIsCrx, prefix.starts_with(b"Cr24"));
}

fn extract_zip_metadata(prefix: &[u8], builder: &mut MetadataBuilder) {
    builder.set_bool(BoolField::ZipIsZip, prefix.starts_with(b"PK\x03\x04"));
}

fn extract_dex_metadata(prefix: &[u8], builder: &mut MetadataBuilder) {
    let is_dex = prefix.len() >= 8
        && &prefix[..4] == b"dex\n"
        && prefix[4].is_ascii_digit()
        && prefix[5].is_ascii_digit()
        && prefix[6].is_ascii_digit()
        && prefix[7] == 0;
    builder.set_bool(BoolField::DexIsDex, is_dex);
    if is_dex {
        let version = std::str::from_utf8(&prefix[4..7])
            .ok()
            .and_then(|text| text.parse::<u64>().ok())
            .unwrap_or(0);
        builder.push_int(IntField::DexVersion, version);
    }
}

fn extract_lnk_metadata(prefix: &[u8], builder: &mut MetadataBuilder) {
    let is_lnk = prefix.len() >= 76
        && le_u32(&prefix[0..4]) == 0x4c
        && le_u64(&prefix[4..12]) == 0x0000_0000_0002_1401
        && le_u64(&prefix[12..20]) == 0x4600_0000_0000_00c0;
    builder.set_bool(BoolField::LnkIsLnk, is_lnk);
    if !is_lnk {
        return;
    }
    if let Some(value) = filetime_to_unix_timestamp(le_u64(&prefix[28..36])) {
        builder.push_int(IntField::LnkCreationTime, value);
    }
    if let Some(value) = filetime_to_unix_timestamp(le_u64(&prefix[36..44])) {
        builder.push_int(IntField::LnkAccessTime, value);
    }
    if let Some(value) = filetime_to_unix_timestamp(le_u64(&prefix[44..52])) {
        builder.push_int(IntField::LnkWriteTime, value);
    }
}

fn extract_elf_metadata(prefix: &[u8], builder: &mut MetadataBuilder) {
    let is_elf = prefix.len() >= 20 && &prefix[..4] == b"\x7fELF";
    builder.set_bool(BoolField::ElfIsElf, is_elf);
    if !is_elf {
        return;
    }
    let order = match prefix.get(5).copied() {
        Some(1) => ByteOrder::Little,
        Some(2) => ByteOrder::Big,
        _ => return,
    };
    builder.push_int(IntField::ElfOsAbi, u64::from(prefix[7]));
    let elf_type = match order {
        ByteOrder::Little => le_u16(&prefix[16..18]),
        ByteOrder::Big => be_u16(&prefix[16..18]),
    };
    let machine = match order {
        ByteOrder::Little => le_u16(&prefix[18..20]),
        ByteOrder::Big => be_u16(&prefix[18..20]),
    };
    builder.push_int(IntField::ElfType, u64::from(elf_type));
    builder.push_int(IntField::ElfMachine, u64::from(machine));
}

fn extract_pe_metadata(
    file: &mut File,
    prefix: &[u8],
    builder: &mut MetadataBuilder,
) -> Result<()> {
    builder.set_bool(
        BoolField::MzIsMz,
        prefix.len() >= 2 && &prefix[..2] == b"MZ",
    );
    builder.set_bool(BoolField::PeIsPe, false);
    builder.set_bool(BoolField::PeIs32Bit, false);
    builder.set_bool(BoolField::PeIs64Bit, false);
    builder.set_bool(BoolField::PeIsDll, false);
    builder.set_bool(BoolField::PeIsSigned, false);
    builder.set_bool(BoolField::DotnetIsDotnet, false);
    if prefix.len() < 64 || &prefix[..2] != b"MZ" {
        return Ok(());
    }
    let pe_offset = u64::from(le_u32(&prefix[0x3c..0x40]));
    let Some(file_header) = read_at(file, pe_offset, 24)? else {
        return Ok(());
    };
    if &file_header[..4] != b"PE\0\0" {
        return Ok(());
    }
    let machine = le_u16(&file_header[4..6]);
    let timestamp = le_u32(&file_header[8..12]);
    let size_of_optional_header = usize::from(le_u16(&file_header[20..22]));
    let characteristics = le_u16(&file_header[22..24]);
    let Some(optional) = read_at(file, pe_offset + 24, size_of_optional_header)? else {
        return Ok(());
    };
    if optional.len() < 72 {
        return Ok(());
    }
    let magic = le_u16(&optional[0..2]);
    let (is_32bit, is_64bit, data_dir_base) = match magic {
        0x10b => (true, false, 96usize),
        0x20b => (false, true, 112usize),
        _ => return Ok(()),
    };
    builder.set_bool(BoolField::PeIsPe, true);
    builder.set_bool(BoolField::PeIs32Bit, is_32bit);
    builder.set_bool(BoolField::PeIs64Bit, is_64bit);
    builder.set_bool(BoolField::PeIsDll, (characteristics & 0x2000) != 0);
    builder.push_int(IntField::PeMachine, u64::from(machine));
    builder.push_int(IntField::PeTimestamp, u64::from(timestamp));
    if optional.len() >= 70 {
        builder.push_int(IntField::PeSubsystem, u64::from(le_u16(&optional[68..70])));
    }
    if optional.len() >= data_dir_base + (15 * 8) {
        let security_offset = data_dir_base + (4 * 8);
        let security_dir = le_u32(&optional[security_offset..security_offset + 4]);
        let security_size = le_u32(&optional[security_offset + 4..security_offset + 8]);
        builder.set_bool(
            BoolField::PeIsSigned,
            security_dir != 0 && security_size != 0,
        );
        let com_offset = data_dir_base + (14 * 8);
        let com_rva = le_u32(&optional[com_offset..com_offset + 4]);
        let com_size = le_u32(&optional[com_offset + 4..com_offset + 8]);
        builder.set_bool(BoolField::DotnetIsDotnet, com_rva != 0 && com_size != 0);
    }
    Ok(())
}

fn thin_macho_kind_and_order(magic: [u8; 4]) -> Option<(ThinMachOKind, ByteOrder)> {
    match magic {
        [0xfe, 0xed, 0xfa, 0xce] => Some((ThinMachOKind::Bits32, ByteOrder::Big)),
        [0xce, 0xfa, 0xed, 0xfe] => Some((ThinMachOKind::Bits32, ByteOrder::Little)),
        [0xfe, 0xed, 0xfa, 0xcf] => Some((ThinMachOKind::Bits64, ByteOrder::Big)),
        [0xcf, 0xfa, 0xed, 0xfe] => Some((ThinMachOKind::Bits64, ByteOrder::Little)),
        _ => None,
    }
}

fn fat_macho_order_and_is_64(magic: [u8; 4]) -> Option<(ByteOrder, bool)> {
    match magic {
        [0xca, 0xfe, 0xba, 0xbe] => Some((ByteOrder::Big, false)),
        [0xbe, 0xba, 0xfe, 0xca] => Some((ByteOrder::Little, false)),
        [0xca, 0xfe, 0xba, 0xbf] => Some((ByteOrder::Big, true)),
        [0xbf, 0xba, 0xfe, 0xca] => Some((ByteOrder::Little, true)),
        _ => None,
    }
}

fn extract_thin_macho_metadata(
    file: &mut File,
    offset: u64,
    builder: &mut MetadataBuilder,
) -> Result<bool> {
    let Some(header) = read_at(file, offset, 32)? else {
        return Ok(false);
    };
    let Some((kind, order)) = thin_macho_kind_and_order(header[0..4].try_into().expect("magic"))
    else {
        return Ok(false);
    };
    builder.push_int(
        IntField::MachoCpuType,
        u64::from(read_u32(&header[4..8], order)),
    );
    let ncmds = read_u32(&header[16..20], order) as usize;
    let sizeofcmds = read_u32(&header[20..24], order) as usize;
    let header_size = match kind {
        ThinMachOKind::Bits32 => 28usize,
        ThinMachOKind::Bits64 => 32usize,
    };
    if sizeofcmds == 0 || sizeofcmds > MAX_MACHO_COMMAND_BYTES {
        return Ok(true);
    }
    let Some(full) = read_at(file, offset, header_size + sizeofcmds)? else {
        return Ok(true);
    };
    let mut cursor = header_size;
    for _ in 0..ncmds {
        if cursor + 8 > full.len() {
            break;
        }
        let command = read_u32(&full[cursor..cursor + 4], order);
        let command_size = read_u32(&full[cursor + 4..cursor + 8], order) as usize;
        if command_size < 8 || cursor + command_size > full.len() {
            break;
        }
        if matches!(command, 0x24 | 0x25 | 0x2f | 0x30) {
            builder.push_int(IntField::MachoDeviceType, u64::from(command));
        }
        cursor += command_size;
    }
    Ok(true)
}

fn extract_macho_metadata(
    file: &mut File,
    prefix: &[u8],
    builder: &mut MetadataBuilder,
) -> Result<()> {
    builder.set_bool(BoolField::MachoIsMacho, false);
    if prefix.len() < 8 {
        return Ok(());
    }
    let magic: [u8; 4] = prefix[0..4].try_into().expect("magic");
    if thin_macho_kind_and_order(magic).is_some() {
        if extract_thin_macho_metadata(file, 0, builder)? {
            builder.set_bool(BoolField::MachoIsMacho, true);
        }
        return Ok(());
    }
    let Some((order, is_64)) = fat_macho_order_and_is_64(magic) else {
        return Ok(());
    };
    let nfat_arch = read_u32(&prefix[4..8], order) as usize;
    let arch_count = nfat_arch.min(MAX_MACHO_ARCHES);
    let entry_size = if is_64 { 32usize } else { 20usize };
    let table_size = 8 + arch_count * entry_size;
    let Some(table) = read_at(file, 0, table_size)? else {
        return Ok(());
    };
    builder.set_bool(BoolField::MachoIsMacho, true);
    for idx in 0..arch_count {
        let start = 8 + idx * entry_size;
        let entry = &table[start..start + entry_size];
        builder.push_int(
            IntField::MachoCpuType,
            u64::from(read_u32(&entry[0..4], order)),
        );
        let thin_offset = if is_64 {
            read_u64(&entry[8..16], order)
        } else {
            u64::from(read_u32(&entry[8..12], order))
        };
        let _ = extract_thin_macho_metadata(file, thin_offset, builder)?;
    }
    Ok(())
}

fn read_u64(bytes: &[u8], order: ByteOrder) -> u64 {
    match order {
        ByteOrder::Little => le_u64(bytes),
        ByteOrder::Big => be_u64(bytes),
    }
}

pub fn extract_compact_document_metadata(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let prefix = read_prefix(&mut file, 4096)?;
    let mut builder = MetadataBuilder::default();
    extract_crx_metadata(&prefix, &mut builder);
    extract_zip_metadata(&prefix, &mut builder);
    extract_dex_metadata(&prefix, &mut builder);
    extract_lnk_metadata(&prefix, &mut builder);
    extract_elf_metadata(&prefix, &mut builder);
    extract_pe_metadata(&mut file, &prefix, &mut builder)?;
    extract_macho_metadata(&mut file, &prefix, &mut builder)?;
    Ok(builder.encode())
}

fn normalize_field(raw: &str) -> Option<&'static str> {
    match raw.to_ascii_lowercase().as_str() {
        "crx.is_crx" => Some("crx.is_crx"),
        "_intern.is_mz" => Some("_intern.is_mz"),
        "pe.is_pe" => Some("pe.is_pe"),
        "pe.is_32bit" => Some("pe.is_32bit"),
        "pe.is_64bit" => Some("pe.is_64bit"),
        "pe.is_dll" => Some("pe.is_dll"),
        "pe.is_signed" => Some("pe.is_signed"),
        "pe.machine" => Some("pe.machine"),
        "pe.subsystem" => Some("pe.subsystem"),
        "pe.timestamp" => Some("pe.timestamp"),
        "elf.is_elf" => Some("elf.is_elf"),
        "elf.type" => Some("elf.type"),
        "elf.os_abi" | "elf.osabi" => Some("elf.os_abi"),
        "elf.machine" => Some("elf.machine"),
        "macho.cpu_type" | "macho.cputype" => Some("macho.cpu_type"),
        "macho.device_type" | "macho.devicetype" => Some("macho.device_type"),
        "dotnet.is_dotnet" => Some("dotnet.is_dotnet"),
        "dex.is_dex" => Some("dex.is_dex"),
        "dex.version" => Some("dex.version"),
        "lnk.is_lnk" => Some("lnk.is_lnk"),
        "_intern.is_zip" | "zip.is_zip" => Some("_intern.is_zip"),
        "lnk.creation_time" => Some("lnk.creation_time"),
        "lnk.access_time" => Some("lnk.access_time"),
        "lnk.write_time" => Some("lnk.write_time"),
        "time.now" => Some("time.now"),
        _ => None,
    }
}

pub fn normalize_query_metadata_field(raw: &str) -> Option<&'static str> {
    normalize_field(raw)
}

pub fn metadata_field_is_boolean(raw: &str) -> bool {
    matches!(
        normalize_field(raw),
        Some(
            "crx.is_crx"
                | "_intern.is_mz"
                | "pe.is_pe"
                | "pe.is_32bit"
                | "pe.is_64bit"
                | "pe.is_dll"
                | "pe.is_signed"
                | "dotnet.is_dotnet"
                | "dex.is_dex"
                | "lnk.is_lnk"
                | "elf.is_elf"
                | "_intern.is_zip"
        )
    )
}

pub fn metadata_field_is_integer(raw: &str) -> bool {
    matches!(
        normalize_field(raw),
        Some(
            "pe.machine"
                | "pe.subsystem"
                | "pe.timestamp"
                | "elf.type"
                | "elf.os_abi"
                | "elf.machine"
                | "macho.cpu_type"
                | "macho.device_type"
                | "dex.version"
                | "lnk.creation_time"
                | "lnk.access_time"
                | "lnk.write_time"
                | "time.now"
        )
    )
}

fn bool_field_for_name(field: &str) -> Option<BoolField> {
    match field {
        "crx.is_crx" => Some(BoolField::CrxIsCrx),
        "_intern.is_mz" => Some(BoolField::MzIsMz),
        "pe.is_pe" => Some(BoolField::PeIsPe),
        "pe.is_32bit" => Some(BoolField::PeIs32Bit),
        "pe.is_64bit" => Some(BoolField::PeIs64Bit),
        "pe.is_dll" => Some(BoolField::PeIsDll),
        "pe.is_signed" => Some(BoolField::PeIsSigned),
        "dotnet.is_dotnet" => Some(BoolField::DotnetIsDotnet),
        "dex.is_dex" => Some(BoolField::DexIsDex),
        "lnk.is_lnk" => Some(BoolField::LnkIsLnk),
        "elf.is_elf" => Some(BoolField::ElfIsElf),
        "_intern.is_zip" => Some(BoolField::ZipIsZip),
        _ => None,
    }
}

fn int_field_for_name(field: &str) -> Option<IntField> {
    match field {
        "pe.machine" => Some(IntField::PeMachine),
        "pe.subsystem" => Some(IntField::PeSubsystem),
        "pe.timestamp" => Some(IntField::PeTimestamp),
        "elf.type" => Some(IntField::ElfType),
        "elf.os_abi" => Some(IntField::ElfOsAbi),
        "elf.machine" => Some(IntField::ElfMachine),
        "macho.cpu_type" => Some(IntField::MachoCpuType),
        "macho.device_type" => Some(IntField::MachoDeviceType),
        "dex.version" => Some(IntField::DexVersion),
        "lnk.creation_time" => Some(IntField::LnkCreationTime),
        "lnk.access_time" => Some(IntField::LnkAccessTime),
        "lnk.write_time" => Some(IntField::LnkWriteTime),
        _ => None,
    }
}

fn module_guard_for_field(field: &str) -> Option<BoolField> {
    match field {
        "pe.machine" | "pe.subsystem" | "pe.timestamp" => Some(BoolField::PeIsPe),
        "elf.type" | "elf.os_abi" | "elf.machine" => Some(BoolField::ElfIsElf),
        "macho.cpu_type" | "macho.device_type" => Some(BoolField::MachoIsMacho),
        "dex.version" => Some(BoolField::DexIsDex),
        "lnk.creation_time" | "lnk.access_time" | "lnk.write_time" => Some(BoolField::LnkIsLnk),
        _ => None,
    }
}

fn bool_value(decoded: &DecodedMetadata, field: BoolField) -> Option<bool> {
    let bit = 1u16 << (field as u16);
    if (decoded.bool_known & bit) == 0 {
        None
    } else {
        Some((decoded.bool_values & bit) != 0)
    }
}

pub fn metadata_field_matches_eq(
    bytes: &[u8],
    raw_field: &str,
    expected: u64,
) -> Result<Option<bool>> {
    let Some(field) = normalize_field(raw_field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_field}"
        )));
    };
    if field == "time.now" {
        return Ok(None);
    }
    let decoded = decode(bytes)?;
    if let Some(bool_field) = bool_field_for_name(field) {
        return Ok(bool_value(&decoded, bool_field).map(|value| value == (expected != 0)));
    }
    if let Some(module_guard) = module_guard_for_field(field)
        && bool_value(&decoded, module_guard) == Some(false)
    {
        return Ok(Some(false));
    }
    let Some(int_field) = int_field_for_name(field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_field}"
        )));
    };
    let values = &decoded.ints[int_field as usize];
    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(values.iter().any(|value| *value == expected)))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn compact_metadata_roundtrip_and_normalization() {
        let mut builder = MetadataBuilder::default();
        builder.set_bool(BoolField::PeIsPe, true);
        builder.set_bool(BoolField::PeIsDll, false);
        builder.push_int(IntField::PeMachine, 0x14c);
        builder.push_int(IntField::MachoCpuType, 7);
        builder.push_int(IntField::MachoCpuType, 7);
        let bytes = builder.encode();
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(bool_value(&decoded, BoolField::PeIsPe), Some(true));
        assert_eq!(bool_value(&decoded, BoolField::PeIsDll), Some(false));
        assert_eq!(decoded.ints[IntField::PeMachine as usize], vec![0x14c]);
        assert_eq!(decoded.ints[IntField::MachoCpuType as usize], vec![7]);
        assert_eq!(
            normalize_query_metadata_field("ELF.OSABI"),
            Some("elf.os_abi")
        );
        assert_eq!(
            normalize_query_metadata_field("zip.is_zip"),
            Some("_intern.is_zip")
        );
        assert_eq!(
            normalize_query_metadata_field("_intern.is_zip"),
            Some("_intern.is_zip")
        );
        assert_eq!(
            normalize_query_metadata_field("_intern.is_mz"),
            Some("_intern.is_mz")
        );
        assert!(metadata_field_is_boolean("pe.is_dll"));
        assert!(metadata_field_is_boolean("elf.is_elf"));
        assert!(metadata_field_is_boolean("zip.is_zip"));
        assert!(metadata_field_is_boolean("_intern.is_zip"));
        assert!(metadata_field_is_boolean("_intern.is_mz"));
        assert!(metadata_field_is_integer("macho.device_type"));
    }

    #[test]
    fn metadata_field_matching_handles_unknown_and_guard_bools() {
        let mut builder = MetadataBuilder::default();
        builder.set_bool(BoolField::PeIsPe, false);
        let bytes = builder.encode();
        assert_eq!(
            metadata_field_matches_eq(&bytes, "pe.machine", 0x14c).expect("match"),
            Some(false)
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "pe.is_pe", 0).expect("match"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "pe.is_pe", 1).expect("match"),
            Some(false)
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "zip.is_zip", 1).expect("match"),
            None
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "_intern.is_mz", 1).expect("match"),
            None
        );
        assert_eq!(
            metadata_field_matches_eq(&[], "pe.machine", 0x14c).expect("unknown"),
            None
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "time.now", 1234).expect("time.now"),
            None
        );
        assert!(
            metadata_field_matches_eq(&bytes, "bogus.field", 1)
                .expect_err("unknown field")
                .to_string()
                .contains("Unsupported metadata field")
        );
    }

    #[test]
    fn extracts_basic_module_metadata_from_small_headers() {
        let tmp = tempdir().expect("tmp");
        let pe_path = tmp.path().join("sample.exe");
        let mut pe = vec![0u8; 512];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        pe[0x88..0x8c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&0x0200u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[0x98 + 112 + 32..0x98 + 112 + 40].copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
        pe[0x98 + 112 + 112..0x98 + 112 + 120].copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
        fs::write(&pe_path, &pe).expect("write pe");
        let pe_bytes = extract_compact_document_metadata(&pe_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "_intern.is_mz", 1).expect("mz"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.is_pe", 1).expect("pe"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.is_64bit", 1).expect("pe64"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.is_signed", 1).expect("signed"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.machine", 0x14c).expect("machine"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "dotnet.is_dotnet", 1).expect("dotnet"),
            Some(true)
        );

        let elf_path = tmp.path().join("sample.elf");
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[7] = 3;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        fs::write(&elf_path, &elf).expect("write elf");
        let elf_bytes = extract_compact_document_metadata(&elf_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.machine", 62).expect("elf machine"),
            Some(true)
        );

        let dex_path = tmp.path().join("sample.dex");
        fs::write(&dex_path, b"dex\n035\0rest").expect("write dex");
        let dex_bytes = extract_compact_document_metadata(&dex_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&dex_bytes, "dex.is_dex", 1).expect("dex"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&dex_bytes, "dex.version", 35).expect("dex version"),
            Some(true)
        );

        let crx_path = tmp.path().join("sample.crx");
        fs::write(&crx_path, b"Cr24payload").expect("write crx");
        let crx_bytes = extract_compact_document_metadata(&crx_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&crx_bytes, "crx.is_crx", 1).expect("crx"),
            Some(true)
        );

        let zip_path = tmp.path().join("sample.zip");
        fs::write(&zip_path, b"PK\x03\x04payload").expect("write zip");
        let zip_bytes = extract_compact_document_metadata(&zip_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&zip_bytes, "zip.is_zip", 1).expect("zip"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&zip_bytes, "_intern.is_zip", 1).expect("zip intern"),
            Some(true)
        );

        let lnk_path = tmp.path().join("sample.lnk");
        let mut lnk = vec![0u8; 76];
        lnk[0..4].copy_from_slice(&0x4cu32.to_le_bytes());
        lnk[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        let ft = ((11_644_473_600u64 + 60) * 10_000_000).to_le_bytes();
        lnk[28..36].copy_from_slice(&ft);
        lnk[36..44].copy_from_slice(&ft);
        lnk[44..52].copy_from_slice(&ft);
        fs::write(&lnk_path, &lnk).expect("write lnk");
        let lnk_bytes = extract_compact_document_metadata(&lnk_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&lnk_bytes, "lnk.is_lnk", 1).expect("lnk"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&lnk_bytes, "lnk.creation_time", 60).expect("lnk ts"),
            Some(true)
        );
    }

    #[test]
    fn decode_and_helper_errors_are_reported() {
        assert!(decode(&[METADATA_VERSION]).is_err());
        assert!(
            decode(&[9, 0, 0, 0, 0, 0, 0])
                .expect_err("unsupported version")
                .to_string()
                .contains("Unsupported compact document metadata version")
        );
        assert!(
            decode(&[METADATA_VERSION, 0, 0, 0, 0, 0, 0, 1])
                .expect_err("trailing bytes")
                .to_string()
                .contains("Trailing compact document metadata bytes")
        );
        assert!(
            decode(&[METADATA_VERSION, 0, 0, 0, 0, 1, 0, 0x80])
                .expect_err("truncated varint")
                .to_string()
                .contains("Truncated compact document metadata")
        );
        assert!(normalize_query_metadata_field("not.real").is_none());
        assert!(!metadata_field_is_boolean("not.real"));
        assert!(!metadata_field_is_integer("not.real"));
        assert_eq!(
            normalize_query_metadata_field("MaChO.CPUType"),
            Some("macho.cpu_type")
        );
    }

    #[test]
    fn extracts_big_endian_elf_and_thin_macho_metadata() {
        let tmp = tempdir().expect("tmp");

        let elf_path = tmp.path().join("sample_be.elf");
        let mut elf = vec![0u8; 64];
        elf[0..4].copy_from_slice(b"\x7fELF");
        elf[4] = 1;
        elf[5] = 2;
        elf[7] = 9;
        elf[16..18].copy_from_slice(&3u16.to_be_bytes());
        elf[18..20].copy_from_slice(&22u16.to_be_bytes());
        fs::write(&elf_path, &elf).expect("write elf");
        let elf_bytes = extract_compact_document_metadata(&elf_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.type", 3).expect("elf type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.machine", 22).expect("elf machine"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.os_abi", 9).expect("elf osabi"),
            Some(true)
        );

        let macho_path = tmp.path().join("sample.macho");
        let mut macho = vec![0u8; 40];
        macho[0..4].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[4..8].copy_from_slice(&0x0100_0007u32.to_le_bytes());
        macho[16..20].copy_from_slice(&1u32.to_le_bytes());
        macho[20..24].copy_from_slice(&8u32.to_le_bytes());
        macho[32..36].copy_from_slice(&0x24u32.to_le_bytes());
        macho[36..40].copy_from_slice(&8u32.to_le_bytes());
        fs::write(&macho_path, &macho).expect("write macho");
        let macho_bytes = extract_compact_document_metadata(&macho_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_type", 0x0100_0007)
                .expect("macho cpu"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.device_type", 0x24)
                .expect("macho device"),
            Some(true)
        );
        assert_eq!(
            normalize_query_metadata_field("macho.cputype"),
            Some("macho.cpu_type")
        );
        assert_eq!(
            normalize_query_metadata_field("macho.devicetype"),
            Some("macho.device_type")
        );
    }

    #[test]
    fn extracts_fat_macho_and_field_aliases() {
        let tmp = tempdir().expect("tmp");
        let macho_path = tmp.path().join("sample-fat.macho");
        let mut macho = vec![0u8; 0x140];
        macho[0..4].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        macho[4..8].copy_from_slice(&1u32.to_be_bytes());
        macho[8..12].copy_from_slice(&7u32.to_be_bytes());
        macho[16..20].copy_from_slice(&0x100u32.to_be_bytes());
        macho[20..24].copy_from_slice(&40u32.to_be_bytes());
        macho[0x100..0x104].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[0x104..0x108].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        macho[0x110..0x114].copy_from_slice(&1u32.to_le_bytes());
        macho[0x114..0x118].copy_from_slice(&8u32.to_le_bytes());
        macho[0x120..0x124].copy_from_slice(&0x25u32.to_le_bytes());
        macho[0x124..0x128].copy_from_slice(&8u32.to_le_bytes());
        fs::write(&macho_path, &macho).expect("write fat macho");
        let macho_bytes = extract_compact_document_metadata(&macho_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cputype", 7).expect("fat cpu type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_type", 0x0100_000c)
                .expect("thin cpu type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.devicetype", 0x25).expect("device type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "elf.machine", 62).expect("other module"),
            Some(false)
        );
    }
}
