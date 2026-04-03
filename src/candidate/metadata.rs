use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::{Result, SspryError};
use yara_x::mods::{self, pe::OptionalMagic};

const METADATA_VERSION: u8 = 1;
const MAX_MACHO_ARCHES: usize = 32;

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
    #[allow(dead_code)]
    ReservedLegacyZipBit = 11,
    #[allow(dead_code)]
    ReservedLegacyMzBit = 12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IntField {
    PeMachine = 0,
    PeSubsystem = 1,
    PeTimestamp = 2,
    PeCharacteristics = 3,
    ElfType = 4,
    ElfOsAbi = 5,
    ElfMachine = 6,
    MachoCpuType = 7,
    MachoFileType = 8,
    DexVersion = 9,
    LnkCreationTime = 10,
    LnkAccessTime = 11,
    LnkWriteTime = 12,
    MachoCpuSubtype = 13,
    MathEntropy = 14,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BytesField {
    PeEntryPointPrefix = 0,
    FilePrefix8 = 1,
}

const BYTES_FIELD_COUNT: usize = 2;
const INT_FIELD_COUNT: usize = IntField::MathEntropy as usize + 1;

#[derive(Clone, Debug, Default)]
struct MetadataBuilder {
    bool_known: u16,
    bool_values: u16,
    ints: [Vec<u64>; INT_FIELD_COUNT],
    bytes: [Vec<u8>; BYTES_FIELD_COUNT],
}

#[derive(Clone, Debug, Default)]
struct DecodedMetadata {
    bool_known: u16,
    bool_values: u16,
    ints: [Vec<u64>; INT_FIELD_COUNT],
    bytes: [Vec<u8>; BYTES_FIELD_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ByteOrder {
    Little,
    Big,
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

    fn set_bytes(&mut self, field: BytesField, value: &[u8]) {
        self.bytes[field as usize].clear();
        self.bytes[field as usize].extend_from_slice(value);
    }

    fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32);
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
        let mut bytes_presence = 0u16;
        for (idx, value) in self.bytes.iter().enumerate() {
            if !value.is_empty() {
                bytes_presence |= 1u16 << idx;
            }
        }
        out.extend_from_slice(&bytes_presence.to_le_bytes());
        for value in self.bytes {
            if value.is_empty() {
                continue;
            }
            encode_varint(value.len() as u64, &mut out);
            out.extend_from_slice(&value);
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
    let version = bytes[0];
    if version != METADATA_VERSION {
        return Err(SspryError::from(format!(
            "Unsupported compact document metadata version: {}",
            version
        )));
    }
    let bool_known = u16::from_le_bytes(bytes[1..3].try_into().expect("bool_known"));
    let bool_values = u16::from_le_bytes(bytes[3..5].try_into().expect("bool_values"));
    let int_presence = u16::from_le_bytes(bytes[5..7].try_into().expect("int_presence"));
    let mut offset = 7usize;
    let mut ints: [Vec<u64>; INT_FIELD_COUNT] = Default::default();
    for idx in 0..INT_FIELD_COUNT {
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
    let mut byte_values: [Vec<u8>; BYTES_FIELD_COUNT] = Default::default();
    if offset + 2 > bytes.len() {
        return Err(SspryError::from("Invalid compact document metadata."));
    }
    let bytes_presence = u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("bytes_presence"),
    );
    offset += 2;
    for (idx, value) in byte_values.iter_mut().enumerate() {
        if (bytes_presence & (1u16 << idx)) == 0 {
            continue;
        }
        let count = decode_varint(bytes, &mut offset)? as usize;
        let end = offset.saturating_add(count);
        if end > bytes.len() {
            return Err(SspryError::from("Truncated compact document metadata."));
        }
        *value = bytes[offset..end].to_vec();
        offset = end;
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
        bytes: byte_values,
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

fn initialize_known_bool_metadata(builder: &mut MetadataBuilder) {
    builder.set_bool(BoolField::CrxIsCrx, false);
    builder.set_bool(BoolField::PeIsPe, false);
    builder.set_bool(BoolField::PeIs32Bit, false);
    builder.set_bool(BoolField::PeIs64Bit, false);
    builder.set_bool(BoolField::PeIsDll, false);
    builder.set_bool(BoolField::PeIsSigned, false);
    builder.set_bool(BoolField::DotnetIsDotnet, false);
    builder.set_bool(BoolField::DexIsDex, false);
    builder.set_bool(BoolField::LnkIsLnk, false);
    builder.set_bool(BoolField::ElfIsElf, false);
    builder.set_bool(BoolField::MachoIsMacho, false);
}

fn extract_yarax_module_metadata(bytes: &[u8], builder: &mut MetadataBuilder) {
    initialize_known_bool_metadata(builder);

    let modules = mods::invoke_all(bytes);

    if let Some(crx) = modules.crx.as_ref() {
        builder.set_bool(BoolField::CrxIsCrx, crx.is_crx());
    }

    if let Some(dex) = modules.dex.as_ref() {
        builder.set_bool(BoolField::DexIsDex, dex.is_dex());
        if let Some(header) = dex.header.as_ref() {
            if header.has_version() {
                builder.push_int(IntField::DexVersion, u64::from(header.version()));
            }
        }
    }

    if let Some(lnk) = modules.lnk.as_ref() {
        builder.set_bool(BoolField::LnkIsLnk, lnk.is_lnk());
        if lnk.has_creation_time() {
            builder.push_int(IntField::LnkCreationTime, lnk.creation_time());
        }
        if lnk.has_access_time() {
            builder.push_int(IntField::LnkAccessTime, lnk.access_time());
        }
        if lnk.has_write_time() {
            builder.push_int(IntField::LnkWriteTime, lnk.write_time());
        }
    }

    if let Some(elf) = modules.elf.as_ref() {
        let is_elf = elf.has_type()
            || elf.has_machine()
            || elf.has_osabi()
            || elf.has_entry_point()
            || elf.has_number_of_sections()
            || elf.has_number_of_segments();
        builder.set_bool(BoolField::ElfIsElf, is_elf);
        if elf.has_type() {
            builder.push_int(IntField::ElfType, elf.type_() as u64);
        }
        if elf.has_osabi() {
            builder.push_int(IntField::ElfOsAbi, elf.osabi() as u64);
        }
        if elf.has_machine() {
            builder.push_int(IntField::ElfMachine, elf.machine() as u64);
        }
    }

    if let Some(pe) = modules.pe.as_ref() {
        builder.set_bool(BoolField::PeIsPe, pe.is_pe());
        if pe.has_machine() {
            builder.push_int(IntField::PeMachine, pe.machine() as u64);
        }
        if pe.has_subsystem() {
            builder.push_int(IntField::PeSubsystem, pe.subsystem() as u64);
        }
        if pe.has_timestamp() {
            builder.push_int(IntField::PeTimestamp, u64::from(pe.timestamp()));
        }
        if pe.has_characteristics() {
            let characteristics = pe.characteristics();
            builder.push_int(IntField::PeCharacteristics, u64::from(characteristics));
            builder.set_bool(BoolField::PeIsDll, (characteristics & 0x2000) != 0);
        }
        if pe.has_opthdr_magic() {
            match pe.opthdr_magic() {
                OptionalMagic::IMAGE_NT_OPTIONAL_HDR32_MAGIC => {
                    builder.set_bool(BoolField::PeIs32Bit, true);
                }
                OptionalMagic::IMAGE_NT_OPTIONAL_HDR64_MAGIC => {
                    builder.set_bool(BoolField::PeIs64Bit, true);
                }
                OptionalMagic::IMAGE_ROM_OPTIONAL_HDR_MAGIC => {}
            }
        }
        if pe.has_is_signed() {
            builder.set_bool(BoolField::PeIsSigned, pe.is_signed());
        }
        if pe.has_entry_point() {
            let entry_point = pe.entry_point() as usize;
            let end = entry_point.saturating_add(16);
            if end <= bytes.len() {
                builder.set_bytes(BytesField::PeEntryPointPrefix, &bytes[entry_point..end]);
            }
        }
    }

    if let Some(dotnet) = modules.dotnet.as_ref() {
        builder.set_bool(BoolField::DotnetIsDotnet, dotnet.is_dotnet());
    }

    if let Some(macho) = modules.macho.as_ref() {
        if macho.has_cputype() {
            builder.push_int(IntField::MachoCpuType, u64::from(macho.cputype()));
        }
        if macho.has_cpusubtype() {
            builder.push_int(IntField::MachoCpuSubtype, u64::from(macho.cpusubtype()));
        }
        if macho.has_filetype() {
            builder.push_int(IntField::MachoFileType, u64::from(macho.filetype()));
        }
        for file in &macho.file {
            if file.has_cputype() {
                builder.push_int(IntField::MachoCpuType, u64::from(file.cputype()));
            }
            if file.has_cpusubtype() {
                builder.push_int(IntField::MachoCpuSubtype, u64::from(file.cpusubtype()));
            }
            if file.has_filetype() {
                builder.push_int(IntField::MachoFileType, u64::from(file.filetype()));
            }
        }
        for arch in &macho.fat_arch {
            if arch.has_cputype() {
                builder.push_int(IntField::MachoCpuType, u64::from(arch.cputype()));
            }
            if arch.has_cpusubtype() {
                builder.push_int(IntField::MachoCpuSubtype, u64::from(arch.cpusubtype()));
            }
        }
    }
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

fn thin_macho_order(magic: [u8; 4]) -> Option<ByteOrder> {
    match magic {
        [0xfe, 0xed, 0xfa, 0xce] => Some(ByteOrder::Big),
        [0xce, 0xfa, 0xed, 0xfe] => Some(ByteOrder::Little),
        [0xfe, 0xed, 0xfa, 0xcf] => Some(ByteOrder::Big),
        [0xcf, 0xfa, 0xed, 0xfe] => Some(ByteOrder::Little),
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
    let Some(order) = thin_macho_order(header[0..4].try_into().expect("magic")) else {
        return Ok(false);
    };
    builder.push_int(
        IntField::MachoCpuType,
        u64::from(read_u32(&header[4..8], order)),
    );
    builder.push_int(
        IntField::MachoCpuSubtype,
        u64::from(read_u32(&header[8..12], order)),
    );
    builder.push_int(
        IntField::MachoFileType,
        u64::from(read_u32(&header[12..16], order)),
    );
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
    if thin_macho_order(magic).is_some() {
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
        builder.push_int(
            IntField::MachoCpuSubtype,
            u64::from(read_u32(&entry[4..8], order)),
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

fn entropy_bits_per_byte(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let total = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let probability = count as f64 / total;
        entropy -= probability * probability.log2();
    }
    entropy as f32
}

pub fn extract_compact_document_metadata(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path)?;
    let prefix = read_prefix(&mut file, 4096)?;
    file.seek(SeekFrom::Start(0))?;
    let mut file_bytes = Vec::new();
    file.read_to_end(&mut file_bytes)?;
    let mut builder = MetadataBuilder::default();
    builder.set_bytes(
        BytesField::FilePrefix8,
        &file_bytes[..file_bytes.len().min(8)],
    );
    builder.push_int(
        IntField::MathEntropy,
        u64::from(entropy_bits_per_byte(&file_bytes).to_bits()),
    );
    extract_yarax_module_metadata(&file_bytes, &mut builder);
    extract_macho_metadata(&mut file, &prefix, &mut builder)?;
    Ok(builder.encode())
}

fn normalize_field(raw: &str) -> Option<&'static str> {
    match raw.to_ascii_lowercase().as_str() {
        "crx.is_crx" => Some("crx.is_crx"),
        "pe.is_pe" => Some("pe.is_pe"),
        "pe.is_32bit" => Some("pe.is_32bit"),
        "pe.is_64bit" => Some("pe.is_64bit"),
        "pe.is_dll" => Some("pe.is_dll"),
        "pe.is_signed" => Some("pe.is_signed"),
        "pe.machine" => Some("pe.machine"),
        "pe.subsystem" => Some("pe.subsystem"),
        "pe.timestamp" => Some("pe.timestamp"),
        "pe.characteristics" => Some("pe.characteristics"),
        "elf.is_elf" => Some("elf.is_elf"),
        "elf.type" => Some("elf.type"),
        "elf.os_abi" | "elf.osabi" => Some("elf.os_abi"),
        "elf.machine" => Some("elf.machine"),
        "macho.cpu_type" | "macho.cputype" => Some("macho.cpu_type"),
        "macho.cpu_subtype" | "macho.cpusubtype" => Some("macho.cpu_subtype"),
        "macho.file_type" | "macho.filetype" => Some("macho.file_type"),
        "dotnet.is_dotnet" => Some("dotnet.is_dotnet"),
        "dex.is_dex" => Some("dex.is_dex"),
        "dex.version" => Some("dex.version"),
        "lnk.is_lnk" => Some("lnk.is_lnk"),
        "lnk.creation_time" => Some("lnk.creation_time"),
        "lnk.access_time" => Some("lnk.access_time"),
        "lnk.write_time" => Some("lnk.write_time"),
        "math.entropy" => Some("math.entropy"),
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
                | "pe.is_pe"
                | "pe.is_32bit"
                | "pe.is_64bit"
                | "pe.is_dll"
                | "pe.is_signed"
                | "dotnet.is_dotnet"
                | "dex.is_dex"
                | "lnk.is_lnk"
                | "elf.is_elf"
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
                | "pe.characteristics"
                | "elf.type"
                | "elf.os_abi"
                | "elf.machine"
                | "macho.cpu_type"
                | "macho.cpu_subtype"
                | "macho.file_type"
                | "dex.version"
                | "lnk.creation_time"
                | "lnk.access_time"
                | "lnk.write_time"
                | "time.now"
        )
    )
}

pub fn metadata_field_is_float(raw: &str) -> bool {
    matches!(normalize_field(raw), Some("math.entropy"))
}

fn bool_field_for_name(field: &str) -> Option<BoolField> {
    match field {
        "crx.is_crx" => Some(BoolField::CrxIsCrx),
        "pe.is_pe" => Some(BoolField::PeIsPe),
        "pe.is_32bit" => Some(BoolField::PeIs32Bit),
        "pe.is_64bit" => Some(BoolField::PeIs64Bit),
        "pe.is_dll" => Some(BoolField::PeIsDll),
        "pe.is_signed" => Some(BoolField::PeIsSigned),
        "dotnet.is_dotnet" => Some(BoolField::DotnetIsDotnet),
        "dex.is_dex" => Some(BoolField::DexIsDex),
        "lnk.is_lnk" => Some(BoolField::LnkIsLnk),
        "elf.is_elf" => Some(BoolField::ElfIsElf),
        _ => None,
    }
}

fn int_field_for_name(field: &str) -> Option<IntField> {
    match field {
        "pe.machine" => Some(IntField::PeMachine),
        "pe.subsystem" => Some(IntField::PeSubsystem),
        "pe.timestamp" => Some(IntField::PeTimestamp),
        "pe.characteristics" => Some(IntField::PeCharacteristics),
        "elf.type" => Some(IntField::ElfType),
        "elf.os_abi" => Some(IntField::ElfOsAbi),
        "elf.machine" => Some(IntField::ElfMachine),
        "macho.cpu_type" => Some(IntField::MachoCpuType),
        "macho.cpu_subtype" => Some(IntField::MachoCpuSubtype),
        "macho.file_type" => Some(IntField::MachoFileType),
        "dex.version" => Some(IntField::DexVersion),
        "lnk.creation_time" => Some(IntField::LnkCreationTime),
        "lnk.access_time" => Some(IntField::LnkAccessTime),
        "lnk.write_time" => Some(IntField::LnkWriteTime),
        "math.entropy" => Some(IntField::MathEntropy),
        _ => None,
    }
}

fn module_guard_for_field(field: &str) -> Option<BoolField> {
    match field {
        "pe.machine" | "pe.subsystem" | "pe.timestamp" | "pe.characteristics" => {
            Some(BoolField::PeIsPe)
        }
        "elf.type" | "elf.os_abi" | "elf.machine" => Some(BoolField::ElfIsElf),
        "macho.cpu_type" | "macho.cpu_subtype" | "macho.file_type" => Some(BoolField::MachoIsMacho),
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataCompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

fn compare_u64(lhs: u64, rhs: u64, op: MetadataCompareOp) -> bool {
    match op {
        MetadataCompareOp::Eq => lhs == rhs,
        MetadataCompareOp::Ne => lhs != rhs,
        MetadataCompareOp::Lt => lhs < rhs,
        MetadataCompareOp::Le => lhs <= rhs,
        MetadataCompareOp::Gt => lhs > rhs,
        MetadataCompareOp::Ge => lhs >= rhs,
    }
}

fn compare_f32(lhs: f32, rhs: f32, op: MetadataCompareOp) -> bool {
    match op {
        MetadataCompareOp::Eq => lhs == rhs,
        MetadataCompareOp::Ne => lhs != rhs,
        MetadataCompareOp::Lt => lhs < rhs,
        MetadataCompareOp::Le => lhs <= rhs,
        MetadataCompareOp::Gt => lhs > rhs,
        MetadataCompareOp::Ge => lhs >= rhs,
    }
}

fn decoded_field_values<'a>(
    decoded: &'a DecodedMetadata,
    field: &str,
) -> Result<Option<&'a [u64]>> {
    if field == "time.now" {
        return Ok(None);
    }
    if let Some(module_guard) = module_guard_for_field(field)
        && bool_value(decoded, module_guard) == Some(false)
    {
        return Ok(Some(&[]));
    }
    let Some(int_field) = int_field_for_name(field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {field}"
        )));
    };
    let values = &decoded.ints[int_field as usize];
    if values.is_empty() {
        Ok(None)
    } else {
        Ok(Some(values.as_slice()))
    }
}

pub fn metadata_field_matches_eq(
    bytes: &[u8],
    raw_field: &str,
    expected: u64,
) -> Result<Option<bool>> {
    metadata_field_matches_compare(bytes, raw_field, MetadataCompareOp::Eq, expected)
}

pub fn metadata_field_matches_compare(
    bytes: &[u8],
    raw_field: &str,
    op: MetadataCompareOp,
    expected: u64,
) -> Result<Option<bool>> {
    let Some(field) = normalize_field(raw_field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_field}"
        )));
    };
    let decoded = decode(bytes)?;
    if let Some(bool_field) = bool_field_for_name(field) {
        return match op {
            MetadataCompareOp::Eq | MetadataCompareOp::Ne => Ok(bool_value(&decoded, bool_field)
                .map(|value| compare_u64(u64::from(value), u64::from(expected != 0), op))),
            _ => Err(SspryError::from(format!(
                "Unsupported metadata comparison for boolean field: {raw_field}"
            ))),
        };
    }
    let Some(values) = decoded_field_values(&decoded, field)? else {
        return Ok(None);
    };
    Ok(Some(
        values
            .iter()
            .copied()
            .any(|value| compare_u64(value, expected, op)),
    ))
}

pub fn metadata_field_matches_compare_f32(
    bytes: &[u8],
    raw_field: &str,
    op: MetadataCompareOp,
    expected: f32,
) -> Result<Option<bool>> {
    let Some(field) = normalize_field(raw_field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_field}"
        )));
    };
    if !metadata_field_is_float(field) {
        return Err(SspryError::from(format!(
            "Unsupported float metadata field: {raw_field}"
        )));
    }
    let decoded = decode(bytes)?;
    let Some(values) = decoded_field_values(&decoded, field)? else {
        return Ok(None);
    };
    Ok(Some(values.iter().copied().any(|value| {
        compare_f32(f32::from_bits(value as u32), expected, op)
    })))
}

pub fn metadata_fields_compare(
    bytes: &[u8],
    raw_lhs_field: &str,
    op: MetadataCompareOp,
    raw_rhs_field: &str,
) -> Result<Option<bool>> {
    let Some(lhs_field) = normalize_field(raw_lhs_field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_lhs_field}"
        )));
    };
    let Some(rhs_field) = normalize_field(raw_rhs_field) else {
        return Err(SspryError::from(format!(
            "Unsupported metadata field: {raw_rhs_field}"
        )));
    };
    let decoded = decode(bytes)?;
    let Some(lhs_values) = decoded_field_values(&decoded, lhs_field)? else {
        return Ok(None);
    };
    let Some(rhs_values) = decoded_field_values(&decoded, rhs_field)? else {
        return Ok(None);
    };
    Ok(Some(lhs_values.iter().copied().any(|lhs| {
        rhs_values
            .iter()
            .copied()
            .any(|rhs| compare_u64(lhs, rhs, op))
    })))
}

pub fn metadata_pe_entry_point_prefix(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let decoded = decode(bytes)?;
    let value = &decoded.bytes[BytesField::PeEntryPointPrefix as usize];
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.clone()))
    }
}

pub fn metadata_file_prefix_8(bytes: &[u8]) -> Result<Option<Vec<u8>>> {
    let decoded = decode(bytes)?;
    let value = &decoded.bytes[BytesField::FilePrefix8 as usize];
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.clone()))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use tempfile::tempdir;
    use yara_x::{Compiler as YaraCompiler, Scanner as YaraScanner};

    use super::*;

    fn yara_condition_matches_file(imports: &[&str], condition: &str, path: &Path) -> bool {
        let mut source = String::new();
        for module in imports {
            source.push_str("import \"");
            source.push_str(module);
            source.push_str("\"\n");
        }
        source.push_str("rule test {\ncondition:\n  ");
        source.push_str(condition);
        source.push_str("\n}\n");
        let mut compiler = YaraCompiler::new();
        compiler
            .add_source(source.as_str())
            .expect("compile yara-x probe");
        let rules = compiler.build();
        let mut scanner = YaraScanner::new(&rules);
        scanner
            .scan_file(path)
            .expect("scan yara-x probe")
            .matching_rules()
            .next()
            .is_some()
    }

    fn assert_no_false_negative(label: &str, oracle: bool, ours: bool) {
        assert!(
            !oracle || ours,
            "{label}: YARA-X matched but compact metadata fast path rejected"
        );
    }

    #[test]
    fn compact_metadata_roundtrip_and_normalization() {
        let mut builder = MetadataBuilder::default();
        builder.set_bool(BoolField::PeIsPe, true);
        builder.set_bool(BoolField::PeIsDll, false);
        builder.push_int(IntField::PeMachine, 0x14c);
        builder.push_int(IntField::PeCharacteristics, 0x2000);
        builder.push_int(IntField::MachoCpuType, 7);
        builder.push_int(IntField::MachoCpuSubtype, 3);
        builder.push_int(IntField::MachoFileType, 6);
        builder.push_int(IntField::MachoCpuType, 7);
        builder.set_bytes(BytesField::PeEntryPointPrefix, b"ABCDEFGHIJKLMNOP");
        builder.set_bytes(BytesField::FilePrefix8, b"MZprefix");
        let bytes = builder.encode();
        let decoded = decode(&bytes).expect("decode");
        assert_eq!(bool_value(&decoded, BoolField::PeIsPe), Some(true));
        assert_eq!(bool_value(&decoded, BoolField::PeIsDll), Some(false));
        assert_eq!(decoded.ints[IntField::PeMachine as usize], vec![0x14c]);
        assert_eq!(
            decoded.ints[IntField::PeCharacteristics as usize],
            vec![0x2000]
        );
        assert_eq!(decoded.ints[IntField::MachoCpuType as usize], vec![7]);
        assert_eq!(decoded.ints[IntField::MachoCpuSubtype as usize], vec![3]);
        assert_eq!(decoded.ints[IntField::MachoFileType as usize], vec![6]);
        assert_eq!(
            decoded.bytes[BytesField::PeEntryPointPrefix as usize],
            b"ABCDEFGHIJKLMNOP"
        );
        assert_eq!(decoded.bytes[BytesField::FilePrefix8 as usize], b"MZprefix");
        assert_eq!(
            normalize_query_metadata_field("ELF.OSABI"),
            Some("elf.os_abi")
        );
        assert_eq!(normalize_query_metadata_field("zip.is_zip"), None);
        assert_eq!(normalize_query_metadata_field("_intern.is_zip"), None);
        assert_eq!(normalize_query_metadata_field("_intern.is_mz"), None);
        assert!(metadata_field_is_boolean("pe.is_dll"));
        assert!(metadata_field_is_boolean("elf.is_elf"));
        assert!(!metadata_field_is_boolean("zip.is_zip"));
        assert!(!metadata_field_is_boolean("_intern.is_zip"));
        assert!(!metadata_field_is_boolean("_intern.is_mz"));
        assert!(metadata_field_is_integer("pe.characteristics"));
        assert!(metadata_field_is_integer("macho.cpu_subtype"));
        assert!(metadata_field_is_integer("macho.file_type"));
        assert!(metadata_field_is_float("math.entropy"));
    }

    #[test]
    fn metadata_field_matching_handles_unknown_and_guard_bools() {
        let mut builder = MetadataBuilder::default();
        builder.set_bool(BoolField::PeIsPe, false);
        builder.push_int(IntField::LnkCreationTime, 10);
        builder.push_int(IntField::LnkWriteTime, 20);
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
        assert!(
            metadata_field_matches_eq(&bytes, "zip.is_zip", 1)
                .expect_err("zip removed")
                .to_string()
                .contains("Unsupported metadata field")
        );
        assert!(
            metadata_field_matches_eq(&bytes, "_intern.is_mz", 1)
                .expect_err("mz removed")
                .to_string()
                .contains("Unsupported metadata field")
        );
        assert_eq!(
            metadata_field_matches_eq(&[], "pe.machine", 0x14c).expect("unknown"),
            None
        );
        assert_eq!(
            metadata_field_matches_eq(&bytes, "time.now", 1234).expect("time.now"),
            None
        );
        assert_eq!(
            metadata_field_matches_compare(&bytes, "lnk.creation_time", MetadataCompareOp::Lt, 11)
                .expect("lt"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_compare(&bytes, "lnk.creation_time", MetadataCompareOp::Ne, 10)
                .expect("ne"),
            Some(false)
        );
        assert_eq!(
            metadata_fields_compare(
                &bytes,
                "lnk.creation_time",
                MetadataCompareOp::Lt,
                "lnk.write_time"
            )
            .expect("field compare"),
            Some(true)
        );
        assert!(
            metadata_field_matches_eq(&bytes, "bogus.field", 1)
                .expect_err("unknown field")
                .to_string()
                .contains("Unsupported metadata field")
        );
    }

    #[test]
    fn extracted_metadata_includes_first_eight_file_bytes() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("prefix.bin");
        fs::write(&path, b"ABCDEFGHijklmnop").expect("write prefix");
        let metadata = extract_compact_document_metadata(&path).expect("metadata");
        assert_eq!(
            metadata_file_prefix_8(&metadata).expect("decode prefix"),
            Some(b"ABCDEFGH".to_vec())
        );
    }

    #[test]
    fn extracted_metadata_includes_math_entropy() {
        let tmp = tempdir().expect("tmp");
        let path = tmp.path().join("entropy.bin");
        fs::write(&path, [0u8; 64]).expect("write entropy");
        let metadata = extract_compact_document_metadata(&path).expect("metadata");
        assert_eq!(
            metadata_field_matches_compare_f32(
                &metadata,
                "math.entropy",
                MetadataCompareOp::Eq,
                0.0
            )
            .expect("entropy compare"),
            Some(true)
        );
        assert_no_false_negative(
            "math entropy",
            yara_condition_matches_file(&["math"], "math.entropy(0, filesize) <= 0.0", &path),
            metadata_field_matches_compare_f32(
                &metadata,
                "math.entropy",
                MetadataCompareOp::Le,
                0.0,
            )
            .expect("entropy oracle compare")
            .expect("known entropy"),
        );
    }

    #[test]
    fn extracts_basic_module_metadata_from_small_headers() {
        let tmp = tempdir().expect("tmp");
        let pe_path = tmp.path().join("sample.exe");
        let mut pe = vec![0u8; 0x240];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x88..0x8c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        pe[0x96..0x98].copy_from_slice(&0x0200u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[0x98 + 16..0x98 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
        pe[0x98 + 112 + 32..0x98 + 112 + 40].copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
        pe[0x98 + 112 + 112..0x98 + 112 + 120].copy_from_slice(&[1, 0, 0, 0, 8, 0, 0, 0]);
        let text_section = 0x80 + 24 + 0xf0;
        pe[text_section..text_section + 8].copy_from_slice(b".text\0\0\0");
        pe[text_section + 8..text_section + 12].copy_from_slice(&0x20u32.to_le_bytes());
        pe[text_section + 12..text_section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        pe[text_section + 16..text_section + 20].copy_from_slice(&0x20u32.to_le_bytes());
        pe[text_section + 20..text_section + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe[0x200..0x210].copy_from_slice(b"ENTRYPOINT-PE!!!");
        fs::write(&pe_path, &pe).expect("write pe");
        let pe_bytes = extract_compact_document_metadata(&pe_path).expect("metadata");
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
            Some(false)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.machine", 0x14c).expect("machine"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "pe.characteristics", 0x0200)
                .expect("characteristics"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&pe_bytes, "dotnet.is_dotnet", 1).expect("dotnet"),
            Some(false)
        );
        assert_eq!(
            metadata_pe_entry_point_prefix(&pe_bytes).expect("entry point prefix"),
            Some(b"ENTRYPOINT-PE!!!".to_vec())
        );
        assert_no_false_negative(
            "pe.is_pe",
            yara_condition_matches_file(&["pe"], "pe.is_pe", &pe_path),
            metadata_field_matches_eq(&pe_bytes, "pe.is_pe", 1)
                .expect("pe is_pe")
                .expect("known pe is_pe"),
        );
        assert_no_false_negative(
            "pe.machine",
            yara_condition_matches_file(&["pe"], "pe.machine == 0x14c", &pe_path),
            metadata_field_matches_eq(&pe_bytes, "pe.machine", 0x14c)
                .expect("pe machine")
                .expect("known pe machine"),
        );
        assert_no_false_negative(
            "pe.timestamp",
            yara_condition_matches_file(
                &["pe"],
                "pe.timestamp == 0x12345678 and pe.timestamp < 0x20000000",
                &pe_path,
            ),
            metadata_field_matches_eq(&pe_bytes, "pe.timestamp", 0x1234_5678)
                .expect("pe timestamp")
                .expect("known pe timestamp")
                && metadata_field_matches_compare(
                    &pe_bytes,
                    "pe.timestamp",
                    MetadataCompareOp::Lt,
                    0x2000_0000,
                )
                .expect("pe timestamp lt")
                .expect("known pe timestamp lt"),
        );
        assert_no_false_negative(
            "pe.is_64bit",
            yara_condition_matches_file(&["pe"], "pe.is_64bit()", &pe_path),
            metadata_field_matches_eq(&pe_bytes, "pe.is_64bit", 1)
                .expect("pe is_64bit")
                .expect("known pe is_64bit"),
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
        assert_no_false_negative(
            "elf fields",
            yara_condition_matches_file(
                &["elf"],
                "elf.type == 2 and elf.machine == 62 and elf.osabi == 3",
                &elf_path,
            ),
            metadata_field_matches_eq(&elf_bytes, "elf.type", 2)
                .expect("elf type")
                .expect("known elf type")
                && metadata_field_matches_eq(&elf_bytes, "elf.machine", 62)
                    .expect("elf machine")
                    .expect("known elf machine")
                && metadata_field_matches_eq(&elf_bytes, "elf.os_abi", 3)
                    .expect("elf osabi")
                    .expect("known elf osabi"),
        );

        let dex_path = tmp.path().join("sample.dex");
        let mut dex = vec![0u8; 0x70];
        let dex_file_size = dex.len() as u32;
        dex[0..4].copy_from_slice(b"dex\n");
        dex[4..7].copy_from_slice(b"035");
        dex[7] = 0;
        dex[32..36].copy_from_slice(&dex_file_size.to_le_bytes());
        dex[36..40].copy_from_slice(&0x70u32.to_le_bytes());
        dex[40..44].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        fs::write(&dex_path, &dex).expect("write dex");
        let dex_bytes = extract_compact_document_metadata(&dex_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&dex_bytes, "dex.is_dex", 1).expect("dex"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&dex_bytes, "dex.version", 35).expect("dex version"),
            Some(true)
        );
        assert_no_false_negative(
            "dex fields",
            yara_condition_matches_file(
                &["dex"],
                "dex.is_dex and dex.header.version == 35",
                &dex_path,
            ),
            metadata_field_matches_eq(&dex_bytes, "dex.is_dex", 1)
                .expect("dex is_dex")
                .expect("known dex is_dex")
                && metadata_field_matches_eq(&dex_bytes, "dex.version", 35)
                    .expect("dex version")
                    .expect("known dex version"),
        );

        let crx_path = tmp.path().join("sample.crx");
        let mut crx = Vec::new();
        crx.extend_from_slice(b"Cr24");
        crx.extend_from_slice(&2u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(&0u32.to_le_bytes());
        crx.extend_from_slice(b"PK\x05\x06");
        crx.extend_from_slice(&[0u8; 18]);
        fs::write(&crx_path, &crx).expect("write crx");
        let crx_bytes = extract_compact_document_metadata(&crx_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&crx_bytes, "crx.is_crx", 1).expect("crx"),
            Some(true)
        );
        assert_no_false_negative(
            "crx.is_crx",
            yara_condition_matches_file(&["crx"], "crx.is_crx", &crx_path),
            metadata_field_matches_eq(&crx_bytes, "crx.is_crx", 1)
                .expect("crx is_crx")
                .expect("known crx is_crx"),
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
        assert_no_false_negative(
            "lnk fields",
            yara_condition_matches_file(
                &["lnk"],
                "lnk.is_lnk and lnk.creation_time == 60 and lnk.access_time == 60 and lnk.write_time == 60 and lnk.creation_time < 61",
                &lnk_path,
            ),
            metadata_field_matches_eq(&lnk_bytes, "lnk.is_lnk", 1)
                .expect("lnk is_lnk")
                .expect("known lnk is_lnk")
                && metadata_field_matches_eq(&lnk_bytes, "lnk.creation_time", 60)
                    .expect("lnk creation")
                    .expect("known lnk creation")
                && metadata_field_matches_eq(&lnk_bytes, "lnk.access_time", 60)
                    .expect("lnk access")
                    .expect("known lnk access")
                && metadata_field_matches_eq(&lnk_bytes, "lnk.write_time", 60)
                    .expect("lnk write")
                    .expect("known lnk write")
                && metadata_field_matches_compare(
                    &lnk_bytes,
                    "lnk.creation_time",
                    MetadataCompareOp::Lt,
                    61,
                )
                .expect("lnk lt")
                .expect("known lnk lt"),
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
            decode(&[METADATA_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 1])
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
        elf[18..20].copy_from_slice(&21u16.to_be_bytes());
        fs::write(&elf_path, &elf).expect("write elf");
        let elf_bytes = extract_compact_document_metadata(&elf_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.type", 3).expect("elf type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&elf_bytes, "elf.machine", 21).expect("elf machine"),
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
        macho[8..12].copy_from_slice(&3u32.to_le_bytes());
        macho[12..16].copy_from_slice(&6u32.to_le_bytes());
        macho[16..20].copy_from_slice(&1u32.to_le_bytes());
        macho[20..24].copy_from_slice(&8u32.to_le_bytes());
        fs::write(&macho_path, &macho).expect("write macho");
        let macho_bytes = extract_compact_document_metadata(&macho_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_type", 0x0100_0007)
                .expect("macho cpu"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_subtype", 3)
                .expect("macho cpu subtype"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.file_type", 6).expect("macho filetype"),
            Some(true)
        );
        assert_no_false_negative(
            "macho fields",
            yara_condition_matches_file(
                &["macho"],
                "macho.cputype == 0x01000007 and macho.filetype == 6",
                &macho_path,
            ),
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_type", 0x0100_0007)
                .expect("macho cpu")
                .expect("known macho cpu")
                && metadata_field_matches_eq(&macho_bytes, "macho.file_type", 6)
                    .expect("macho filetype")
                    .expect("known macho filetype"),
        );
        assert_eq!(
            normalize_query_metadata_field("macho.cputype"),
            Some("macho.cpu_type")
        );
        assert_eq!(
            normalize_query_metadata_field("macho.cpusubtype"),
            Some("macho.cpu_subtype")
        );
        assert_eq!(
            normalize_query_metadata_field("macho.filetype"),
            Some("macho.file_type")
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
        macho[12..16].copy_from_slice(&8u32.to_be_bytes());
        macho[16..20].copy_from_slice(&0x100u32.to_be_bytes());
        macho[20..24].copy_from_slice(&40u32.to_be_bytes());
        macho[0x100..0x104].copy_from_slice(&[0xcf, 0xfa, 0xed, 0xfe]);
        macho[0x104..0x108].copy_from_slice(&0x0100_000cu32.to_le_bytes());
        macho[0x108..0x10c].copy_from_slice(&9u32.to_le_bytes());
        macho[0x10c..0x110].copy_from_slice(&7u32.to_le_bytes());
        macho[0x110..0x114].copy_from_slice(&1u32.to_le_bytes());
        macho[0x114..0x118].copy_from_slice(&8u32.to_le_bytes());
        fs::write(&macho_path, &macho).expect("write fat macho");
        let macho_bytes = extract_compact_document_metadata(&macho_path).expect("metadata");
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cputype", 7).expect("fat cpu type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_subtype", 8)
                .expect("fat cpu subtype"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpu_type", 0x0100_000c)
                .expect("thin cpu type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.cpusubtype", 9)
                .expect("thin cpu subtype"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "macho.filetype", 7).expect("file type"),
            Some(true)
        );
        assert_eq!(
            metadata_field_matches_eq(&macho_bytes, "elf.machine", 62).expect("other module"),
            Some(false)
        );
    }
}
