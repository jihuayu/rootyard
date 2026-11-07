use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_OBJECT_SIZE: usize = 32 * 1024 * 1024;
pub const MAX_DELTA_DEPTH: usize = 64;
pub const MAX_OBJECTS: usize = 250_000;

pub const OBJ_COMMIT: u8 = 1;
pub const OBJ_TREE: u8 = 2;
pub const OBJ_BLOB: u8 = 3;
pub const OBJ_TAG: u8 = 4;
pub const OBJ_OFS_DELTA: u8 = 6;
pub const OBJ_REF_DELTA: u8 = 7;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ObjectType {
    Commit,
    Tree,
    Blob,
    Tag,
}

impl ObjectType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Commit => "commit",
            Self::Tree => "tree",
            Self::Blob => "blob",
            Self::Tag => "tag",
        }
    }

    pub fn from_raw(raw: u8) -> Result<Self> {
        match raw {
            OBJ_COMMIT => Ok(Self::Commit),
            OBJ_TREE => Ok(Self::Tree),
            OBJ_BLOB => Ok(Self::Blob),
            OBJ_TAG => Ok(Self::Tag),
            other => bail!("unsupported non-delta pack object type {other}"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_object_size: usize,
    pub max_delta_depth: usize,
    pub max_objects: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_object_size: MAX_OBJECT_SIZE,
            max_delta_depth: MAX_DELTA_DEPTH,
            max_objects: MAX_OBJECTS,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedObject {
    pub oid: String,
    pub sha256: String,
    pub obj_type: ObjectType,
    pub size: usize,
    pub pack_offset: usize,
    pub delta_depth: usize,
    pub base_oid: Option<String>,
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackReport {
    pub version: u32,
    pub object_count: usize,
    pub pack_sha1: String,
    pub pack_sha256: String,
    pub max_delta_depth_observed: usize,
    pub delta_objects: usize,
    pub base_objects: usize,
    pub objects: Vec<ResolvedObject>,
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Pure safe Rust FIPS 180-4 SHA-1 implementation for Git object OIDs and pack trailers.
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut padded = Vec::with_capacity((data.len() + 72) & !63);
    padded.extend_from_slice(data);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[i] = u32::from_be_bytes([word[0], word[1], word[2], word[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                _ => (b ^ c ^ d, 0xca62c1d6),
            };
            let temp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = temp;
        }
        for (dst, add) in h.iter_mut().zip([a, b, c, d, e]) {
            *dst = dst.wrapping_add(add);
        }
    }

    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn git_object_oid(obj_type: ObjectType, data: &[u8]) -> String {
    let header = format!("{} {}\0", obj_type.as_str(), data.len());
    let mut buf = Vec::with_capacity(header.len() + data.len());
    buf.extend_from_slice(header.as_bytes());
    buf.extend_from_slice(data);
    hex::encode(sha1_digest(&buf))
}

pub fn adler32(data: &[u8]) -> u32 {
    const MOD_ADLER: u32 = 65521;
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a += byte as u32;
            b += a;
        }
        a %= MOD_ADLER;
        b %= MOD_ADLER;
    }
    (b << 16) | a
}

/// Encodes `data` as a valid RFC 1950 zlib stream using stored (BTYPE=00) DEFLATE blocks.
pub fn compress_zlib_stored(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x78, 0x01];
    if data.is_empty() {
        out.extend_from_slice(&[0x01, 0x00, 0x00, 0xff, 0xff]);
    } else {
        let chunks: Vec<&[u8]> = data.chunks(65535).collect();
        for (idx, chunk) in chunks.iter().enumerate() {
            let bfinal = u8::from(idx + 1 == chunks.len());
            let len = chunk.len() as u16;
            out.push(bfinal);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&(!len).to_le_bytes());
            out.extend_from_slice(chunk);
        }
    }
    out.extend_from_slice(&adler32(data).to_be_bytes());
    out
}

struct BitReader<'a> {
    input: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(input: &'a [u8], start: usize) -> Self {
        Self { input, byte_pos: start, bit_pos: 0 }
    }

    fn read_bit(&mut self) -> Result<u32> {
        ensure!(self.byte_pos < self.input.len(), "truncated deflate bitstream");
        let bit = ((self.input[self.byte_pos] >> self.bit_pos) & 1) as u32;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Ok(bit)
    }

    fn read_bits(&mut self, count: u8) -> Result<u32> {
        let mut value = 0u32;
        for shift in 0..count {
            value |= self.read_bit()? << shift;
        }
        Ok(value)
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8]> {
        if self.bit_pos != 0 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        let end = self.byte_pos.checked_add(len).context("deflate byte slice overflow")?;
        ensure!(end <= self.input.len(), "truncated deflate byte block");
        let slice = &self.input[self.byte_pos..end];
        self.byte_pos = end;
        Ok(slice)
    }
}

struct HuffmanTable {
    counts: [u16; 16],
    symbols: Vec<u16>,
}

impl HuffmanTable {
    fn from_lengths(lengths: &[u8]) -> Result<Self> {
        let mut counts = [0u16; 16];
        for &len in lengths {
            ensure!(len <= 15, "invalid Huffman code length {len}");
            if len > 0 {
                counts[len as usize] += 1;
            }
        }
        let (mut offsets, mut total) = ([0usize; 16], 0usize);
        for bits in 1..=15 {
            offsets[bits] = total;
            total += counts[bits] as usize;
        }
        let mut symbols = vec![0u16; total];
        for (sym, &len) in lengths.iter().enumerate() {
            if len > 0 {
                symbols[offsets[len as usize]] = sym as u16;
                offsets[len as usize] += 1;
            }
        }
        Ok(Self { counts, symbols })
    }

    fn decode(&self, bits: &mut BitReader<'_>) -> Result<u16> {
        let (mut code, mut first, mut index) = (0i32, 0i32, 0usize);
        for len in 1..=15 {
            code |= bits.read_bit()? as i32;
            let count = self.counts[len] as i32;
            if code - count < first {
                return Ok(self.symbols[index + (code - first) as usize]);
            }
            index += count as usize;
            first = (first + count) << 1;
            code <<= 1;
        }
        bail!("invalid Huffman code in deflate stream")
    }
}

fn fixed_tables() -> Result<(HuffmanTable, HuffmanTable)> {
    let mut lit = [0u8; 288];
    lit[0..=143].fill(8);
    lit[144..=255].fill(9);
    lit[256..=279].fill(7);
    lit[280..=287].fill(8);
    Ok((HuffmanTable::from_lengths(&lit)?, HuffmanTable::from_lengths(&[5u8; 32])?))
}

fn dynamic_tables(bits: &mut BitReader<'_>) -> Result<(HuffmanTable, HuffmanTable)> {
    const CL_ORDER: [usize; 19] = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
    let hlit = bits.read_bits(5)? as usize + 257;
    let hdist = bits.read_bits(5)? as usize + 1;
    let hclen = bits.read_bits(4)? as usize + 4;
    ensure!(hlit <= 286 && hdist <= 32, "invalid dynamic Huffman counts");

    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CL_ORDER[i]] = bits.read_bits(3)? as u8;
    }
    let cl_table = HuffmanTable::from_lengths(&cl_lengths)?;
    let total = hlit + hdist;
    let mut lengths = Vec::with_capacity(total);
    while lengths.len() < total {
        match cl_table.decode(bits)? {
            sym @ 0..=15 => lengths.push(sym as u8),
            16 => {
                let prev = *lengths.last().context("repeat code 16 with no previous length")?;
                let repeat = bits.read_bits(2)? as usize + 3;
                ensure!(lengths.len() + repeat <= total, "code length repeat overflow");
                lengths.resize(lengths.len() + repeat, prev);
            }
            17 => {
                let repeat = bits.read_bits(3)? as usize + 3;
                ensure!(lengths.len() + repeat <= total, "code length zero overflow");
                lengths.resize(lengths.len() + repeat, 0);
            }
            18 => {
                let repeat = bits.read_bits(7)? as usize + 11;
                ensure!(lengths.len() + repeat <= total, "code length zero overflow");
                lengths.resize(lengths.len() + repeat, 0);
            }
            sym => bail!("invalid code length symbol {sym}"),
        }
    }
    Ok((
        HuffmanTable::from_lengths(&lengths[..hlit])?,
        HuffmanTable::from_lengths(&lengths[hlit..])?,
    ))
}

/// Inflates a single RFC 1950 zlib stream from the start of `input`, enforcing `max_output`
/// and returning `(decompressed_bytes, compressed_bytes_consumed)`.
pub fn inflate_zlib_stream(input: &[u8], max_output: usize) -> Result<(Vec<u8>, usize)> {
    const LENGTH_BASE: [usize; 29] = [
        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
        131, 163, 195, 227, 258,
    ];
    const LENGTH_EXTRA: [u8; 29] = [
        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
    ];
    const DIST_BASE: [usize; 30] = [
        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
        2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
    ];
    const DIST_EXTRA: [u8; 30] = [
        0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12,
        13, 13,
    ];

    ensure!(input.len() >= 6, "truncated zlib stream");
    let (cmf, flg) = (input[0], input[1]);
    ensure!((cmf & 0x0f) == 8 && (cmf >> 4) <= 7, "invalid zlib CMF header");
    ensure!(((cmf as u16) * 256 + (flg as u16)).is_multiple_of(31), "invalid zlib header check bits");
    ensure!((flg & 0x20) == 0, "zlib preset dictionary not supported");

    let mut bits = BitReader::new(input, 2);
    let mut out = Vec::new();
    loop {
        let bfinal = bits.read_bits(1)?;
        let btype = bits.read_bits(2)?;
        match btype {
            0 => {
                let hdr = bits.read_bytes(4)?;
                let len = u16::from_le_bytes([hdr[0], hdr[1]]);
                let nlen = u16::from_le_bytes([hdr[2], hdr[3]]);
                ensure!(len == !nlen, "corrupt uncompressed deflate block length");
                let len = len as usize;
                ensure!(
                    out.len().checked_add(len).is_some_and(|n| n <= max_output),
                    "inflated object exceeds size limit"
                );
                out.extend_from_slice(bits.read_bytes(len)?);
            }
            1 | 2 => {
                let (lit_table, dist_table) = if btype == 1 {
                    fixed_tables()?
                } else {
                    dynamic_tables(&mut bits)?
                };
                loop {
                    let sym = lit_table.decode(&mut bits)? as usize;
                    if sym < 256 {
                        ensure!(out.len() < max_output, "inflated object exceeds size limit");
                        out.push(sym as u8);
                    } else if sym == 256 {
                        break;
                    } else {
                        ensure!(sym <= 285, "invalid length symbol {sym}");
                        let len_idx = sym - 257;
                        let length = LENGTH_BASE[len_idx] + bits.read_bits(LENGTH_EXTRA[len_idx])? as usize;
                        let dist_sym = dist_table.decode(&mut bits)? as usize;
                        ensure!(dist_sym < 30, "invalid distance symbol {dist_sym}");
                        let distance = DIST_BASE[dist_sym] + bits.read_bits(DIST_EXTRA[dist_sym])? as usize;
                        ensure!(distance >= 1 && distance <= out.len(), "deflate backward distance out of bounds");
                        ensure!(
                            out.len().checked_add(length).is_some_and(|n| n <= max_output),
                            "inflated object exceeds size limit"
                        );
                        let start = out.len() - distance;
                        for i in 0..length {
                            out.push(out[start + i]);
                        }
                    }
                }
            }
            _ => bail!("invalid deflate block type {btype}"),
        }
        if bfinal == 1 {
            break;
        }
    }

    let trailer = bits.read_bytes(4)?;
    let expected_adler = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
    ensure!(adler32(&out) == expected_adler, "zlib Adler-32 checksum mismatch");
    Ok((out, bits.byte_pos))
}

fn read_delta_varint(delta: &[u8], pos: &mut usize) -> Result<usize> {
    let (mut result, mut shift) = (0usize, 0u32);
    loop {
        ensure!(*pos < delta.len(), "truncated delta size varint");
        let b = delta[*pos];
        *pos += 1;
        let part = ((b & 0x7f) as usize).checked_shl(shift).context("delta varint overflow")?;
        result = result.checked_add(part).context("delta varint overflow")?;
        if (b & 0x80) == 0 {
            return Ok(result);
        }
        shift += 7;
        ensure!(shift < usize::BITS, "delta varint shift overflow");
    }
}

/// Decodes a Git binary delta instruction stream against `base`.
pub fn apply_delta(base: &[u8], delta: &[u8], max_object_size: usize) -> Result<Vec<u8>> {
    let mut pos = 0usize;
    let base_size = read_delta_varint(delta, &mut pos)?;
    ensure!(base_size == base.len(), "delta base size mismatch: expected {base_size}, got {}", base.len());
    let target_size = read_delta_varint(delta, &mut pos)?;
    ensure!(target_size <= max_object_size, "delta target size {target_size} exceeds limit {max_object_size}");

    let mut out = Vec::with_capacity(target_size);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if (cmd & 0x80) != 0 {
            let (mut cp_off, mut cp_size) = (0usize, 0usize);
            for bit in 0..4 {
                if (cmd & (1 << bit)) != 0 {
                    ensure!(pos < delta.len(), "truncated delta copy offset");
                    cp_off |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            for bit in 0..3 {
                if (cmd & (1 << (4 + bit))) != 0 {
                    ensure!(pos < delta.len(), "truncated delta copy size");
                    cp_size |= (delta[pos] as usize) << (bit * 8);
                    pos += 1;
                }
            }
            if cp_size == 0 {
                cp_size = 0x10000;
            }
            let end_base = cp_off.checked_add(cp_size).context("delta copy offset overflow")?;
            ensure!(end_base <= base.len(), "delta copy out of base bounds");
            ensure!(
                out.len().checked_add(cp_size).is_some_and(|n| n <= target_size),
                "delta copy exceeds target size"
            );
            out.extend_from_slice(&base[cp_off..end_base]);
        } else if cmd != 0 {
            let insert_len = cmd as usize;
            let end_delta = pos.checked_add(insert_len).context("delta insert overflow")?;
            ensure!(end_delta <= delta.len(), "truncated delta literal insert");
            ensure!(
                out.len().checked_add(insert_len).is_some_and(|n| n <= target_size),
                "delta insert exceeds target size"
            );
            out.extend_from_slice(&delta[pos..end_delta]);
            pos = end_delta;
        } else {
            bail!("reserved delta opcode 0x00");
        }
    }
    ensure!(out.len() == target_size, "delta reconstructed size {} != {target_size}", out.len());
    Ok(out)
}

#[derive(Debug, Clone)]
enum RawEntryKind {
    Base(ObjectType),
    OfsDelta { base_offset: usize },
    RefDelta { base_oid: String },
}

#[derive(Debug, Clone)]
struct RawEntry {
    pack_offset: usize,
    kind: RawEntryKind,
    inflated: Vec<u8>,
}

/// Parses and validates a Git `.pack` v2 buffer in pure safe Rust, resolving all `OBJ_OFS_DELTA`
/// and `OBJ_REF_DELTA` chains and verifying pack and object digests.
pub fn verify_pack(pack_bytes: &[u8], limits: &Limits) -> Result<PackReport> {
    ensure!(pack_bytes.len() >= 32, "pack file smaller than minimum header + trailer");
    ensure!(&pack_bytes[0..4] == b"PACK", "invalid pack magic header");
    let version = u32::from_be_bytes([pack_bytes[4], pack_bytes[5], pack_bytes[6], pack_bytes[7]]);
    ensure!(version == 2, "unsupported pack version {version}");
    let object_count = u32::from_be_bytes([pack_bytes[8], pack_bytes[9], pack_bytes[10], pack_bytes[11]]) as usize;
    ensure!(object_count <= limits.max_objects, "pack object count {object_count} exceeds limit");

    let trailer_pos = pack_bytes.len() - 20;
    let computed_sha1 = sha1_digest(&pack_bytes[..trailer_pos]);
    ensure!(computed_sha1 == pack_bytes[trailer_pos..], "pack trailer SHA-1 checksum mismatch");
    let pack_sha1 = hex::encode(computed_sha1);
    let pack_sha256 = sha256_hex(pack_bytes);

    let mut pos = 12usize;
    let mut raw_entries = Vec::with_capacity(object_count);
    let mut offset_to_idx = BTreeMap::new();

    for idx in 0..object_count {
        ensure!(pos < trailer_pos, "unexpected end of pack entries");
        let entry_offset = pos;
        let first = pack_bytes[pos];
        pos += 1;
        let raw_type = (first >> 4) & 0x07;
        let mut inflated_size = (first & 0x0f) as usize;
        let mut shift = 4u32;
        let mut cont = (first & 0x80) != 0;
        while cont {
            ensure!(pos < trailer_pos, "truncated pack entry header");
            let b = pack_bytes[pos];
            pos += 1;
            let part = ((b & 0x7f) as usize).checked_shl(shift).context("pack entry size overflow")?;
            inflated_size = inflated_size.checked_add(part).context("pack entry size overflow")?;
            cont = (b & 0x80) != 0;
            shift += 7;
            ensure!(shift < usize::BITS, "pack entry size shift overflow");
        }
        ensure!(inflated_size <= limits.max_object_size, "pack entry inflated size exceeds limit");

        let kind = match raw_type {
            OBJ_COMMIT | OBJ_TREE | OBJ_BLOB | OBJ_TAG => RawEntryKind::Base(ObjectType::from_raw(raw_type)?),
            OBJ_OFS_DELTA => {
                ensure!(pos < trailer_pos, "truncated OFS_DELTA offset");
                let mut b = pack_bytes[pos];
                pos += 1;
                let mut delta_off = (b & 0x7f) as usize;
                while (b & 0x80) != 0 {
                    ensure!(pos < trailer_pos, "truncated OFS_DELTA offset");
                    b = pack_bytes[pos];
                    pos += 1;
                    delta_off = delta_off
                        .checked_add(1)
                        .and_then(|v| v.checked_shl(7))
                        .context("OFS_DELTA offset overflow")?
                        | ((b & 0x7f) as usize);
                }
                let base_offset = entry_offset.checked_sub(delta_off).context("OFS_DELTA base offset underflow")?;
                ensure!(base_offset >= 12 && base_offset < entry_offset, "invalid OFS_DELTA base offset");
                RawEntryKind::OfsDelta { base_offset }
            }
            OBJ_REF_DELTA => {
                ensure!(pos + 20 <= trailer_pos, "truncated REF_DELTA base OID");
                let base_oid = hex::encode(&pack_bytes[pos..pos + 20]);
                pos += 20;
                RawEntryKind::RefDelta { base_oid }
            }
            other => bail!("invalid pack entry type {other}"),
        };

        let (inflated, consumed) = inflate_zlib_stream(&pack_bytes[pos..trailer_pos], limits.max_object_size)?;
        ensure!(inflated.len() == inflated_size, "pack entry inflated size mismatch");
        pos += consumed;
        offset_to_idx.insert(entry_offset, idx);
        raw_entries.push(RawEntry { pack_offset: entry_offset, kind, inflated });
    }
    ensure!(pos == trailer_pos, "pack contains unconsumed trailing bytes before SHA-1 trailer");

    let mut resolved: Vec<Option<ResolvedObject>> = vec![None; object_count];
    let mut oid_to_idx: BTreeMap<String, usize> = BTreeMap::new();
    let (mut base_objects, mut delta_objects) = (0usize, 0usize);

    for (idx, entry) in raw_entries.iter().enumerate() {
        if let RawEntryKind::Base(obj_type) = entry.kind {
            let oid = git_object_oid(obj_type, &entry.inflated);
            let sha256 = sha256_hex(&entry.inflated);
            oid_to_idx.insert(oid.clone(), idx);
            resolved[idx] = Some(ResolvedObject {
                oid,
                sha256,
                obj_type,
                size: entry.inflated.len(),
                pack_offset: entry.pack_offset,
                delta_depth: 0,
                base_oid: None,
                data: entry.inflated.clone(),
            });
            base_objects += 1;
        } else {
            delta_objects += 1;
        }
    }

    fn resolve_idx(
        idx: usize,
        raw_entries: &[RawEntry],
        offset_to_idx: &BTreeMap<usize, usize>,
        oid_to_idx: &mut BTreeMap<String, usize>,
        resolved: &mut [Option<ResolvedObject>],
        visiting: &mut BTreeSet<usize>,
        limits: &Limits,
    ) -> Result<()> {
        if resolved[idx].is_some() {
            return Ok(());
        }
        ensure!(visiting.insert(idx), "cycle detected in pack delta chain at entry {idx}");
        let base_idx = match &raw_entries[idx].kind {
            RawEntryKind::Base(_) => unreachable!(),
            RawEntryKind::OfsDelta { base_offset } => *offset_to_idx
                .get(base_offset)
                .with_context(|| format!("missing OFS_DELTA base at pack offset {base_offset}"))?,
            RawEntryKind::RefDelta { base_oid } => {
                if let Some(&found) = oid_to_idx.get(base_oid) {
                    found
                } else {
                    let mut found_idx = None;
                    for candidate in 0..raw_entries.len() {
                        if candidate != idx && resolved[candidate].is_none() && !visiting.contains(&candidate) {
                            let _ = resolve_idx(candidate, raw_entries, offset_to_idx, oid_to_idx, resolved, visiting, limits);
                            if let Some(&f) = oid_to_idx.get(base_oid) {
                                found_idx = Some(f);
                                break;
                            }
                        }
                    }
                    found_idx.with_context(|| format!("unresolved REF_DELTA base {base_oid}"))?
                }
            }
        };
        resolve_idx(base_idx, raw_entries, offset_to_idx, oid_to_idx, resolved, visiting, limits)?;
        visiting.remove(&idx);

        let base_obj = resolved[base_idx].as_ref().context("base object unexpectedly unresolved")?;
        let depth = base_obj.delta_depth + 1;
        ensure!(depth <= limits.max_delta_depth, "delta chain depth {depth} exceeds limit");
        let obj_type = base_obj.obj_type;
        let base_oid = base_obj.oid.clone();
        let data = apply_delta(&base_obj.data, &raw_entries[idx].inflated, limits.max_object_size)?;
        let oid = git_object_oid(obj_type, &data);
        let sha256 = sha256_hex(&data);
        oid_to_idx.insert(oid.clone(), idx);
        resolved[idx] = Some(ResolvedObject {
            oid,
            sha256,
            obj_type,
            size: data.len(),
            pack_offset: raw_entries[idx].pack_offset,
            delta_depth: depth,
            base_oid: Some(base_oid),
            data,
        });
        Ok(())
    }

    let mut visiting = BTreeSet::new();
    for idx in 0..object_count {
        if resolved[idx].is_none() {
            resolve_idx(idx, &raw_entries, &offset_to_idx, &mut oid_to_idx, &mut resolved, &mut visiting, limits)?;
        }
    }

    let mut objects = Vec::with_capacity(object_count);
    let mut max_delta_depth_observed = 0usize;
    for item in resolved {
        let obj = item.context("unresolved pack object")?;
        max_delta_depth_observed = max_delta_depth_observed.max(obj.delta_depth);
        objects.push(obj);
    }

    Ok(PackReport {
        version,
        object_count,
        pack_sha1,
        pack_sha256,
        max_delta_depth_observed,
        delta_objects,
        base_objects,
        objects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_pack_entry_header(raw_type: u8, mut size: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut first = ((raw_type & 0x07) << 4) | ((size & 0x0f) as u8);
        size >>= 4;
        if size > 0 {
            first |= 0x80;
        }
        out.push(first);
        while size > 0 {
            let mut b = (size & 0x7f) as u8;
            size >>= 7;
            if size > 0 {
                b |= 0x80;
            }
            out.push(b);
        }
        out
    }

    fn encode_ofs_delta_offset(mut distance: usize) -> Vec<u8> {
        let mut bytes = vec![(distance & 0x7f) as u8];
        while distance > 0x7f {
            distance = (distance >> 7) - 1;
            bytes.push(((distance & 0x7f) as u8) | 0x80);
        }
        bytes.reverse();
        bytes
    }

    fn encode_delta_varint(mut n: usize, out: &mut Vec<u8>) {
        loop {
            let mut b = (n & 0x7f) as u8;
            n >>= 7;
            if n > 0 {
                b |= 0x80;
            }
            out.push(b);
            if n == 0 {
                break;
            }
        }
    }

    #[test]
    fn sha1_and_git_oid_match_known_vectors() {
        assert_eq!(hex::encode(sha1_digest(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            git_object_oid(ObjectType::Blob, b"hello world\n"),
            "3b18e512dba79e4c8300dd08aeb37f8e728b8dad"
        );
    }

    #[test]
    fn zlib_roundtrip_and_size_limit_enforcement() {
        let payload = b"synthetic pando zlib streaming test payload".repeat(40);
        let compressed = compress_zlib_stored(&payload);
        let (inflated, consumed) = inflate_zlib_stream(&compressed, payload.len()).unwrap();
        assert_eq!(inflated, payload);
        assert_eq!(consumed, compressed.len());
        assert!(inflate_zlib_stream(&compressed, payload.len() - 1).is_err());
    }

    #[test]
    fn ofs_and_ref_delta_pack_verification_and_guards() {
        let base_data = b"hello base world\n";
        let base_oid = git_object_oid(ObjectType::Blob, base_data);

        let mut delta1 = Vec::new();
        encode_delta_varint(base_data.len(), &mut delta1);
        encode_delta_varint(16, &mut delta1);
        delta1.extend_from_slice(&[0x90, 6, 10]);
        delta1.extend_from_slice(b"ofs delta\n");

        let mut delta2 = Vec::new();
        encode_delta_varint(base_data.len(), &mut delta2);
        encode_delta_varint(10, &mut delta2);
        delta2.push(10);
        delta2.extend_from_slice(b"ref delta\n");

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&3u32.to_be_bytes());

        let off0 = pack.len();
        pack.extend_from_slice(&encode_pack_entry_header(OBJ_BLOB, base_data.len()));
        pack.extend_from_slice(&compress_zlib_stored(base_data));

        let off1 = pack.len();
        pack.extend_from_slice(&encode_pack_entry_header(OBJ_OFS_DELTA, delta1.len()));
        pack.extend_from_slice(&encode_ofs_delta_offset(off1 - off0));
        pack.extend_from_slice(&compress_zlib_stored(&delta1));

        pack.extend_from_slice(&encode_pack_entry_header(OBJ_REF_DELTA, delta2.len()));
        pack.extend_from_slice(&hex::decode(&base_oid).unwrap());
        pack.extend_from_slice(&compress_zlib_stored(&delta2));

        let trailer = sha1_digest(&pack);
        pack.extend_from_slice(&trailer);

        let report = verify_pack(&pack, &Limits::default()).unwrap();
        assert_eq!(report.object_count, 3);
        assert_eq!(report.objects[1].data, b"hello ofs delta\n");
        assert_eq!(report.objects[2].data, b"ref delta\n");
        assert!(verify_pack(&pack, &Limits { max_delta_depth: 0, ..Limits::default() }).is_err());
        assert!(verify_pack(&pack, &Limits { max_object_size: 8, ..Limits::default() }).is_err());
    }
}
