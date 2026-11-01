//! Numeric projection of node94 VA 0x5553fe0, excluding native pointer aliasing.
#![no_std]
#![forbid(unsafe_code)]

// Data extracted from the authenticated target's .rodata at VA 0x801180.
const TABLE: [u8; 64] = *b"\xfe\xd3\xbb\xa9\x9c\x90\x87\x7f\x78\x71\x6b\x66\x61\x5d\x59\x55\x51\x4d\x4a\x47\x44\x41\x3e\x3c\x39\x37\x35\x32\x30\x2e\x2c\x2a\x28\x27\x25\x23\x21\x20\x1e\x1d\x1b\x1a\x18\x17\x15\x14\x13\x12\x10\x0f\x0e\x0d\x0c\x0a\x09\x08\x07\x06\x05\x04\x03\x02\x01\x00";

#[inline(never)]
pub fn mix_div61(state: u64, field: i32) -> (u64, u32, u32) {
    let updated = state.wrapping_mul(0x5851f42d4c957f2d).wrapping_add(0x14057b7ef767814f);
    let table_byte = u64::from(TABLE[(updated >> 58) as usize]);
    let product = table_byte.wrapping_mul(field as i64 as u64);
    (updated, (product / 61) as u32, 1)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::mix_div61;
    use std::vec::Vec;

    #[test]
    fn frozen_pre_rust_table_buckets_and_signed_fields() {
        let mut count = 0;
        for row in include_str!("target-vectors.tsv").lines() {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 6);
            let state = u64::from_str_radix(fields[1], 16).unwrap();
            let field = u32::from_str_radix(fields[2], 16).unwrap() as i32;
            let expected = (u64::from_str_radix(fields[3], 16).unwrap(),
                            u32::from_str_radix(fields[4], 16).unwrap(),
                            u32::from_str_radix(fields[5], 16).unwrap());
            assert_eq!(mix_div61(state, field), expected, "case {}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 3136);
    }
}
