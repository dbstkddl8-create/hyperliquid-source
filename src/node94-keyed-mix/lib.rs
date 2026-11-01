//! Safe numeric projection of node94 VA 0x399c600; not its native pointer ABI.
#![no_std]
#![forbid(unsafe_code)]

#[inline(never)]
pub fn keyed_mix(block: [u8; 20], seed: u64, keys: [u64; 2]) -> u64 {
    let word = |offset: usize| u64::from_le_bytes([
        block[offset], block[offset + 1], block[offset + 2], block[offset + 3],
        block[offset + 4], block[offset + 5], block[offset + 6], block[offset + 7],
    ]);
    let first = u128::from(word(12) ^ keys[0]) * u128::from(word(8) ^ keys[1]);
    let second = u128::from(word(4) ^ keys[0]) * u128::from(word(0) ^ seed);
    let folded = first as u64 ^ (first >> 64) as u64
        ^ second as u64 ^ (second >> 64) as u64 ^ 0x14;
    let final_product = u128::from(folded) * u128::from(keys[0]);
    final_product as u64 ^ (final_product >> 64) as u64
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::keyed_mix;
    use std::vec::Vec;

    #[test]
    fn frozen_pre_rust_byte_windows_and_products() {
        let mut count = 0;
        for row in include_str!("target-vectors.tsv").lines() {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 10);
            let mut block = [0; 20];
            for index in 0..5 {
                let word = u32::from_str_radix(fields[index + 1], 16).unwrap();
                block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
            }
            let seed = u64::from_str_radix(fields[6], 16).unwrap();
            let keys = [u64::from_str_radix(fields[7], 16).unwrap(),
                        u64::from_str_radix(fields[8], 16).unwrap()];
            let expected = u64::from_str_radix(fields[9], 16).unwrap();
            assert_eq!(keyed_mix(block, seed, keys), expected, "case {}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 1844);
    }
}
