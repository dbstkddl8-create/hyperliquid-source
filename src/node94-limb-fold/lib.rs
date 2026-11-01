#![no_std]
#![forbid(unsafe_code)]

const COEFFICIENT: u64 = 0x1_0000_03d1;
const MASK52: u64 = (1 << 52) - 1;
const MASK48: u64 = (1 << 48) - 1;

/// Numeric projection of node94 ELF VA 0x56327f0..0x563286b.
///
/// All five input words may use their complete u64 domain. Each addition's
/// bit 64 is discarded before extracting its 12-bit carry. This deliberately
/// does not substitute an unbounded base-2^52 integer reduction.
///
/// This independently chosen safe value API is not the original pointer ABI,
/// in-place write order, physical register contract or returned base pointer.
#[inline(never)]
pub fn fold_high_bits(input: [u64; 5]) -> [u64; 5] {
    // The upper 16 bits times this 33-bit coefficient fit within 48 bits.
    let mut carry = (input[4] >> 48) * COEFFICIENT;
    let mut output = [0; 5];
    for index in 0..4 {
        let wide = u128::from(input[index]) + u128::from(carry);
        let wrapped = wide as u64;
        output[index] = wrapped & MASK52;
        carry = wrapped >> 52;
    }
    // A 48-bit value plus a 12-bit carry fits in 49 bits, without wrapping.
    output[4] = (input[4] & MASK48) + carry;
    output
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::fold_high_bits;
    use std::vec::Vec;

    #[test]
    fn frozen_pre_rust_static_contract_cases() {
        let mut count = 0;
        for row in include_str!("target-vectors.tsv").lines() {
            let fields: Vec<_> = row.split('\t').collect();
            assert_eq!(fields.len(), 11);
            let mut input = [0; 5];
            let mut expected = [0; 5];
            for index in 0..5 {
                input[index] = u64::from_str_radix(fields[index + 1], 16).unwrap();
                expected[index] = u64::from_str_radix(fields[index + 6], 16).unwrap();
            }
            assert_eq!(fold_high_bits(input), expected, "case {}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 1331);
    }
}
