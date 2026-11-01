#![no_std]
#![forbid(unsafe_code)]

use core::num::NonZeroU128;

/// Remainder on the complete nonzero-divisor unsigned numerical domain.
///
/// The bit-prefix algorithm is independently chosen. The native leaf's
/// ordinary-return theorem establishes the value rule, without recovering
/// its original ABI, physical clobbers or zero-divisor exception behavior.
#[inline(never)]
pub fn remainder(dividend: u128, divisor: NonZeroU128) -> u128 {
    let divisor = divisor.get();
    let mut residue = 0_u128;
    let mut bit = 128_usize;
    while bit != 0 {
        bit -= 1;
        residue = (residue << 1) | ((dividend >> bit) & 1);
        if residue >= divisor {
            residue -= divisor;
        }
    }
    residue
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::remainder;
    use core::num::NonZeroU128;
    use std::vec::Vec;

    #[test]
    fn frozen_independent_boundary_cases() {
        let mut count = 0;
        for line in include_str!("unit-vectors.tsv").lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            assert_eq!(fields.len(), 4);
            let dividend = u128::from_str_radix(fields[1], 16).unwrap();
            let divisor = NonZeroU128::new(u128::from_str_radix(fields[2], 16).unwrap()).unwrap();
            let expected = u128::from_str_radix(fields[3], 16).unwrap();
            assert_eq!(remainder(dividend, divisor), expected, "{}", fields[0]);
            count += 1;
        }
        assert_eq!(count, 13);
    }
}
