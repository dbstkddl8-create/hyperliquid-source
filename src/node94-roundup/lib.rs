//! Value projection of node94 VA 0x4f9ee90 and its field-plus-one getter.
//! No pointer ABI or native exception behavior is implemented.
#![no_std]
#![forbid(unsafe_code)]

/// Return the native quotient value, or None for the zero-divisor input.
/// The ADD carry is discarded: this is not mathematical ceiling division
/// when x + field overflows u64. None classifies #DE; it does not emulate it.
#[inline(never)]
pub fn quotient(field: u32, x: u64) -> Option<u64> {
    let divisor = field.wrapping_add(1) as u64;
    if divisor == 0 {
        return None;
    }
    let numerator = x.wrapping_add(field as u64);
    Some(numerator / divisor)
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::quotient;
    #[test]
    fn frozen_static_vectors() {
        for row in include_str!("target-vectors.tsv").lines() {
            let parts: std::vec::Vec<_> = row.split('\t').collect();
            let expected = if parts[3] == "fault" { None } else { Some(parts[3].parse().unwrap()) };
            assert_eq!(quotient(parts[1].parse().unwrap(), parts[2].parse().unwrap()), expected, "case {}", parts[0]);
        }
    }
}
