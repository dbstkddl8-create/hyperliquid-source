//! ASCII acceptance/payload projection, not the original address parser ABI.
#![no_std]
#![forbid(unsafe_code)]

/// This research API leaves non-ASCII behavior unqualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutsideAsciiDomain;

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Project qualified ASCII input to the observed successful twenty bytes.
///
/// Only lowercase `0x` is a prefix. Additional leading zero bytes are allowed;
/// the final forty bytes must all be hexadecimal, without whitespace. `None`
/// represents the observed rejection path assuming ordinary error-helper
/// returns. No allocated error, display, Unicode or original object layout is
/// recovered. Non-ASCII input is outside this API's qualified domain.
pub fn parse_ascii_address(input: &[u8]) -> Result<Option<[u8; 20]>, OutsideAsciiDomain> {
    if !input.is_ascii() {
        return Err(OutsideAsciiDomain);
    }
    let body = input.strip_prefix(b"0x").unwrap_or(input);
    let Some((padding, tail)) = body.split_last_chunk::<40>() else {
        return Ok(None);
    };
    if padding.iter().any(|&byte| byte != b'0') {
        return Ok(None);
    }
    let mut output = [0; 20];
    for (slot, pair) in output.iter_mut().zip(tail.chunks_exact(2)) {
        let (Some(high), Some(low)) = (digit(pair[0]), digit(pair[1])) else {
            return Ok(None);
        };
        *slot = (high << 4) | low;
    }
    Ok(Some(output))
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use super::{parse_ascii_address, OutsideAsciiDomain};
    use std::vec::Vec;

    fn bytes(text: &str) -> Vec<u8> {
        if text == "-" {
            return Vec::new();
        }
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn pre_implementation_target_grounded_smoke_cases() {
        let mut count = 0;
        for line in include_str!("target-smoke.tsv").lines() {
            let (input, expected) = line.split_once('\t').unwrap();
            let actual = parse_ascii_address(&bytes(input));
            match expected {
                "outside" => assert_eq!(actual, Err(OutsideAsciiDomain)),
                "reject" => assert_eq!(actual, Ok(None)),
                value => {
                    let expected: [u8; 20] = bytes(value).try_into().unwrap();
                    assert_eq!(actual, Ok(Some(expected)));
                }
            }
            count += 1;
        }
        assert_eq!(count, 14);
    }
}
