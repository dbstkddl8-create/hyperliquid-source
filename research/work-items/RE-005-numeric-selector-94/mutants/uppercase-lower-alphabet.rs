#![no_std]
#![forbid(unsafe_code)]
//! Independent safe request projection of node94 VA 0x14f7660..0x14f774b.

use node94_integer_digit_span::write_decimal_suffix;

/// Arguments exposed by the chosen safe interface to the opaque sink.
///
/// `start` and `end` are observation metadata relative to the supplied buffer;
/// the native call instead supplies a digit pointer and length. Neither this
/// structure nor the function below claims the original ABI or pointer values.
pub struct Request<'a> {
    pub raw_sign: u8,
    pub prefix: &'static [u8],
    pub digits: &'a [u8],
    pub start: usize,
    pub end: usize,
}

/// Select unsigned decimal/lower hex/upper hex and make one opaque request.
///
/// Only the low DWORD of `flags` participates. Bit25 selects lower hex before
/// bit26 can select upper hex. Hex digits end at buffer offset16; decimal digits
/// end at20. Zero always has one digit. Both hex modes request prefix `0x`;
/// decimal requests an empty slice. All unwritten buffer bytes are preserved.
///
/// The supplied sink receives the same borrowed context exactly once and its
/// raw u8 result is returned unchanged. This initialized-array, separate-flags,
/// generic-context API is chosen for safe execution of the established argument
/// projection. It does not implement the opaque sink, rendering or native ABI.
pub fn request_unsigned<C, F>(
    value: u64,
    flags: u64,
    buffer: &mut [u8; 20],
    context: &mut C,
    sink: F,
) -> u8
where
    F: FnOnce(&mut C, Request<'_>) -> u8,
{
    const LOWER: u32 = 1 << 25;
    const UPPER: u32 = 1 << 26;
    let selection = flags as u32;
    let alphabet = if selection & LOWER != 0 {
        Some(b"0123456789abcdef")
    } else if selection & UPPER != 0 {
        Some(b"0123456789abcdef")
    } else {
        None
    };
    let (start, end, prefix): (usize, usize, &'static [u8]) = if let Some(alphabet) = alphabet {
        let mut remaining = value;
        let mut start = 16;
        loop {
            start -= 1;
            buffer[start] = alphabet[(remaining % 16) as usize];
            remaining /= 16;
            if remaining == 0 {
                break;
            }
        }
        (start, 16, b"0x")
    } else {
        (write_decimal_suffix(value, buffer), 20, b"")
    };
    let status = sink(
        context,
        Request {
            raw_sign: 1,
            prefix,
            digits: &buffer[start..end],
            start,
            end,
        },
    );
    status
}

#[cfg(test)]
mod tests {
    use super::request_unsigned;

    fn bytes<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), 2 * N);
        let mut out = [0; N];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn independently_frozen_complete_request_vectors() {
        let inputs = include_str!(concat!(env!("NODE94_SELECTOR_FIXTURES"), "/inputs.tsv"));
        let answers = include_str!(concat!(env!("NODE94_SELECTOR_FIXTURES"), "/expected.tsv"));
        assert_eq!(inputs.lines().count(), 8892);
        assert_eq!(answers.lines().count(), 8892);
        for (given, wanted) in inputs.lines().zip(answers.lines()) {
            let mut i = given.split('\t');
            let mut e = wanted.split('\t');
            let id = i.next().unwrap();
            assert_eq!(e.next().unwrap(), id);
            let value = i.next().unwrap().parse::<u64>().unwrap();
            let flags = i.next().unwrap().parse::<u64>().unwrap();
            let mut buffer = bytes::<20>(i.next().unwrap());
            let mut context = i.next().unwrap().parse::<u64>().unwrap();
            let status = i.next().unwrap().parse::<u8>().unwrap();
            assert!(i.next().is_none());
            let start = e.next().unwrap().parse::<usize>().unwrap();
            let end = e.next().unwrap().parse::<usize>().unwrap();
            let final_buffer = bytes::<20>(e.next().unwrap());
            let prefix = e.next().unwrap();
            let sign = e.next().unwrap().parse::<u8>().unwrap();
            let wanted_context = e.next().unwrap().parse::<u64>().unwrap();
            let wanted_calls = e.next().unwrap().parse::<usize>().unwrap();
            let wanted_status = e.next().unwrap().parse::<u8>().unwrap();
            let digits = e.next().unwrap();
            assert!(e.next().is_none());
            let mut calls = 0;
            let actual_status = request_unsigned(value, flags, &mut buffer, &mut context, |c, r| {
                calls += 1;
                assert_eq!(*c, wanted_context, "context for {id}");
                assert_eq!((r.start, r.end), (start, end), "span for {id}");
                assert_eq!(r.raw_sign, sign, "sign for {id}");
                assert_eq!(r.prefix, if prefix == "-" { &b""[..] } else { &b"0x"[..] }, "prefix for {id}");
                assert_eq!(r.digits, &final_buffer[start..end], "digits for {id}");
                assert_eq!(digits.len(), 2 * r.digits.len());
                for (j, byte) in r.digits.iter().enumerate() {
                    assert_eq!(*byte, u8::from_str_radix(&digits[2*j..2*j+2], 16).unwrap());
                }
                status
            });
            assert_eq!(buffer, final_buffer, "all20 bytes for {id}");
            assert_eq!(calls, wanted_calls, "call count for {id}");
            assert_eq!(context, wanted_context, "final context for {id}");
            assert_eq!(actual_status, wanted_status, "raw status for {id}");
        }
    }

    #[test]
    fn same_borrowed_context_is_mutable_and_sink_runs_once() {
        struct Context { value: u64, calls: usize }
        for flags in [0, 1 << 25, 1 << 26, (1 << 25) | (1 << 26)] {
            let mut context = Context { value: 0xfeedbeef, calls: 0 };
            let original = &context as *const Context;
            let mut buffer = [0xa5; 20];
            let status = request_unsigned(u64::MAX, flags, &mut buffer, &mut context, |c, _| {
                assert!(core::ptr::eq(original, c as *const Context));
                c.value ^= 0x12345678;
                c.calls += 1;
                0xd3
            });
            assert_eq!(context.value, 0xfeedbeef ^ 0x12345678);
            assert_eq!(context.calls, 1);
            assert_eq!(status, 0xd3);
        }
    }
}
