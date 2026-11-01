#![no_std]
#![forbid(unsafe_code)]
//! Independently authored normal-callback projection of node94's formatter.
//! Opaque identities and supplied callbacks are not the original private ABI.

use core::cell::Cell;

pub const DEFAULT_OPTIONS: u32 = 0x6000_0020;

/// Live logical words of one native 16-byte paired descriptor row.
/// The second word is both a callback identity and a low16 quantity source.
pub struct Row {
    pub data: Cell<u64>,
    pub second: Cell<u64>,
}

impl Row {
    pub const fn new(data: u64, second: u64) -> Self {
        Self { data: Cell::new(data), second: Cell::new(second) }
    }
}

/// Entry words remain opaque. Only the supplied method cell is live.
pub struct Writer<'a> {
    pub destination: u64,
    pub table: u64,
    pub method: &'a Cell<u64>,
}

/// A chosen safe 24-byte context, reset in full before every value callback.
/// Its C layout does not identify an original nominal type or calling ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Context {
    pub destination: u64,
    pub table: u64,
    pub options: u32,
    pub first: u16,
    pub second: u16,
}

pub enum Input<'a> {
    /// Corresponds to an odd fourth word, with logical length word >> 1.
    Direct(&'a [u8]),
    /// Immutable compact stream; paired row words remain live across callbacks.
    Encoded(&'a [u8]),
}

/// These are chosen safe refusals, never recovered native error results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    Truncated,
    MissingRow(usize),
}

/// Real supplied environment. There is no default renderer or sticky error.
/// A value callback can use its current context to make further writer calls.
pub trait Requests {
    fn write(&mut self, method: u64, destination: u64, bytes: &[u8]) -> u8;
    fn value(&mut self, data: u64, second: u64, context: &mut Context) -> u8;
}

struct Stream<'a> {
    remaining: &'a [u8],
}

impl<'a> Stream<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Refusal> {
        let bytes = self.remaining.get(..count).ok_or(Refusal::Truncated)?;
        self.remaining = &self.remaining[count..];
        Ok(bytes)
    }

    fn byte(&mut self) -> Result<u8, Refusal> { Ok(self.take(1)?[0]) }

    fn short(&mut self) -> Result<u16, Refusal> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn word(&mut self) -> Result<u32, Refusal> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

fn row(rows: &[Row], index: usize) -> Result<&Row, Refusal> {
    rows.get(index).ok_or(Refusal::MissingRow(index))
}

/// Implement the complete finite, qualified normal request relation.
///
/// References/stream allocations remain valid, roles are separated and all
/// supplied callbacks return normally. Stream/control/frame corruption,
/// concurrency, faults and unwind behavior are outside this projection.
/// Refusals are lazy: an earlier callback error or terminator can hide a bad
/// tail. Safe checks do not establish native malformed-input behavior.
pub fn request<R: Requests + ?Sized>(
    input: Input<'_>, writer: Writer<'_>, rows: &[Row], requests: &mut R,
) -> Result<u8, Refusal> {
    let bytes = match input {
        Input::Direct(bytes) => {
            // The native direct tail preserves the callback's raw low AL.
            return Ok(requests.write(writer.method.get(), writer.destination, bytes));
        }
        Input::Encoded(bytes) => bytes,
    };
    let mut stream = Stream { remaining: bytes };
    let mut tag = stream.byte()?;
    if tag == 0 { return Ok(0); }
    let cached_method = writer.method.get();
    let mut next_index = 0usize;

    loop {
        if tag < 128 {
            let literal = stream.take(usize::from(tag))?;
            if requests.write(cached_method, writer.destination, literal) != 0 { return Ok(1); }
        } else if tag == 128 {
            let length = usize::from(stream.short()?);
            let literal = stream.take(length)?;
            // Even an extended zero-length literal makes one writer request.
            if requests.write(cached_method, writer.destination, literal) != 0 { return Ok(1); }
        } else {
            let (options, mut first, mut second, index) = if tag == 192 {
                (DEFAULT_OPTIONS, 0, 0, next_index)
            } else {
                let options = if tag & 1 != 0 { stream.word()? } else { DEFAULT_OPTIONS };
                let first = if tag & 2 != 0 { stream.short()? } else { 0 };
                let second = if tag & 4 != 0 { stream.short()? } else { 0 };
                let index = if tag & 8 != 0 { usize::from(stream.short()?) } else { next_index };
                (options, first, second, index)
            };
            if tag != 192 && tag & 16 != 0 {
                first = row(rows, usize::from(first))?.second.get() as u16;
            }
            if tag != 192 && tag & 32 != 0 {
                second = row(rows, usize::from(second))?.second.get() as u16;
            }
            let selected = row(rows, index)?;
            let mut context = Context {
                destination: writer.destination, table: writer.table,
                options, first, second,
            };
            if requests.value(selected.data.get(), selected.second.get(), &mut context) != 0 {
                return Ok(1);
            }
            // An explicit index rebases the following implicit selection too.
            next_index = index.wrapping_add(1);
        }
        tag = stream.byte()?;
        if tag == 0 { return Ok(0); }
    }
}
