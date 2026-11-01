use std::cell::Cell;
use node94_format_request_protocol::{request, Context, Input, Requests, Row, Writer, DEFAULT_OPTIONS};

struct Environment<'a> { method: &'a Cell<u64>, calls: Vec<(u64, u64, Vec<u8>)>, values: Vec<(u64, u64, Context)> }
impl Requests for Environment<'_> {
    fn write(&mut self, method: u64, destination: u64, bytes: &[u8]) -> u8 {
        self.calls.push((method, destination, bytes.to_vec())); self.method.set(900); 0
    }
    fn value(&mut self, data: u64, second: u64, context: &mut Context) -> u8 {
        self.values.push((data, second, *context));
        *context = Context { destination: 999, table: 2, options: 0, first: 88, second: 99 };
        0
    }
}
#[test]
fn native_extended_empty_literal_and_cached_method() {
    let method = Cell::new(101);
    let mut env = Environment { method: &method, calls: Vec::new(), values: Vec::new() };
    let input = [128, 0, 0, 1, b'x', 0];
    assert_eq!(request(Input::Encoded(&input), Writer { destination: 11, table: 1, method: &method }, &[], &mut env), Ok(0));
    assert_eq!(env.calls, vec![(101, 11, vec![]), (101, 11, vec![b'x'])]);
}
#[test]
fn native_paired_second_word_quantities_rebase_and_full_reset() {
    let method = Cell::new(101);
    let rows: Vec<_> = (0..5).map(|i| Row::new(100 + i, 0x1234_0000 + 20 + i)).collect();
    let mut env = Environment { method: &method, calls: Vec::new(), values: Vec::new() };
    // low6=0x3e: q0=1,q1=2,index=3, both quantities indirect; then implicit.
    let input = [0xbe, 1, 0, 2, 0, 3, 0, 192, 0];
    assert_eq!(request(Input::Encoded(&input), Writer { destination: 11, table: 1, method: &method }, &rows, &mut env), Ok(0));
    assert_eq!(env.values[0], (103, 0x1234_0017, Context { destination: 11, table: 1, options: DEFAULT_OPTIONS, first: 21, second: 22 }));
    assert_eq!(env.values[1], (104, 0x1234_0018, Context { destination: 11, table: 1, options: DEFAULT_OPTIONS, first: 0, second: 0 }));
    assert_eq!(std::mem::size_of::<Context>(), 24);
}
#[test]
fn native_direct_raw_reply_and_compact_canonical_reply() {
    struct Replies;
    impl Requests for Replies {
        fn write(&mut self, _: u64, _: u64, _: &[u8]) -> u8 { 255 }
        fn value(&mut self, _: u64, _: u64, _: &mut Context) -> u8 { 128 }
    }
    let method = Cell::new(101);
    let writer = || Writer { destination: 11, table: 1, method: &method };
    assert_eq!(request(Input::Direct(&[]), writer(), &[], &mut Replies), Ok(255));
    assert_eq!(request(Input::Encoded(&[1, b'a', 255]), writer(), &[], &mut Replies), Ok(1));
    assert_eq!(request(Input::Encoded(&[192, 255]), writer(), &[Row::new(1, 2)], &mut Replies), Ok(1));
    assert_eq!(request(Input::Encoded(&[0, 255]), writer(), &[], &mut Replies), Ok(0));
}
