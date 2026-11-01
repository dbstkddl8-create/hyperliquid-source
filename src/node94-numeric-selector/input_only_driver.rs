#![forbid(unsafe_code)]
use node94_numeric_selector::request_unsigned;
use std::io::{self, Write};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2, "one input-only TSV path is required");
    let inputs = std::fs::read_to_string(&args[1]).unwrap();
    let mut out = io::BufWriter::new(io::stdout().lock());
    for line in inputs.lines() {
        let mut fields = line.split('\t');
        let id = fields.next().unwrap();
        let value = fields.next().unwrap().parse::<u64>().unwrap();
        let flags = fields.next().unwrap().parse::<u64>().unwrap();
        let initial = fields.next().unwrap();
        assert_eq!(initial.len(), 40);
        let mut buffer = [0; 20];
        for (i, b) in buffer.iter_mut().enumerate() {
            *b = u8::from_str_radix(&initial[2*i..2*i+2], 16).unwrap();
        }
        let mut context = fields.next().unwrap().parse::<u64>().unwrap();
        let callback_status = fields.next().unwrap().parse::<u8>().unwrap();
        assert!(fields.next().is_none());
        let mut calls = 0;
        let mut observed = (20, 20, String::new(), 0, context, String::new());
        let status = request_unsigned(value, flags, &mut buffer, &mut context, |c, request| {
            calls += 1;
            observed = (request.start, request.end, hex(request.prefix), request.raw_sign, *c, hex(request.digits));
            callback_status
        });
        let (start, end, prefix, sign, passed_context, digits) = observed;
        writeln!(out, "{id}\t{start}\t{end}\t{}\t{}\t{sign}\t{passed_context}\t{calls}\t{status}\t{}",
                 hex(&buffer), if prefix.is_empty() { "-" } else { &prefix },
                 if digits.is_empty() { "-" } else { &digits }).unwrap();
    }
}
