//! Separately linked client: synthetic inputs only, no expected answers.
use node94_mix_div61::mix_div61;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for row in text.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 3);
        let state = u64::from_str_radix(fields[1], 16).unwrap();
        let field = u32::from_str_radix(fields[2], 16).unwrap() as i32;
        let (updated, stored, returned) = mix_div61(state, field);
        println!("{}\t{:016x}\t{:016x}\t{:016x}", fields[0], updated, stored, returned);
    }
}
