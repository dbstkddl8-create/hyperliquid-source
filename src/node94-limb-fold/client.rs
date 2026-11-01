//! Separately linked own-Rust client: receives stimuli, never expected outputs.
use node94_limb_fold::fold_high_bits;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for row in text.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 6);
        let mut input = [0; 5];
        for index in 0..5 {
            input[index] = u64::from_str_radix(fields[index + 1], 16).unwrap();
        }
        let output = fold_high_bits(input);
        println!("{}\t{:016x}\t{:016x}\t{:016x}\t{:016x}\t{:016x}",
                 fields[0], output[0], output[1], output[2], output[3], output[4]);
    }
}
