//! Separately linked own-Rust client receives only stimuli, never answers.
use node94_wide_subtract::subtract_words;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for row in text.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 9);
        let mut left = [0; 4];
        let mut right = [0; 4];
        for index in 0..4 {
            left[index] = u64::from_str_radix(fields[index + 1], 16).unwrap();
            right[index] = u64::from_str_radix(fields[index + 5], 16).unwrap();
        }
        let (output, borrow) = subtract_words(left, right);
        println!("{}\t{:016x}\t{:016x}\t{:016x}\t{:016x}\t{:016x}",
                 fields[0], output[0], output[1], output[2], output[3], u64::from(borrow));
    }
}
