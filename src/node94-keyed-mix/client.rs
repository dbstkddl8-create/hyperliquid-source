//! Separately linked own Rust; stdin contains stimuli only, never answers.
use node94_keyed_mix::keyed_mix;
use std::io::{self, Read};

fn main() {
    let mut text = String::new();
    io::stdin().read_to_string(&mut text).unwrap();
    for row in text.lines() {
        let fields: Vec<_> = row.split_whitespace().collect();
        assert_eq!(fields.len(), 9);
        let mut block = [0; 20];
        for index in 0..5 {
            let value = u32::from_str_radix(fields[index + 1], 16).unwrap();
            block[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
        }
        let seed = u64::from_str_radix(fields[6], 16).unwrap();
        let keys = [u64::from_str_radix(fields[7], 16).unwrap(),
                    u64::from_str_radix(fields[8], 16).unwrap()];
        println!("{}\t{:016x}", fields[0], keyed_mix(block, seed, keys));
    }
}
