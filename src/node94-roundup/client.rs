use std::io::{self, BufRead};
use node94_roundup::quotient;

fn main() {
    for line in io::stdin().lock().lines() {
        let line = line.expect("input read");
        let fields: Vec<_> = line.split('\t').collect();
        assert_eq!(fields.len(), 3, "Only case id and inputs are accepted");
        let result = quotient(fields[1].parse().expect("u32 field"), fields[2].parse().expect("u64 x"));
        match result {
            Some(value) => println!("{}\t{}", fields[0], value),
            None => println!("{}\tfault", fields[0]),
        }
    }
}
