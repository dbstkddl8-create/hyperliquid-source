use hl_bincode_varint::{PayloadOrder, ReaderError, read_u32, read_u64};

fn bytes(text: &str) -> Vec<u8> {
    if text == "-" { return Vec::new(); }
    (0..text.len()).step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at+2], 16).unwrap()).collect()
}

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".to_owned(); }
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn authenticated_reader_values_errors_and_remaining_suffixes() {
    let inputs = include_str!("../../../research/work-items/RE-005-bincode-reader-rust-94/target-inputs.tsv");
    let expected = include_str!("../../../research/work-items/RE-005-bincode-reader-rust-94/target-vectors.tsv");
    assert_eq!(inputs.lines().count(), 3276);
    assert_eq!(expected.lines().count(), 3276);
    for (line, wanted) in inputs.lines().zip(expected.lines()) {
        let f: Vec<_> = line.split_whitespace().collect();
        let original = bytes(f[3]);
        let mut input = original.as_slice();
        let order = if f[2] == "0" { PayloadOrder::Little } else { PayloadOrder::Big };
        let result = if f[1] == "32" { read_u32(&mut input, order).map(u64::from) }
                     else { read_u64(&mut input, order) };
        let status = match result {
            Ok(n) => format!("ok\t{n}"),
            Err(ReaderError::UnexpectedEnd { needed }) => format!("end\t{needed}"),
            Err(ReaderError::InvalidIntegerType { expected_code, found_code }) =>
                format!("type\t{expected_code}:{found_code}"),
        };
        assert_eq!(format!("{}\t{}\t{}\t{}", f[0], status, original.len()-input.len(), hex(input)), wanted);
    }
}

#[test]
fn short_payload_consumes_marker_but_not_the_available_payload() {
    let mut input: &[u8] = &[0xfb, 0x34];
    assert_eq!(read_u32(&mut input, PayloadOrder::Little), Err(ReaderError::UnexpectedEnd { needed: 1 }));
    assert_eq!(input, &[0x34]);
    assert_eq!(read_u64(&mut input, PayloadOrder::Little), Ok(0x34));
    assert!(input.is_empty());
}
