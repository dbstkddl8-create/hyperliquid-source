#!/usr/bin/env python3
"""Check the finite byte-subtraction lemma; this is not an instruction evaluator."""
import argparse
import json
from pathlib import Path
from survey import Image, InvalidEvidence, json_bytes, require


def check(binary):
    image = Image(Path(binary).read_bytes())
    high = int.from_bytes(image.at(0x2bf18e, 8), 'little')
    sub = int.from_bytes(image.at(0x2bf198, 8), 'little')
    require(high == 0x8080808080808080, 'Unexpected high-bit mask')
    require(sub == 0x0101010101010100, 'Unexpected subtraction constant')
    count = 0
    # The low byte has minuend 0 and no incoming borrow. Before the
    # first zero, every higher byte has minuend 1 and incoming borrow 1.
    # These are mathematical base-256 digit states, not x86 register states.
    for minuend, incoming_borrow in [(0, 0), (1, 1)]:
        for byte in range(256):
            difference = minuend - byte - incoming_borrow
            digit = difference % 256
            outgoing_borrow = int(difference < 0)
            high_bit = ((digit | byte) >> 7) & 1
            require(high_bit == int(byte != 0), 'Byte high-bit lemma failed')
            require(outgoing_borrow == int(byte != 0), 'Borrow induction failed')
            count += 1
    # A wrong low constant must not accidentally satisfy the same theorem.
    all_ones = 0x0101010101010101
    mask64 = (1 << 64) - 1
    good = (((sub - all_ones) & mask64) | all_ones) & high
    wrong = ((((sub + 1) - all_ones) & mask64) | all_ones) & high
    require(good == high and wrong != high, 'Constant mutation witness failed')
    return {
        'schema': 'visor-nul-byte-lemma-1',
        'targetSha256': '89338207c793d80ac2fba75bb0d36c659e2cabc87a94e61a57ba532b8d212e31',
        'highMask': hex(high), 'subtractConstant': hex(sub),
        'checkedDigitTransitions': count,
        'states': [{'minuend': 0, 'incomingBorrow': 0},
                   {'minuend': 1, 'incomingBorrow': 1}],
        'constantMutation': {'wrongConstant': hex(sub + 1),
                             'allNonzeroWord': hex(all_ones),
                             'correctMask': hex(good), 'wrongMask': hex(wrong)},
        'scope': 'Finite base-256 algebra lemma. The 64-bit induction, two-word conjunction and first-index control-flow argument are manual in PROOF.md. No x86 instruction evaluation, target callback or runtime behavior test.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--receipt', type=Path)
    args = parser.parse_args()
    try:
        if args.receipt:
            require(not args.receipt.exists(), 'Preserve existing receipt')
        result = check(args.binary)
        if args.receipt:
            with args.receipt.open('xb') as stream:
                stream.write(json_bytes(result))
        print(json.dumps(result))
    except (InvalidEvidence, OSError, UnicodeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
