//! Pure value/note-request projection of the established Decimal conversion.
//! Original input/output Rust types and the opaque note helper are not recovered.

const MANTISSA_LIMIT: u128 = 1 << 96;
const CAP: u128 = 9_223_372_036_854_775_806;

/// Own representation of the normal-return scalar outcome, not a target ABI.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ScaledDecimalOutcome {
    /// `None` projects the observed rejection tag without assigning its type.
    pub value: Option<u64>,
    /// Whether the native path requests its opaque note callback.
    /// No callback or equivalent external side effect is performed here.
    pub note_requested: bool,
}

impl ScaledDecimalOutcome {
    fn rejected(note_requested: bool) -> Self {
        Self {
            value: None,
            note_requested,
        }
    }
}

/// Parts outside the qualified 96-bit mantissa / scale-0-through-28 domain.
/// Refusal is this research API's policy, not a target error-layout claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnsupportedDecimalParts;

/// Convert qualified Decimal parts using the captured mode and exponent bytes.
///
/// Mode zero is exact; mode one snaps only at distance strictly below 0.001;
/// all other modes round halfway cases to even. Exponents above 19, remaining
/// fractions, nonzero negative results and values above 2^63-2 are rejected.
/// The note flag assumes the opaque native callback returns normally.
pub fn decimal_to_scaled_u64(
    negative: bool,
    mantissa: u128,
    scale: u8,
    mode: u8,
    exponent: u8,
) -> Result<ScaledDecimalOutcome, UnsupportedDecimalParts> {
    if mantissa >= MANTISSA_LIMIT || scale > 28 {
        return Err(UnsupportedDecimalParts);
    }
    if exponent > 19 {
        return Ok(ScaledDecimalOutcome::rejected(false));
    }
    if mantissa == 0 {
        return Ok(ScaledDecimalOutcome {
            value: Some(0),
            note_requested: false,
        });
    }

    // The conceptual product can need 160 bits. Its factor is a power of ten:
    // every digit dropped to restore the 96-bit bound is zero, and at most
    // `exponent` digits are needed because the original mantissa already fits.
    // Reduce that factor before multiplication instead of truncating to u128.
    let mut factor = 10_u128.pow(u32::from(exponent));
    let mut dropped = 0;
    let mut value = loop {
        match mantissa.checked_mul(factor) {
            Some(product) if product < MANTISSA_LIMIT => break product,
            _ => {
                if dropped == scale {
                    return Ok(ScaledDecimalOutcome::rejected(false));
                }
                factor /= 10;
                dropped += 1;
            }
        }
    };
    let mut kept = scale - dropped;
    let divisor = 10_u128.pow(u32::from(kept));
    let quotient = value / divisor;
    let remainder = value % divisor;
    let twice = remainder * 2;
    let rounded = quotient + u128::from(twice > divisor || (twice == divisor && quotient & 1 != 0));
    let gap = value.abs_diff(rounded * divisor);
    let mut note_requested = false;
    if mode == 1 {
        if gap * 1000 < divisor {
            note_requested = gap != 0;
            value = rounded;
            kept = 0;
        }
    } else if mode != 0 {
        value = rounded;
        kept = 0;
    }
    let divisor = 10_u128.pow(u32::from(kept));
    if value % divisor != 0 {
        return Ok(ScaledDecimalOutcome::rejected(note_requested));
    }
    let whole = value / divisor;
    if (negative && whole != 0) || whole > CAP {
        return Ok(ScaledDecimalOutcome::rejected(note_requested));
    }
    Ok(ScaledDecimalOutcome {
        value: Some(whole as u64),
        note_requested,
    })
}

#[cfg(test)]
mod tests {
    use super::{UnsupportedDecimalParts, decimal_to_scaled_u64};

    #[test]
    fn frozen_instruction_evaluator_values_and_note_requests() {
        let vectors =
            include_str!("../../../research/work-items/RE-004-decimal-scaled-u64-94/vectors.tsv");
        let mut count = 0;
        for line in vectors.lines().skip(1) {
            let fields: Vec<_> = line.split('\t').collect();
            let actual = decimal_to_scaled_u64(
                fields[1] == "1",
                fields[2].parse().unwrap(),
                fields[3].parse().unwrap(),
                fields[4].parse().unwrap(),
                fields[5].parse().unwrap(),
            )
            .unwrap();
            let expected = if fields[6] == "ok" {
                Some(fields[7].parse().unwrap())
            } else {
                None
            };
            assert_eq!(actual.value, expected, "{line}");
            assert_eq!(actual.note_requested, fields[8] != "0", "{line}");
            count += 1;
        }
        assert_eq!(count, 25325);
    }

    #[test]
    fn own_api_refuses_unqualified_parts() {
        assert_eq!(
            decimal_to_scaled_u64(false, 1 << 96, 0, 0, 0),
            Err(UnsupportedDecimalParts)
        );
        assert_eq!(
            decimal_to_scaled_u64(false, 1, 29, 0, 0),
            Err(UnsupportedDecimalParts)
        );
        assert_eq!(
            decimal_to_scaled_u64(true, u128::MAX, 255, 255, 255),
            Err(UnsupportedDecimalParts)
        );
    }
}
