use fasthash::murmur3;
use ibig::{ubig, UBig};
use std::convert::TryFrom;

const ALPHABET_SIZE: usize = 124;

// Sorted by character code to make binary search effective
// From <https://developer.vonage.com/messaging/sms/guides/concatenation-and-encoding>
const ALPHABET: &[char; ALPHABET_SIZE] = &[
    '!', '\"', '#', '$', '%', '&', '\'', '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2',
    '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E',
    'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', '_', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
    'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '¡', '£', '¤', '¥', '§', '¿', 'Ä', 'Å', 'Æ',
    'Ç', 'É', 'Ñ', 'Ö', 'Ø', 'Ü', 'ß', 'à', 'ä', 'å', 'æ', 'è', 'é', 'ì', 'ñ', 'ò', 'ö', 'ø', 'ù',
    'ü', 'Γ', 'Δ', 'Θ', 'Λ', 'Ξ', 'Π', 'Σ', 'Φ', 'Ψ', 'Ω',
];

fn compute_checksum(bytes: &[u8]) -> u16 {
    murmur3::hash32(bytes) as u16
}

pub fn encode(bytes: &[u8]) -> Vec<char> {
    let mut scratch = bytes.to_vec();

    let checksum = compute_checksum(bytes);
    scratch.extend_from_slice(&checksum.to_le_bytes());

    // Without this market we wouldn't be able to detect leading zeros. This
    // is cheaper than encoding a length to pad-to. Base64 doesn't have this
    // problem because they pad to a fixed chunk length, but the reason this
    // is more efficient is because we encode a variable length.
    scratch.push(u8::MAX);

    let mut q = UBig::from_le_bytes(&scratch);

    // Convert base-10 to base-alphabet_size
    let mut out = Vec::new();
    while q > ubig!(0) {
        let r = &q % ALPHABET_SIZE;
        out.push(ALPHABET[r]);
        q /= ALPHABET_SIZE;
    }

    out
}

pub fn decode(chars: &[char]) -> Result<Vec<u8>, MalformedError> {
    // Interpret bytes as a base-alphabet_size integer, convert to base-10
    let mut q = ubig!(0);
    let radix = UBig::try_from(ALPHABET_SIZE).unwrap();
    for (place, char) in chars.iter().enumerate() {
        let digit = ALPHABET.binary_search(char).map_err(|_| MalformedError)?;
        let value = digit * radix.pow(place);
        q += value;
    }

    let mut out = q.to_le_bytes();

    // Pop off the marker
    let marker = out.pop().ok_or(MalformedError)?;
    if marker != u8::MAX {
        return Err(MalformedError);
    }

    // Pop off the checksum
    let check_msb = out.pop().ok_or(MalformedError)?;
    let check_lsb = out.pop().ok_or(MalformedError)?;
    let check = u16::from_le_bytes([check_lsb, check_msb]);
    if check != compute_checksum(&out) {
        return Err(MalformedError);
    }

    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MalformedError;

#[cfg(test)]
mod test {
    use super::*;

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(10_000))]
            #[test]
            fn round_trips(bytes in any::<Vec<u8>>()) {
                let encoded = encode(&bytes);
                let decoded = decode(&encoded).unwrap();
                prop_assert_eq!(bytes, decoded);
            }
        }
    }

    #[test]
    fn basic_round_trips() {
        let bytes = &[0, 1, 42, 0][..];
        let encoded = encode(bytes);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn realistic_long_round_trips() {
        let bytes = generate_bytes(1_000);
        let encoded = encode(&bytes);
        let decoded = decode(&encoded).unwrap();
        assert_eq!(bytes, decoded);
    }

    #[test]
    fn is_efficient() {
        let mut n = 0;
        let max_n = loop {
            let bytes = generate_bytes(n);
            let encoded = encode(&bytes);
            if encoded.len() > 160 {
                break n - 1;
            }
            n += 1;
        };

        let efficiency = 160f64 / max_n as f64;
        // Base64 encodes to a length of 8/6 chars per byte, or ~1.33. We should be beating that
        assert!(efficiency < 1.33);

        assert_eq!(136, max_n); // Found by testing. Asserting to catch regression
    }

    #[test]
    fn rejects_outside_alphabet() {
        let result = decode(&[' ']);
        assert_eq!(Err(MalformedError), result);
    }

    fn generate_bytes(len: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for n in 0_usize..len {
            let b = (n % 256_usize) as u8;
            bytes.push(b);
        }
        bytes
    }
}
