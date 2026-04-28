use sha2::{Digest, Sha256};

pub fn ce_v1_bytes(records: &[(&str, &[u8])]) -> Vec<u8> {
    let total: usize = records
        .iter()
        .map(|(label, value)| 2 + label.len() + 4 + value.len())
        .sum();
    let mut out = Vec::with_capacity(total);
    for (label, value) in records {
        let label_len = u16::try_from(label.len()).expect("CE-v1 label exceeds u16::MAX");
        let value_len = u32::try_from(value.len()).expect("CE-v1 value exceeds u32::MAX");
        out.extend_from_slice(&label_len.to_be_bytes());
        out.extend_from_slice(label.as_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(value);
    }
    out
}

pub fn ce_v1_hash(records: &[(&str, &[u8])]) -> [u8; 32] {
    Sha256::digest(ce_v1_bytes(records)).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_layout_matches_d11() {
        assert_eq!(
            ce_v1_bytes(&[("ab", b"cd")]),
            vec![0x00, 0x02, b'a', b'b', 0x00, 0x00, 0x00, 0x02, b'c', b'd']
        );
    }

    #[test]
    fn no_magic_prefix_is_added() {
        let bytes = ce_v1_bytes(&[("purpose", b"example")]);
        assert!(!bytes.starts_with(b"CE-v1"));
    }

    #[test]
    fn hash_is_sha256_of_raw_tlv() {
        let records = &[("purpose", b"enclava-test-v1".as_slice())];
        let expected: [u8; 32] = Sha256::digest(ce_v1_bytes(records)).into();
        assert_eq!(ce_v1_hash(records), expected);
    }

    #[test]
    fn boundaries_are_unambiguous() {
        assert_ne!(ce_v1_bytes(&[("a", b"bc")]), ce_v1_bytes(&[("ab", b"c")]));
        assert_ne!(ce_v1_hash(&[("a", b"bc")]), ce_v1_hash(&[("ab", b"c")]));
    }
}
