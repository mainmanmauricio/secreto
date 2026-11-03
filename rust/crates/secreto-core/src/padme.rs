//! Padmé length padding (`spec/format.md`, *Padding*).

/// Padmé(L): the padded length for an unpadded length `l`.
///
/// `padme(0) == 0`. The result is always `>= l`.
pub fn padme(l: u64) -> u64 {
    if l < 2 {
        return l;
    }
    let e = 63 - l.leading_zeros() as u64; // floor(log2(l)), >= 1 here
    let s = (63 - e.leading_zeros() as u64) / 2; // floor(floor(log2(E)) / 2)
    let mask = (1u64 << (e - s)) - 1;
    // `l + mask` cannot overflow for any realistic file size; saturate for safety.
    l.saturating_add(mask) & !mask
}

/// Number of zero bytes to insert for an unpadded inner length `l`.
pub fn padding_len(l: u64) -> u64 {
    padme(l) - l
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct V {
        #[serde(rename = "L")]
        l: u64,
        padded: u64,
    }
    #[derive(Deserialize)]
    struct File {
        vectors: Vec<V>,
    }

    #[test]
    fn vectors() {
        let p = crate::test_util::vector_path("padme.json");
        let f: File = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        assert!(!f.vectors.is_empty());
        for v in f.vectors {
            assert_eq!(padme(v.l), v.padded, "L={}", v.l);
        }
    }

    #[test]
    fn properties() {
        assert_eq!(padme(0), 0);
        let mut prev = 0;
        for l in 1..100_000u64 {
            let p = padme(l);
            assert!(p >= l);
            assert!(p >= prev, "monotonic at {l}");
            assert_eq!(padme(p), p, "idempotent at {l}");
            assert!(p < 2 * l, "overhead too large at {l}: {p}");
            prev = p;
        }
        assert_eq!(padding_len(3), 1);
    }
}
