use crate::{Result, SspryError};

pub const DEFAULT_TIER1_GRAM_SIZE: usize = 3;
pub const DEFAULT_TIER2_GRAM_SIZE: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GramSizes {
    pub tier2: usize,
    pub tier1: usize,
}

impl Default for GramSizes {
    /// Returns the default `(tier1, tier2)` gram pair used by the index.
    fn default() -> Self {
        Self {
            tier1: DEFAULT_TIER1_GRAM_SIZE,
            tier2: DEFAULT_TIER2_GRAM_SIZE,
        }
    }
}

impl GramSizes {
    /// Parses a CLI gram-size pair in `<tier1>,<tier2>` form and validates the
    /// resulting sizes.
    pub fn parse(text: &str) -> Result<Self> {
        let raw = text.trim();
        let Some((left, right)) = raw.split_once(',') else {
            return Err(SspryError::from(
                "candidate-gram-sizes must be '<tier1>,<tier2>' like '3,4'",
            ));
        };
        let left = left
            .trim()
            .parse::<usize>()
            .map_err(|_| SspryError::from("candidate-gram-sizes must contain positive integers"))?;
        let right = right
            .trim()
            .parse::<usize>()
            .map_err(|_| SspryError::from("candidate-gram-sizes must contain positive integers"))?;
        Self::new(left, right)
    }

    /// Validates and constructs a gram-size pair used by tier-1 and tier-2
    /// candidate extraction.
    pub fn new(tier1: usize, tier2: usize) -> Result<Self> {
        if tier1 < 3 || tier2 < 4 || tier1 >= tier2 || tier2 > 8 {
            return Err(SspryError::from(
                "candidate gram sizes must satisfy 3 <= tier1 < tier2 <= 8",
            ));
        }
        Ok(Self { tier1, tier2 })
    }

    /// Formats the gram-size pair back into the CLI string representation.
    pub fn as_cli_value(self) -> String {
        format!("{},{}", self.tier1, self.tier2)
    }

    /// Returns the encoded key width used to store tier-1 grams for this size.
    pub fn tier1_key_bytes(self) -> usize {
        if self.tier1 <= 4 { 4 } else { 8 }
    }
}

/// Packs an exact gram window into the low bytes of a little-endian `u64`.
pub fn pack_exact_gram(window: &[u8]) -> u64 {
    debug_assert!((1..=8).contains(&window.len()));
    let mut bytes = [0u8; 8];
    bytes[..window.len()].copy_from_slice(window);
    u64::from_le_bytes(bytes)
}

#[cfg(test)]
/// Expands a packed gram back into its original little-endian byte window for
/// test assertions.
pub fn exact_gram_to_le_bytes(value: u64, gram_size: usize) -> Vec<u8> {
    value.to_le_bytes()[..gram_size].to_vec()
}

#[cfg(test)]
mod tests {
    use super::{GramSizes, exact_gram_to_le_bytes, pack_exact_gram};

    #[test]
    fn gram_sizes_parse_and_normalize() {
        assert_eq!(
            GramSizes::parse("3,4").expect("sizes"),
            GramSizes { tier1: 3, tier2: 4 }
        );
        assert!(GramSizes::parse("3").is_err());
        assert!(GramSizes::parse("2,4").is_err());
        assert!(GramSizes::parse("4,4").is_err());
        assert!(GramSizes::parse("9,7").is_err());
    }

    #[test]
    fn gram_sizes_helpers_cover_defaults_and_errors() {
        let defaults = GramSizes::default();
        assert_eq!(defaults, GramSizes { tier1: 3, tier2: 4 });
        assert_eq!(defaults.as_cli_value(), "3,4");
        assert_eq!(defaults.tier1_key_bytes(), 4);
        assert_eq!(GramSizes::new(5, 6).expect("sizes").tier1_key_bytes(), 8);
        assert_eq!(
            GramSizes::parse(" 4 , 5 ").expect("normalized"),
            GramSizes { tier1: 4, tier2: 5 }
        );
        assert!(GramSizes::parse("x,4").is_err());
        assert!(GramSizes::parse("4,y").is_err());
        assert!(GramSizes::new(3, 3).is_err());
        assert!(GramSizes::new(2, 8).is_err());
        assert!(GramSizes::new(7, 9).is_err());
    }

    #[test]
    fn exact_pack_roundtrips() {
        let value = pack_exact_gram(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
        assert_eq!(
            exact_gram_to_le_bytes(value, 5),
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE]
        );
        let value8 = pack_exact_gram(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            exact_gram_to_le_bytes(value8, 8),
            vec![1, 2, 3, 4, 5, 6, 7, 8]
        );
    }
}
