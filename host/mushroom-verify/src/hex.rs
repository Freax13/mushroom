//! This module implements (de-)serialization byte arrays as hex strings.

use core::fmt;

use serde::{de::Visitor, Deserializer, Serializer};

pub fn serialize<S, const N: usize>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    struct Hex<'a>(&'a [u8]);

    impl fmt::Display for Hex<'_> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            self.0
                .iter()
                .copied()
                .try_for_each(|b| write!(f, "{b:02x}"))
        }
    }

    serializer.collect_str(&Hex(value))
}

pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'de>,
{
    struct HexVisitor<const N: usize>;

    impl<const N: usize> Visitor<'_> for HexVisitor<N> {
        type Value = [u8; N];

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            write!(formatter, "a hex string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: serde::de::Error,
        {
            if let Some(c) = v.chars().find(|c| !c.is_ascii_hexdigit()) {
                return Err(E::custom(format!("expected hex digits, got {c:?}")));
            }

            if v.len() != N * 2 {
                return Err(E::custom(format!(
                    "expected {} hex digits, got {}",
                    N * 2,
                    v.len(),
                )));
            }

            let mut chars = v.chars();
            let mut bytes = [0; N];
            for dst in bytes.iter_mut() {
                let digit1 = chars.next().unwrap().to_digit(16).unwrap() as u8;
                let digit2 = chars.next().unwrap().to_digit(16).unwrap() as u8;
                *dst = (digit1 << 4) | digit2;
            }
            Ok(bytes)
        }
    }

    deserializer.deserialize_str(HexVisitor)
}
