/*
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * This file incorporates work originally licensed under the
 * BSD 3-Clause License:
 *
 *   Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
 *
 * Modifications and additional work:
 *
 *   Copyright (c) 2026 Damian Peckett <damian@pecke.tt>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

use base64::{Engine, engine::general_purpose};
use x25519_dalek::PublicKey;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyBytes(pub [u8; 32]);

impl core::str::FromStr for KeyBytes {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut internal = [0u8; 32];

        match s.len() {
            64 => {
                hex::decode_to_slice(s, &mut internal).map_err(|_| "Illegal character in key")?;
            }

            43 | 44 => {
                // Try to parse as base64 without allocating

                let decoded_len = general_purpose::STANDARD
                    .decode_slice(s, &mut internal)
                    .map_err(|_| "Illegal character in key")?;

                if decoded_len != internal.len() {
                    return Err("Illegal key size");
                }
            }

            _ => {
                return Err("Illegal key size");
            }
        }

        Ok(KeyBytes(internal))
    }
}

impl From<KeyBytes> for PublicKey {
    fn from(key: KeyBytes) -> Self {
        PublicKey::from(key.0)
    }
}

impl From<PublicKey> for KeyBytes {
    fn from(key: PublicKey) -> Self {
        KeyBytes(key.to_bytes())
    }
}

impl From<&PublicKey> for KeyBytes {
    fn from(key: &PublicKey) -> Self {
        KeyBytes(key.to_bytes())
    }
}

#[cfg(feature = "log")]
impl core::fmt::Display for KeyBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut encoded = [0u8; 44];

        general_purpose::STANDARD
            .encode_slice(self.0, &mut encoded)
            .map_err(|_| core::fmt::Error)?;

        // SAFETY: base64 output is always ASCII
        let s = unsafe { core::str::from_utf8_unchecked(&encoded) };

        f.write_str(s)
    }
}

#[cfg(feature = "defmt")]
impl defmt::Format for KeyBytes {
    fn format(&self, fmt: defmt::Formatter) {
        let mut encoded = [0u8; 44];

        let len = general_purpose::STANDARD
            .encode_slice(&self.0, &mut encoded)
            .unwrap();

        // SAFETY: base64 output is always valid ASCII/UTF-8
        let s = unsafe { core::str::from_utf8_unchecked(&encoded[..len]) };

        defmt::write!(fmt, "{}", s);
    }
}

impl serde::Serialize for KeyBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            let mut encoded = [0u8; 44];

            let len = general_purpose::STANDARD
                .encode_slice(self.0, &mut encoded)
                .map_err(serde::ser::Error::custom)?;

            let encoded =
                core::str::from_utf8(&encoded[..len]).map_err(serde::ser::Error::custom)?;

            serializer.serialize_str(encoded)
        } else {
            use serde::ser::SerializeTuple;

            // Binary formats such as postcard should carry keys as a fixed
            // 32-byte array, not as a base64 string or length-prefixed byte
            // slice.
            let mut tuple = serializer.serialize_tuple(32)?;
            for byte in self.0 {
                tuple.serialize_element(&byte)?;
            }
            tuple.end()
        }
    }
}

impl<'de> serde::Deserialize<'de> for KeyBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct KeyBytesVisitor;

        impl<'de> serde::de::Visitor<'de> for KeyBytesVisitor {
            type Value = KeyBytes;

            fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                formatter
                    .write_str("a 32-byte key encoded as hex/base64 text or a raw 32-byte array")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                value.parse().map_err(E::custom)
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }

            fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let bytes: [u8; 32] = value
                    .try_into()
                    .map_err(|_| E::custom("invalid key length"))?;
                Ok(KeyBytes(bytes))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 32];
                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }

                if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                    return Err(serde::de::Error::invalid_length(33, &self));
                }

                Ok(KeyBytes(bytes))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(KeyBytesVisitor)
        } else {
            deserializer.deserialize_tuple(32, KeyBytesVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use x25519_dalek::PublicKey;

    use super::KeyBytes;

    const KEY_BYTES: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];

    #[test]
    fn keybytes_from_str_accepts_hex_and_base64_encodings() {
        let expected = KeyBytes(KEY_BYTES);

        assert_eq!(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".parse::<KeyBytes>(),
            Ok(expected)
        );
        assert_eq!(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".parse::<KeyBytes>(),
            Ok(expected)
        );
    }

    #[test]
    fn keybytes_from_str_rejects_malformed_input_by_size_or_character() {
        let malformed_non_ascii_with_64_bytes = "😀".repeat(16);

        assert_eq!(malformed_non_ascii_with_64_bytes.len(), 64);
        assert_eq!(
            malformed_non_ascii_with_64_bytes.parse::<KeyBytes>(),
            Err("Illegal character in key")
        );
        assert_eq!("abc".parse::<KeyBytes>(), Err("Illegal key size"));
        assert_eq!(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh?=".parse::<KeyBytes>(),
            Err("Illegal character in key")
        );
        assert_eq!(
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHg==".parse::<KeyBytes>(),
            Err("Illegal key size")
        );
    }

    #[test]
    fn keybytes_round_trips_to_and_from_x25519_public_key() {
        let key_bytes = KeyBytes(KEY_BYTES);

        let public_key = PublicKey::from(key_bytes);

        assert_eq!(public_key.to_bytes(), KEY_BYTES);
        assert_eq!(KeyBytes::from(public_key), key_bytes);
        assert_eq!(KeyBytes::from(&PublicKey::from(KEY_BYTES)), key_bytes);
    }
}
