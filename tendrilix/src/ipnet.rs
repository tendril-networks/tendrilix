/*
 * SPDX-License-Identifier: AGPL-3.0-only
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

use core::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, EnumAccess, Error as _, VariantAccess, Visitor},
    ser::SerializeTuple,
};

/// Error returned when a prefix length exceeds the address family's width
/// (32 bits for IPv4, 128 bits for IPv6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PrefixLenError;

impl fmt::Display for PrefixLenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP prefix length")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrefixLenError {}

/// Error returned when a string cannot be parsed as a CIDR network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AddrParseError;

impl fmt::Display for AddrParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid IP network address")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AddrParseError {}

#[inline]
fn v4_netmask(prefix_len: u8) -> u32 {
    // `u32 << 32` is undefined behaviour, so handle a zero-length prefix
    // explicitly. For 1..=32 the shift is well defined (32 - prefix_len < 32,
    // except prefix_len == 32 where the shift is 0 and the mask is all ones).
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

#[inline]
fn v6_netmask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

/// An IPv4 address together with a prefix length, i.e. a CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Net {
    /// Maximum valid prefix length for an IPv4 network.
    pub const MAX_PREFIX_LEN: u8 = 32;

    /// Creates a new IPv4 network from an address and prefix length.
    ///
    /// The host bits of `addr` are preserved; use
    /// [`network`](Self::network) to obtain the masked network address.
    pub const fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Ipv4Net, PrefixLenError> {
        if prefix_len > Self::MAX_PREFIX_LEN {
            return Err(PrefixLenError);
        }
        Ok(Ipv4Net { addr, prefix_len })
    }

    /// Returns the stored address, including any host bits.
    #[inline]
    pub const fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// Returns the prefix length.
    #[inline]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns the network address (the stored address with its host bits
    /// cleared).
    #[inline]
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.addr) & v4_netmask(self.prefix_len))
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Ipv4Net {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = s.split_once('/').ok_or(AddrParseError)?;
        let addr = Ipv4Addr::from_str(addr_s).map_err(|_| AddrParseError)?;
        let prefix_len = prefix_s.parse::<u8>().map_err(|_| AddrParseError)?;
        Ipv4Net::new(addr, prefix_len).map_err(|_| AddrParseError)
    }
}

/// An IPv6 address together with a prefix length, i.e. a CIDR block.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Ipv6Net {
    addr: Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Net {
    /// Maximum valid prefix length for an IPv6 network.
    pub const MAX_PREFIX_LEN: u8 = 128;

    /// Creates a new IPv6 network from an address and prefix length.
    ///
    /// The host bits of `addr` are preserved; use
    /// [`network`](Self::network) to obtain the masked network address.
    pub const fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Ipv6Net, PrefixLenError> {
        if prefix_len > Self::MAX_PREFIX_LEN {
            return Err(PrefixLenError);
        }
        Ok(Ipv6Net { addr, prefix_len })
    }

    /// Returns the stored address, including any host bits.
    #[inline]
    pub const fn addr(&self) -> Ipv6Addr {
        self.addr
    }

    /// Returns the prefix length.
    #[inline]
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Returns the network address (the stored address with its host bits
    /// cleared).
    #[inline]
    pub fn network(&self) -> Ipv6Addr {
        Ipv6Addr::from(u128::from(self.addr) & v6_netmask(self.prefix_len))
    }
}

impl fmt::Display for Ipv6Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for Ipv6Net {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = s.split_once('/').ok_or(AddrParseError)?;
        let addr = Ipv6Addr::from_str(addr_s).map_err(|_| AddrParseError)?;
        let prefix_len = prefix_s.parse::<u8>().map_err(|_| AddrParseError)?;
        Ipv6Net::new(addr, prefix_len).map_err(|_| AddrParseError)
    }
}

/// An IP network (CIDR block) of either address family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IpNet {
    /// An IPv4 network.
    V4(Ipv4Net),
    /// An IPv6 network.
    V6(Ipv6Net),
}

impl IpNet {
    /// Creates a new network from an [`IpAddr`] and prefix length.
    ///
    /// Returns [`PrefixLenError`] if `prefix_len` is too large for the address
    /// family.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<IpNet, PrefixLenError> {
        match addr {
            IpAddr::V4(addr) => Ipv4Net::new(addr, prefix_len).map(IpNet::V4),
            IpAddr::V6(addr) => Ipv6Net::new(addr, prefix_len).map(IpNet::V6),
        }
    }

    /// Returns the stored address, including any host bits.
    #[inline]
    pub fn addr(&self) -> IpAddr {
        match self {
            IpNet::V4(n) => IpAddr::V4(n.addr()),
            IpNet::V6(n) => IpAddr::V6(n.addr()),
        }
    }

    /// Returns the prefix length.
    #[inline]
    pub fn prefix_len(&self) -> u8 {
        match self {
            IpNet::V4(n) => n.prefix_len(),
            IpNet::V6(n) => n.prefix_len(),
        }
    }

    /// Returns the network address (the stored address with its host bits
    /// cleared).
    #[inline]
    pub fn network(&self) -> IpAddr {
        match self {
            IpNet::V4(n) => IpAddr::V4(n.network()),
            IpNet::V6(n) => IpAddr::V6(n.network()),
        }
    }

    /// Returns `true` if this is an IPv4 network.
    #[inline]
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpNet::V4(_))
    }

    /// Returns `true` if this is an IPv6 network.
    #[inline]
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpNet::V6(_))
    }
}

impl fmt::Display for IpNet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpNet::V4(n) => n.fmt(f),
            IpNet::V6(n) => n.fmt(f),
        }
    }
}

impl FromStr for IpNet {
    type Err = AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (addr_s, prefix_s) = s.split_once('/').ok_or(AddrParseError)?;
        let prefix_len = prefix_s.parse::<u8>().map_err(|_| AddrParseError)?;
        match IpAddr::from_str(addr_s).map_err(|_| AddrParseError)? {
            IpAddr::V4(addr) => Ipv4Net::new(addr, prefix_len)
                .map(IpNet::V4)
                .map_err(|_| AddrParseError),
            IpAddr::V6(addr) => Ipv6Net::new(addr, prefix_len)
                .map(IpNet::V6)
                .map_err(|_| AddrParseError),
        }
    }
}

impl From<Ipv4Net> for IpNet {
    fn from(net: Ipv4Net) -> Self {
        IpNet::V4(net)
    }
}

impl From<Ipv6Net> for IpNet {
    fn from(net: Ipv6Net) -> Self {
        IpNet::V6(net)
    }
}

impl Serialize for Ipv4Net {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // "a.b.c.d/p" — max length is "255.255.255.255/32" = 18 chars.
            let mut buf = heapless::String::<18>::new();
            let _ = fmt::write(&mut buf, format_args!("{}", self));
            serializer.serialize_str(buf.as_str())
        } else {
            let mut tuple = serializer.serialize_tuple(5)?;
            for octet in self.addr.octets() {
                tuple.serialize_element(&octet)?;
            }
            tuple.serialize_element(&self.prefix_len)?;
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for Ipv4Net {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct StrVisitor;
            impl Visitor<'_> for StrVisitor {
                type Value = Ipv4Net;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an IPv4 network address")
                }
                fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                    s.parse().map_err(E::custom)
                }
            }
            deserializer.deserialize_str(StrVisitor)
        } else {
            let b = <[u8; 5]>::deserialize(deserializer)?;
            Ipv4Net::new(Ipv4Addr::new(b[0], b[1], b[2], b[3]), b[4]).map_err(D::Error::custom)
        }
    }
}

impl Serialize for Ipv6Net {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            // Worst case is an IPv4-mapped form such as
            // "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128" (<= 49); 64
            // leaves comfortable headroom.
            let mut buf = heapless::String::<64>::new();
            let _ = fmt::write(&mut buf, format_args!("{}", self));
            serializer.serialize_str(buf.as_str())
        } else {
            let mut tuple = serializer.serialize_tuple(17)?;
            for octet in self.addr.octets() {
                tuple.serialize_element(&octet)?;
            }
            tuple.serialize_element(&self.prefix_len)?;
            tuple.end()
        }
    }
}

impl<'de> Deserialize<'de> for Ipv6Net {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct StrVisitor;
            impl Visitor<'_> for StrVisitor {
                type Value = Ipv6Net;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an IPv6 network address")
                }
                fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                    s.parse().map_err(E::custom)
                }
            }
            deserializer.deserialize_str(StrVisitor)
        } else {
            let b = <[u8; 17]>::deserialize(deserializer)?;
            let addr = Ipv6Addr::from([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12],
                b[13], b[14], b[15],
            ]);
            Ipv6Net::new(addr, b[16]).map_err(D::Error::custom)
        }
    }
}

impl Serialize for IpNet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            match self {
                IpNet::V4(n) => n.serialize(serializer),
                IpNet::V6(n) => n.serialize(serializer),
            }
        } else {
            match self {
                IpNet::V4(n) => serializer.serialize_newtype_variant("IpNet", 0, "V4", n),
                IpNet::V6(n) => serializer.serialize_newtype_variant("IpNet", 1, "V6", n),
            }
        }
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct StrVisitor;
            impl Visitor<'_> for StrVisitor {
                type Value = IpNet;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an IPv4 or IPv6 network address")
                }
                fn visit_str<E: de::Error>(self, s: &str) -> Result<Self::Value, E> {
                    s.parse().map_err(E::custom)
                }
            }
            deserializer.deserialize_str(StrVisitor)
        } else {
            #[derive(Deserialize)]
            enum Kind {
                V4,
                V6,
            }

            struct EnumVisitor;
            impl<'de> Visitor<'de> for EnumVisitor {
                type Value = IpNet;
                fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    f.write_str("an IPv4 or IPv6 network address")
                }
                fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
                where
                    A: EnumAccess<'de>,
                {
                    match data.variant()? {
                        (Kind::V4, v) => v.newtype_variant().map(IpNet::V4),
                        (Kind::V6, v) => v.newtype_variant().map(IpNet::V6),
                    }
                }
            }
            deserializer.deserialize_enum("IpNet", &["V4", "V6"], EnumVisitor)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(a: u8, b: u8, c: u8, d: u8) -> Ipv4Addr {
        Ipv4Addr::new(a, b, c, d)
    }

    #[test]
    fn prefix_len_is_validated() {
        assert!(Ipv4Net::new(v4(10, 0, 0, 0), 32).is_ok());
        assert_eq!(Ipv4Net::new(v4(10, 0, 0, 0), 33), Err(PrefixLenError));
        assert!(Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 128).is_ok());
        assert_eq!(
            Ipv6Net::new(Ipv6Addr::UNSPECIFIED, 129),
            Err(PrefixLenError)
        );
    }

    #[test]
    fn addr_keeps_host_bits_network_masks() {
        let n = Ipv4Net::new(v4(45, 25, 15, 1), 30).unwrap();
        assert_eq!(n.addr(), v4(45, 25, 15, 1));
        assert_eq!(n.network(), v4(45, 25, 15, 0));

        // Edge prefixes must not trigger an out-of-range shift.
        let zero = Ipv4Net::new(v4(10, 1, 2, 3), 0).unwrap();
        assert_eq!(zero.network(), v4(0, 0, 0, 0));
        let full = Ipv4Net::new(v4(10, 1, 2, 3), 32).unwrap();
        assert_eq!(full.network(), v4(10, 1, 2, 3));

        let n6 = Ipv6Net::new("2001:db8::1".parse().unwrap(), 32).unwrap();
        assert_eq!(n6.network(), "2001:db8::".parse::<Ipv6Addr>().unwrap());
        let z6 = Ipv6Net::new("2001:db8::1".parse().unwrap(), 0).unwrap();
        assert_eq!(z6.network(), Ipv6Addr::UNSPECIFIED);
        let f6 = Ipv6Net::new("2001:db8::1".parse().unwrap(), 128).unwrap();
        assert_eq!(f6.network(), "2001:db8::1".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn display_round_trips_through_from_str() {
        for s in ["0.0.0.0/0", "45.25.15.1/30", "255.255.255.255/32"] {
            let n: IpNet = s.parse().unwrap();
            let mut buf = heapless::String::<64>::new();
            let _ = fmt::write(&mut buf, format_args!("{n}"));
            assert_eq!(buf.as_str(), s);
            assert!(n.is_ipv4());
        }
        for s in ["::/0", "2001:db8::1/64", "fe80::1/128"] {
            let n: IpNet = s.parse().unwrap();
            assert!(n.is_ipv6());
            assert_eq!(n, s.parse().unwrap());
        }
        assert!("not-an-ip/24".parse::<IpNet>().is_err());
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("10.0.0.0".parse::<IpNet>().is_err());
    }

    #[test]
    fn json_is_a_string() {
        let n = IpNet::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24).unwrap();
        let s = serde_json::to_string(&n).unwrap();
        assert_eq!(s, "\"10.0.0.0/24\"");
        let back: IpNet = serde_json::from_str(&s).unwrap();
        assert_eq!(back, n);
    }
}
