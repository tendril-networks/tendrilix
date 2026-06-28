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

use core::net::IpAddr;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;
const IPV4_IHL_MASK: u8 = 0x0f;

fn valid_ipv4_header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < IPV4_MIN_HEADER_SIZE {
        return None;
    }

    let header_len = ((packet[0] & IPV4_IHL_MASK) as usize) * 4;
    if header_len < IPV4_MIN_HEADER_SIZE || packet.len() < header_len {
        return None;
    }

    Some(header_len)
}

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

pub fn src_address(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if valid_ipv4_header_len(packet).is_some() => {
            let addr_bytes: [u8; IPV4_IP_SZ] = packet
                [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                .try_into()
                .unwrap();

            Some(IpAddr::from(addr_bytes))
        }

        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV6_IP_SZ] = packet
                [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                .try_into()
                .unwrap();

            Some(IpAddr::from(addr_bytes))
        }

        _ => None,
    }
}

pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }

    match packet[0] >> 4 {
        4 if valid_ipv4_header_len(packet).is_some() => {
            let addr_bytes: [u8; IPV4_IP_SZ] = packet
                [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                .try_into()
                .unwrap();

            Some(IpAddr::from(addr_bytes))
        }

        6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
            let addr_bytes: [u8; IPV6_IP_SZ] = packet
                [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                .try_into()
                .unwrap();

            Some(IpAddr::from(addr_bytes))
        }

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::*;

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4]) -> [u8; 20] {
        let mut packet = [0u8; 20];
        packet[0] = 0x45; // IPv4, IHL = 5
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet
    }

    fn ipv6_packet(src: [u8; 16], dst: [u8; 16]) -> [u8; 40] {
        let mut packet = [0u8; 40];
        packet[0] = 0x60; // IPv6
        packet[8..24].copy_from_slice(&src);
        packet[24..40].copy_from_slice(&dst);
        packet
    }

    #[test]
    fn returns_none_for_empty_packet() {
        assert_eq!(src_address(&[]), None);
        assert_eq!(dst_address(&[]), None);
    }

    #[test]
    fn returns_none_for_unknown_ip_version() {
        let packet = [0x50u8; 20]; // version 5
        assert_eq!(src_address(&packet), None);
        assert_eq!(dst_address(&packet), None);
    }

    #[test]
    fn returns_none_for_short_ipv4_packet() {
        let mut packet = [0u8; 19];
        packet[0] = 0x45;

        assert_eq!(src_address(&packet), None);
        assert_eq!(dst_address(&packet), None);
    }

    #[test]
    fn returns_none_for_ipv4_header_length_below_minimum() {
        let mut packet = ipv4_packet([192, 0, 2, 1], [198, 51, 100, 2]);
        packet[0] = 0x44; // IPv4, invalid IHL = 4

        assert_eq!(src_address(&packet), None);
        assert_eq!(dst_address(&packet), None);
    }

    #[test]
    fn returns_none_for_ipv4_header_length_longer_than_packet() {
        let mut packet = ipv4_packet([192, 0, 2, 1], [198, 51, 100, 2]);
        packet[0] = 0x46; // IPv4, IHL = 6, but only 20 bytes present

        assert_eq!(src_address(&packet), None);
        assert_eq!(dst_address(&packet), None);
    }

    #[test]
    fn extracts_ipv4_source_and_destination() {
        let packet = ipv4_packet([192, 0, 2, 1], [198, 51, 100, 2]);

        assert_eq!(
            src_address(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );

        assert_eq!(
            dst_address(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );
    }

    #[test]
    fn extracts_ipv4_addresses_from_packet_with_options() {
        let mut packet = [0u8; 24];
        packet[0] = 0x46; // IPv4, IHL = 6
        packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
        packet[16..20].copy_from_slice(&[10, 0, 0, 2]);

        assert_eq!(
            src_address(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))
        );

        assert_eq!(
            dst_address(&packet),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    #[test]
    fn returns_none_for_short_ipv6_packet() {
        let mut packet = [0u8; 39];
        packet[0] = 0x60;

        assert_eq!(src_address(&packet), None);
        assert_eq!(dst_address(&packet), None);
    }

    #[test]
    fn extracts_ipv6_source_and_destination() {
        let src = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];

        let dst = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];

        let packet = ipv6_packet(src, dst);

        assert_eq!(src_address(&packet), Some(IpAddr::V6(Ipv6Addr::from(src))));
        assert_eq!(dst_address(&packet), Some(IpAddr::V6(Ipv6Addr::from(dst))));
    }
}
