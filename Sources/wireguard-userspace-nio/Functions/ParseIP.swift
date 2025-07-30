import Foundation

enum ParsedIP {
    case ipv4(src: String, dst: String, proto: UInt8, headerLen: Int, totalLen: Int)
    case ipv6(src: String, dst: String, nextHeader: UInt8, totalLen: Int)
}

/// Top-level parser. Returns nil if `bytes` do not form a valid IPv4/IPv6 packet.
func parseIPPacket(_ bytes: [UInt8]) -> ParsedIP? {
    guard let first = bytes.first else { return nil }
    let version = first >> 4
    switch version {
        case 4: return parseIPv4(bytes)
        case 6: return parseIPv6(bytes)
        default: return nil
    }
}

/// Parse IPv4
private func parseIPv4(_ b: [UInt8]) -> ParsedIP? {
    // Minimum header 20 bytes
    guard b.count >= 20 else { return nil }

    let versionIHL = b[0]
    let version = versionIHL >> 4
    guard version == 4 else { return nil }

    let ihl = Int(versionIHL & 0x0F)           // in 32-bit words
    guard ihl >= 5 else { return nil }         // 5 * 4 = 20 bytes minimum
    let headerLen = ihl * 4
    guard b.count >= headerLen else { return nil }

    // total length (network byte order)
    let totalLen = Int((UInt16(b[2]) << 8) | UInt16(b[3]))
    guard totalLen >= headerLen, totalLen <= b.count else { return nil }

    // Validate header checksum (over header only)
    guard ipv4HeaderChecksumIsValid(b, headerLen: headerLen) else { return nil }

    // Source: bytes 12..15, Destination: 16..19
    let src = ipv4String(Array(b[12..<16]))
    let dst = ipv4String(Array(b[16..<20]))

    let proto = b[9] // Protocol field (e.g., 6 TCP, 17 UDP, 1 ICMP)

    return .ipv4(src: src, dst: dst, proto: proto, headerLen: headerLen, totalLen: totalLen)
}

private func ipv4HeaderChecksumIsValid(_ b: [UInt8], headerLen: Int) -> Bool {
    // Sum 16-bit words (header only). A valid header yields 0xFFFF after one's-complement addition.
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < headerLen {
        let word = (UInt16(b[i]) << 8) | UInt16(b[i+1])
        sum &+= UInt32(word)
        // fold carries
        sum = (sum & 0xFFFF) &+ (sum >> 16)
        i += 2
    }
    // If odd number of header bytes (shouldn't happen in IPv4), fold last byte.
    if i < headerLen {
        let word = UInt16(b[i]) << 8
        sum &+= UInt32(word)
        sum = (sum & 0xFFFF) &+ (sum >> 16)
    }
    // Final one's complement: valid checksum → sum == 0xFFFF
    return (sum & 0xFFFF) == 0xFFFF
}

private func ipv4String(_ quad: [UInt8]) -> String {
    precondition(quad.count == 4)
    return "\(quad[0]).\(quad[1]).\(quad[2]).\(quad[3])"
}

/// Parse IPv6
private func parseIPv6(_ b: [UInt8]) -> ParsedIP? {
    // IPv6 fixed header is 40 bytes
    guard b.count >= 40 else { return nil }
    let version = b[0] >> 4
    guard version == 6 else { return nil }

    // Payload length (bytes 4..5), total = 40 + payloadLen
    let payloadLen = Int((UInt16(b[4]) << 8) | UInt16(b[5]))
    let totalLen = 40 + payloadLen
    guard totalLen <= b.count else { return nil }

    let nextHeader = b[6]

    // Source: 16 bytes starting at 8; Destination: 16 bytes starting at 24
    let srcBytes = Array(b[8 ..< 24])
    let dstBytes = Array(b[24 ..< 40])

    let src = ipv6UncompressedString(srcBytes)
    let dst = ipv6UncompressedString(dstBytes)

    return .ipv6(src: src, dst: dst, nextHeader: nextHeader, totalLen: totalLen)
}

private func ipv6UncompressedString(_ bytes: [UInt8]) -> String {
    precondition(bytes.count == 16)
    // Group into 8 16-bit words, print hex without zero-compression
    var parts: [String] = []
    parts.reserveCapacity(8)
    var i = 0
    while i < 16 {
        let word = (UInt16(bytes[i]) << 8) | UInt16(bytes[i+1])
        parts.append(String(word, radix: 16))
        i += 2
    }
    return parts.joined(separator: ":")
}
