package com.flow.validator.vpn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * PacketParser — Zero-allocation IPv4/TCP/UDP packet field extractor.
 *
 * <p>All methods operate directly on a {@link ByteBuffer} slice that the caller
 * positions at the start of the IP header. No new objects are created on the
 * hot path — callers reuse their ByteBuffer and this class produces only
 * primitive values or writes into caller-supplied arrays.
 *
 * <p>Supported protocols:
 * <ul>
 *   <li>IP version 4 only (version field check)</li>
 *   <li>Protocol 6  = TCP</li>
 *   <li>Protocol 17 = UDP</li>
 * </ul>
 */
public final class PacketParser {

    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    private PacketParser() {}

    // ---- IPv4 header accessors ------------------------------------------------

    public static int ipVersion(ByteBuffer pkt) {
        return (pkt.get(0) >> 4) & 0xF;
    }

    public static int ipHeaderLen(ByteBuffer pkt) {
        return (pkt.get(0) & 0xF) * 4;
    }

    public static int ipProtocol(ByteBuffer pkt) {
        return pkt.get(9) & 0xFF;
    }

    public static int ipTotalLen(ByteBuffer pkt) {
        return ((pkt.get(2) & 0xFF) << 8) | (pkt.get(3) & 0xFF);
    }

    /** Source IP as a 32-bit int (big-endian). */
    public static int srcIp(ByteBuffer pkt) {
        return pkt.getInt(12);
    }

    /** Destination IP as a 32-bit int (big-endian). */
    public static int dstIp(ByteBuffer pkt) {
        return pkt.getInt(16);
    }

    // ---- TCP / UDP transport accessors ----------------------------------------

    public static int srcPort(ByteBuffer pkt) {
        int ihl = ipHeaderLen(pkt);
        return ((pkt.get(ihl) & 0xFF) << 8) | (pkt.get(ihl + 1) & 0xFF);
    }

    public static int dstPort(ByteBuffer pkt) {
        int ihl = ipHeaderLen(pkt);
        return ((pkt.get(ihl + 2) & 0xFF) << 8) | (pkt.get(ihl + 3) & 0xFF);
    }

    /** TCP data offset (header length in bytes). */
    public static int tcpHeaderLen(ByteBuffer pkt) {
        int ihl = ipHeaderLen(pkt);
        return ((pkt.get(ihl + 12) >> 4) & 0xF) * 4;
    }

    /** Offset of the first TCP payload byte within the packet buffer. */
    public static int tcpPayloadOffset(ByteBuffer pkt) {
        return ipHeaderLen(pkt) + tcpHeaderLen(pkt);
    }

    /** Offset of the UDP payload within the packet buffer (skips 8-byte UDP header). */
    public static int udpPayloadOffset(ByteBuffer pkt) {
        return ipHeaderLen(pkt) + 8;
    }

    // ---- Payload extraction ---------------------------------------------------

    /**
     * Extract a US-ASCII string from the TCP payload.
     *
     * @param pkt    Packet buffer, position at start.
     * @param maxLen Maximum characters to extract (avoids large allocations).
     * @return Extracted string, or empty string if no payload.
     */
    public static String tcpPayloadString(ByteBuffer pkt, int maxLen) {
        int offset = tcpPayloadOffset(pkt);
        int limit  = Math.min(pkt.limit(), offset + maxLen);
        if (offset >= limit) return "";
        byte[] tmp = new byte[limit - offset];
        for (int i = 0; i < tmp.length; i++) tmp[i] = pkt.get(offset + i);
        return new String(tmp, StandardCharsets.US_ASCII);
    }

    /**
     * Parse a DNS question section hostname from a UDP payload.
     *
     * @param pkt Packet buffer.
     * @return Dot-separated hostname, or {@code null} if malformed.
     */
    public static String dnsQueryName(ByteBuffer pkt) {
        int pos = udpPayloadOffset(pkt) + 12; // skip 12-byte DNS header
        StringBuilder name = new StringBuilder(64);
        try {
            while (pos < pkt.limit()) {
                int labelLen = pkt.get(pos) & 0xFF;
                if (labelLen == 0) break;
                if (name.length() > 0) name.append('.');
                pos++;
                if (pos + labelLen > pkt.limit()) return null;
                for (int i = 0; i < labelLen; i++) {
                    name.append((char) (pkt.get(pos + i) & 0xFF));
                }
                pos += labelLen;
            }
        } catch (Exception e) {
            return null;
        }
        return name.length() > 0 ? name.toString().toLowerCase() : null;
    }

    // ---- Validity checks ------------------------------------------------------

    public static boolean isValidIPv4(ByteBuffer pkt) {
        return pkt.limit() >= 20 && ipVersion(pkt) == 4;
    }

    public static boolean isTcp(ByteBuffer pkt) {
        return ipProtocol(pkt) == PROTO_TCP;
    }

    public static boolean isUdp(ByteBuffer pkt) {
        return ipProtocol(pkt) == PROTO_UDP;
    }

    public static boolean isDns(ByteBuffer pkt) {
        return isUdp(pkt) && dstPort(pkt) == 53;
    }

    public static boolean isHttp(ByteBuffer pkt) {
        if (!isTcp(pkt)) return false;
        int port = dstPort(pkt);
        return port == 80 || port == 8080 || port == 8888;
    }

    public static boolean isHttps(ByteBuffer pkt) {
        return isTcp(pkt) && dstPort(pkt) == 443;
    }
    /** TCP flags byte. */
    public static int tcpFlags(ByteBuffer pkt) {
        int ihl = ipHeaderLen(pkt);
        if (pkt.limit() < ihl + 14) return 0;
        return pkt.get(ihl + 13) & 0xFF;
    }

    /** True если это TCP SYN (без ACK) — начало нового соединения. */
    public static boolean isTcpSyn(ByteBuffer pkt) {
        if (!isTcp(pkt)) return false;
        int flags = tcpFlags(pkt);
        return (flags & 0x02) != 0 && (flags & 0x10) == 0; // SYN=1, ACK=0
    }

    /** True если TCP пакет содержит данные (payload > 0). */
    public static boolean hasTcpPayload(ByteBuffer pkt) {
        if (!isTcp(pkt)) return false;
        int payloadOff = tcpPayloadOffset(pkt);
        return payloadOff < pkt.limit();
    }

}
