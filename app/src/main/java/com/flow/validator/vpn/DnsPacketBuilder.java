package com.flow.validator.vpn;

import java.nio.ByteBuffer;

/**
 * DnsPacketBuilder — строит DNS NXDOMAIN UDP/IPv4 ответ.
 *
 * Получает на вход сырой IPv4+UDP+DNS запрос (byte[]),
 * возвращает корректный DNS ответ с RCODE=3 (NXDOMAIN) готовый
 * для записи в TUN-интерфейс.
 *
 * Формат DNS ответа: те же поля что и запрос, но:
 *  - QR=1 (response)
 *  - RA=1 (recursion available)
 *  - RCODE=3 (NXDOMAIN)
 *  - ANCOUNT=0 (нет ответных записей)
 *
 * IP/UDP src↔dst меняются местами.
 */
public final class DnsPacketBuilder {

    private DnsPacketBuilder() {}

    /**
     * @param queryRaw сырой IPv4+UDP+DNS запрос
     * @return готовый пакет для TUN или null при ошибке
     */
    public static byte[] buildNxdomain(byte[] queryRaw) {
        try {
            ByteBuffer q = ByteBuffer.wrap(queryRaw);
            if (queryRaw.length < 28) return null; // IP(20) + UDP(8)

            int ipHdrLen = (queryRaw[0] & 0x0F) * 4;
            if (ipHdrLen < 20 || ipHdrLen + 8 > queryRaw.length) return null;

            int udpOff = ipHdrLen;
            int dnsOff = udpOff + 8;
            int dnsLen = queryRaw.length - dnsOff;
            if (dnsLen < 12) return null; // DNS header минимум 12 байт

            // Читаем адреса из запроса
            int srcIp   = q.getInt(12);
            int dstIp   = q.getInt(16);
            int srcPort = ((queryRaw[udpOff]     & 0xFF) << 8) | (queryRaw[udpOff + 1] & 0xFF);
            int dstPort = ((queryRaw[udpOff + 2] & 0xFF) << 8) | (queryRaw[udpOff + 3] & 0xFF);

            // Копируем DNS payload и модифицируем flags
            byte[] dns = new byte[dnsLen];
            System.arraycopy(queryRaw, dnsOff, dns, 0, dnsLen);

            // DNS flags: QR=1, Opcode=0, AA=0, TC=0, RD=1(из запроса), RA=1, Z=0, RCODE=3
            byte rdBit = (byte)((dns[2] & 0x01));  // сохраняем RD из запроса
            dns[2] = (byte)(0x81 | rdBit);         // QR=1, RD=сохранён
            dns[3] = (byte)0x83;                    // RA=1, RCODE=3 NXDOMAIN
            // ANCOUNT, NSCOUNT, ARCOUNT = 0
            dns[6] = 0; dns[7]  = 0;
            dns[8] = 0; dns[9]  = 0;
            dns[10]= 0; dns[11] = 0;

            // Строим ответный пакет: IP + UDP + DNS
            int udpPayloadLen = dnsLen;
            int udpTotalLen   = 8 + udpPayloadLen;
            int ipTotalLen    = 20 + udpTotalLen;
            byte[] out = new byte[ipTotalLen];

            // ── IPv4 header (20 байт) ──────────────────────────────────────────
            out[0]  = 0x45;                                    // Version=4, IHL=5
            out[1]  = 0x00;                                    // DSCP/ECN
            out[2]  = (byte)(ipTotalLen >> 8);
            out[3]  = (byte)(ipTotalLen & 0xFF);
            out[4]  = 0x00; out[5] = 0x01;                    // ID
            out[6]  = 0x40; out[7] = 0x00;                    // Flags=DF
            out[8]  = 64;                                      // TTL
            out[9]  = 17;                                      // Protocol=UDP
            out[10] = 0;    out[11] = 0;                      // checksum placeholder
            // Src = original dst (DNS server), Dst = original src (client)
            out[12] = (byte)(dstIp >>> 24); out[13] = (byte)(dstIp >>> 16);
            out[14] = (byte)(dstIp >>>  8); out[15] = (byte)(dstIp);
            out[16] = (byte)(srcIp >>> 24); out[17] = (byte)(srcIp >>> 16);
            out[18] = (byte)(srcIp >>>  8); out[19] = (byte)(srcIp);

            int ipCsum = checksum(out, 0, 20);
            out[10] = (byte)(ipCsum >> 8);
            out[11] = (byte)(ipCsum & 0xFF);

            // ── UDP header (8 байт) ────────────────────────────────────────────
            // src port = 53 (DNS), dst port = client ephemeral
            out[20] = (byte)(dstPort >> 8); out[21] = (byte)(dstPort & 0xFF); // src=53
            out[22] = (byte)(srcPort >> 8); out[23] = (byte)(srcPort & 0xFF); // dst=client
            out[24] = (byte)(udpTotalLen >> 8);
            out[25] = (byte)(udpTotalLen & 0xFF);
            out[26] = 0; out[27] = 0; // UDP checksum = 0 (optional для UDP/IPv4)

            // ── DNS payload ────────────────────────────────────────────────────
            System.arraycopy(dns, 0, out, 28, dnsLen);

            return out;
        } catch (Exception e) {
            return null;
        }
    }

    // Internet checksum (RFC 1071)
    static int checksum(byte[] buf, int off, int len) {
        int sum = 0;
        int i   = off;
        while (i < off + len - 1) {
            sum += ((buf[i] & 0xFF) << 8) | (buf[i + 1] & 0xFF);
            i += 2;
        }
        if ((len & 1) == 1) sum += (buf[off + len - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }
}
