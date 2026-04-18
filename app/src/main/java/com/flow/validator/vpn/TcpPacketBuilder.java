package com.flow.validator.vpn;

import java.nio.ByteBuffer;

/**
 * TcpPacketBuilder — строит TCP RST пакет в ответ на входящий TCP пакет.
 *
 * Используется для блокировки HTTP и HTTPS соединений.
 * RST отправляется от имени "сервера" (src/dst меняются местами),
 * что заставляет клиента немедленно закрыть соединение.
 *
 * Итоговый пакет: IPv4(20) + TCP(20) = 40 байт, без payload.
 */
public final class TcpPacketBuilder {

    private TcpPacketBuilder() {}

    /**
     * @param queryRaw сырой IPv4+TCP пакет который нужно сбросить
     * @return RST пакет готовый для записи в TUN, или null при ошибке
     */
    public static byte[] buildRst(byte[] queryRaw) {
        try {
            ByteBuffer q = ByteBuffer.wrap(queryRaw);
            if (queryRaw.length < 40) return null; // IP(20)+TCP(20)

            int ipHdrLen = (queryRaw[0] & 0x0F) * 4;
            if (ipHdrLen < 20 || ipHdrLen + 20 > queryRaw.length) return null;

            int tcpOff = ipHdrLen;

            // Поля из оригинального пакета
            int srcIp   = q.getInt(12);
            int dstIp   = q.getInt(16);
            int srcPort = ((queryRaw[tcpOff]     & 0xFF) << 8) | (queryRaw[tcpOff + 1] & 0xFF);
            int dstPort = ((queryRaw[tcpOff + 2] & 0xFF) << 8) | (queryRaw[tcpOff + 3] & 0xFF);

            // SEQ из входящего пакета → наш ACK = SEQ+1 (если есть SYN или данные)
            long inSeq = ((queryRaw[tcpOff + 4] & 0xFFL) << 24)
                       | ((queryRaw[tcpOff + 5] & 0xFFL) << 16)
                       | ((queryRaw[tcpOff + 6] & 0xFFL) << 8)
                       |  (queryRaw[tcpOff + 7] & 0xFFL);

            // RST пакет: 40 байт (IP=20 + TCP=20)
            byte[] out = new byte[40];

            // ── IPv4 header ────────────────────────────────────────────────────
            out[0]  = 0x45;               // Version=4, IHL=5
            out[1]  = 0x00;
            out[2]  = 0x00; out[3] = 0x28; // Total length = 40
            out[4]  = 0x00; out[5] = 0x01; // ID
            out[6]  = 0x40; out[7] = 0x00; // DF flag
            out[8]  = 64;                   // TTL
            out[9]  = 6;                    // Protocol = TCP
            out[10] = 0;    out[11] = 0;   // IP checksum placeholder

            // RST идёт от дестинации к источнику (от "сервера" к клиенту)
            out[12] = (byte)(dstIp >>> 24); out[13] = (byte)(dstIp >>> 16);
            out[14] = (byte)(dstIp >>>  8); out[15] = (byte)(dstIp);
            out[16] = (byte)(srcIp >>> 24); out[17] = (byte)(srcIp >>> 16);
            out[18] = (byte)(srcIp >>>  8); out[19] = (byte)(srcIp);

            int ipCsum = DnsPacketBuilder.checksum(out, 0, 20);
            out[10] = (byte)(ipCsum >> 8);
            out[11] = (byte)(ipCsum & 0xFF);

            // ── TCP header ─────────────────────────────────────────────────────
            // Src port = дестинация оригинала (порт сервера: 80 или 443)
            out[20] = (byte)(dstPort >> 8); out[21] = (byte)(dstPort & 0xFF);
            // Dst port = источник оригинала (ephemeral порт клиента)
            out[22] = (byte)(srcPort >> 8); out[23] = (byte)(srcPort & 0xFF);

            // SEQ = 0 (для RST допустимо)
            out[24] = 0; out[25] = 0; out[26] = 0; out[27] = 0;

            // ACK = входящий SEQ + 1
            long ack = (inSeq + 1) & 0xFFFFFFFFL;
            out[28] = (byte)(ack >>> 24); out[29] = (byte)(ack >>> 16);
            out[30] = (byte)(ack >>>  8); out[31] = (byte)(ack);

            out[32] = 0x50;        // Data offset = 5 (20 bytes), reserved = 0
            out[33] = 0x14;        // Flags: ACK=1, RST=1 (0x14)
            out[34] = 0x00; out[35] = 0x00; // Window size = 0
            out[36] = 0;    out[37] = 0;    // TCP checksum placeholder
            out[38] = 0;    out[39] = 0;    // Urgent pointer

            // TCP checksum с pseudo-header
            int tcpCsum = tcpChecksum(out, 12, 16, 20, 20);
            out[36] = (byte)(tcpCsum >> 8);
            out[37] = (byte)(tcpCsum & 0xFF);

            return out;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * TCP checksum = pseudo-header (src IP, dst IP, proto, tcp len) + TCP segment.
     *
     * @param pkt    полный пакет (IP+TCP)
     * @param srcOff offset начала src IP в pkt (обычно 12)
     * @param dstOff offset начала dst IP в pkt (обычно 16)
     * @param tcpOff offset начала TCP header
     * @param tcpLen длина TCP segment в байтах
     */
    static int tcpChecksum(byte[] pkt, int srcOff, int dstOff, int tcpOff, int tcpLen) {
        int sum = 0;
        // Pseudo-header: src IP
        sum += ((pkt[srcOff]     & 0xFF) << 8) | (pkt[srcOff + 1] & 0xFF);
        sum += ((pkt[srcOff + 2] & 0xFF) << 8) | (pkt[srcOff + 3] & 0xFF);
        // dst IP
        sum += ((pkt[dstOff]     & 0xFF) << 8) | (pkt[dstOff + 1] & 0xFF);
        sum += ((pkt[dstOff + 2] & 0xFF) << 8) | (pkt[dstOff + 3] & 0xFF);
        // Protocol = 6 (TCP), TCP length
        sum += 6;
        sum += tcpLen;
        // TCP header + data
        int i = tcpOff;
        while (i < tcpOff + tcpLen - 1) {
            sum += ((pkt[i] & 0xFF) << 8) | (pkt[i + 1] & 0xFF);
            i += 2;
        }
        if ((tcpLen & 1) == 1) sum += (pkt[tcpOff + tcpLen - 1] & 0xFF) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xFFFF) + (sum >> 16);
        return ~sum & 0xFFFF;
    }
}
