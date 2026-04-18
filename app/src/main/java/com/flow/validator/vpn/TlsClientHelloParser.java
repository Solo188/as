package com.flow.validator.vpn;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * TlsClientHelloParser — парсит SNI из TLS ClientHello без SSL handshake.
 *
 * Формат TLS record:
 *   Byte 0:     Content Type (0x16 = Handshake)
 *   Byte 1-2:   Protocol Version (0x0301..0x0303)
 *   Byte 3-4:   Record Length
 *   Byte 5:     Handshake Type (0x01 = ClientHello)
 *   ...
 *   Extensions → SNI extension type 0x0000
 *
 * Этот парсер работает на сырых TCP payload байтах из TUN.
 * Не зависит от javax.net.ssl — нет handshake, только read.
 */
public final class TlsClientHelloParser {

    private TlsClientHelloParser() {}

    /**
     * Извлекает SNI hostname из TLS ClientHello в TCP payload пакета.
     *
     * @param pkt IPv4 пакет (полный, с IP и TCP заголовками)
     * @return hostname или null если не TLS ClientHello / SNI отсутствует
     */
    public static String extractSni(ByteBuffer pkt) {
        try {
            int tcpPayloadOff = PacketParser.tcpPayloadOffset(pkt);
            int remaining     = pkt.limit() - tcpPayloadOff;
            if (remaining < 5) return null;

            // TLS Record header
            int contentType = pkt.get(tcpPayloadOff) & 0xFF;
            if (contentType != 0x16) return null; // не Handshake

            int versionMajor = pkt.get(tcpPayloadOff + 1) & 0xFF;
            int versionMinor = pkt.get(tcpPayloadOff + 2) & 0xFF;
            // Допустимые версии: TLS 1.0(0x0301), 1.1(0x0302), 1.2(0x0303), 1.3(0x0304)
            if (versionMajor != 0x03 || versionMinor < 0x01 || versionMinor > 0x04) return null;

            int recordLen = ((pkt.get(tcpPayloadOff + 3) & 0xFF) << 8)
                           | (pkt.get(tcpPayloadOff + 4) & 0xFF);
            if (remaining < 5 + recordLen) return null;

            // Handshake header (offset 5 от TLS record начала)
            int hsOff = tcpPayloadOff + 5;
            if (hsOff >= pkt.limit()) return null;

            int hsType = pkt.get(hsOff) & 0xFF;
            if (hsType != 0x01) return null; // не ClientHello

            // Handshake length (3 байта big-endian)
            if (hsOff + 4 > pkt.limit()) return null;
            int hsLen = ((pkt.get(hsOff + 1) & 0xFF) << 16)
                      | ((pkt.get(hsOff + 2) & 0xFF) << 8)
                      |  (pkt.get(hsOff + 3) & 0xFF);

            // ClientHello начинается с offset 9
            int pos = tcpPayloadOff + 9; // после TLS record(5) + handshake header(4)

            // client_version (2)
            pos += 2;
            // random (32)
            pos += 32;

            if (pos + 1 > pkt.limit()) return null;
            // session_id length (1)
            int sessionIdLen = pkt.get(pos) & 0xFF;
            pos += 1 + sessionIdLen;

            if (pos + 2 > pkt.limit()) return null;
            // cipher_suites length (2)
            int cipherSuitesLen = ((pkt.get(pos) & 0xFF) << 8) | (pkt.get(pos + 1) & 0xFF);
            pos += 2 + cipherSuitesLen;

            if (pos + 1 > pkt.limit()) return null;
            // compression_methods length (1)
            int comprLen = pkt.get(pos) & 0xFF;
            pos += 1 + comprLen;

            if (pos + 2 > pkt.limit()) return null;
            // extensions length (2)
            int extLen = ((pkt.get(pos) & 0xFF) << 8) | (pkt.get(pos + 1) & 0xFF);
            pos += 2;

            int extEnd = pos + extLen;
            // Итерируемся по extensions
            while (pos + 4 <= extEnd && pos + 4 <= pkt.limit()) {
                int extType = ((pkt.get(pos) & 0xFF) << 8) | (pkt.get(pos + 1) & 0xFF);
                int extDataLen = ((pkt.get(pos + 2) & 0xFF) << 8) | (pkt.get(pos + 3) & 0xFF);
                pos += 4;

                if (extType == 0x0000) {
                    // SNI extension (type=0)
                    // server_name_list_length (2)
                    if (pos + 2 > pkt.limit()) return null;
                    // pos + 2 = server_name_type (1) + server_name_length (2) + name
                    if (pos + 5 > pkt.limit()) return null;

                    int nameType = pkt.get(pos + 2) & 0xFF;
                    if (nameType != 0x00) return null; // 0 = host_name

                    int nameLen = ((pkt.get(pos + 3) & 0xFF) << 8) | (pkt.get(pos + 4) & 0xFF);
                    pos += 5;

                    if (pos + nameLen > pkt.limit()) return null;

                    byte[] nameBytes = new byte[nameLen];
                    for (int i = 0; i < nameLen; i++) {
                        nameBytes[i] = pkt.get(pos + i);
                    }
                    return new String(nameBytes, StandardCharsets.US_ASCII).toLowerCase();
                }

                pos += extDataLen;
            }

            return null; // SNI extension не найден
        } catch (Exception e) {
            return null;
        }
    }
}
