package com.flow.validator.mitm;

import com.flow.validator.util.AhoCorasick;
import com.flow.validator.util.SentinelLog;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

/**
 * SSLInterceptor — hot-path filter for decrypted TLS payload.
 *
 * Design:
 *   - filterTraffic(byte[], int) works entirely on the raw byte array —
 *     zero String conversions on the inspection path
 *   - AhoCorasick instance swapped atomically via AtomicReference —
 *     lock-free reads from any number of concurrent connection threads
 *   - Pattern replacement pads to original length with spaces to keep
 *     TCP sequence numbers intact (no RST required)
 *   - Ad-block patterns look for URL substrings in HTTP Host/path headers
 *     and common JS ad tags embedded in HTML payloads
 */
public final class SSLInterceptor {

    private static final byte[] AD_JS_TAG_OPEN  = "<script".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] AD_JS_TAG_CLOSE = "</script>".getBytes(StandardCharsets.US_ASCII);

    // ── URL path substrings that indicate ad/tracker content ─────────────────
    private static final String[] URL_PATTERNS = {
        "/ads/", "/ad/", "/adserve", "/adserver", "/advert", "/banner",
        "/pixel.gif", "/pixel.png", "/track", "/beacon", "/analytics",
        "/collect", "/impression", "/click/", "/hits/",
        "/v1/verify", "/get_reward", "/reward", "/complete_task",
        // JavaScript ad library filenames
        "googletag", "adsense", "doubleclick", "applovin-sdk",
        "unityads", "admob", "mopub", "appsflyer",
    };

    // ── Domain substrings (checked in HTTP Host header) ──────────────────────
    private static final String[] DOMAIN_PATTERNS = {
        "googleads", "doubleclick.net", "googlesyndication",
        "admob.googleapis.com", "unityads.unity3d.com",
        "applovin.com", "an.facebook.com",
        "an.yandex.ru", "bs.yandex.ru", "yandexadexchange.net",
        "mopub.com", "crashlytics.com", "app-measurement.com",
        "google-analytics.com", "appsflyer.com",
        "ironsource.com", "vungle.com", "chartboost.com",
        "adcolony.com", "inmobi.com", "mintegral.com",
    };

    // AtomicReference for lock-free swap when rules are updated at runtime
    private final AtomicReference<AhoCorasick> urlFilter;
    private final AtomicReference<AhoCorasick> domainFilter;

    // Reusable scratch buffer for domain extraction (per-instance, not per-call)
    // SSLInterceptor is one-per-MitmProxyServer, connections run on separate threads
    // — each connection thread calls filterTraffic, so we use ThreadLocal here
    private static final ThreadLocal<byte[]> SCRATCH = ThreadLocal.withInitial(() -> new byte[512]);

    // ─────────────────────────────────────────────────────────────────────────

    public SSLInterceptor() {
        urlFilter    = new AtomicReference<>(AhoCorasick.build(URL_PATTERNS));
        domainFilter = new AtomicReference<>(AhoCorasick.build(DOMAIN_PATTERNS));
    }

    /**
     * Hot-path filter. Called from MitmProxyServer.relay() for every request.
     *
     * Works directly on byte[] — no String allocation.
     * Returns true if the content matches an ad pattern (should be blocked).
     * Modifies buf in-place to erase ad content when detected in HTML body,
     * padding to original length to keep TCP sequence numbers valid.
     *
     * @param buf decrypted HTTP request/response bytes
     * @param len valid byte count in buf
     * @return true = drop / substitute response
     */
    public boolean filterTraffic(byte[] buf, int len) {
        if (len < 8) return false;

        long t0 = System.nanoTime();
        boolean blocked = false;

        // ── 1. Check HTTP Host header (bytes, no String) ──────────────────────
        int hostOff = findHostHeader(buf, len);
        if (hostOff > 0) {
            int hostEnd = hostOff;
            while (hostEnd < len && buf[hostEnd] != '\r' && buf[hostEnd] != '\n') hostEnd++;
            int hostLen = Math.min(hostEnd - hostOff, 253);
            if (hostLen > 0 && domainFilter.get().matchBytes(buf, hostOff, hostLen, true)) {
                SentinelLog.hit("DOMAIN", buf, hostOff, hostLen);
                blocked = true;
            }
        }

        // ── 2. Check URL path in request line ─────────────────────────────────
        if (!blocked) {
            int pathEnd = Math.min(len, 512);
            if (urlFilter.get().matchBytes(buf, 0, pathEnd, true)) {
                SentinelLog.hit("URL", buf, 0, Math.min(64, pathEnd));
                blocked = true;
            }
        }

        // ── 3. Erase <script> ad tags in HTML body (in-place, length-preserving) ──
        if (!blocked) {
            eraseAdScriptTags(buf, len);
        }

        SentinelLog.perf("filter", System.nanoTime() - t0);
        return blocked;
    }

    /**
     * Same as filterTraffic(byte[], int) but accepts a direct ByteBuffer.
     * Reads from buffer position to limit without modifying position.
     */
    public boolean filterTraffic(ByteBuffer data) {
        if (!data.hasArray()) {
            // Direct buffer — copy to thread-local scratch for inspection only
            int len = Math.min(data.remaining(), 4096);
            byte[] tmp = len <= 512 ? SCRATCH.get() : new byte[len];
            int savedPos = data.position();
            data.get(tmp, 0, len);
            data.position(savedPos); // restore — we don't modify ByteBuffer
            return filterTraffic(tmp, len);
        }
        return filterTraffic(data.array(),
                             data.arrayOffset() + data.limit() - data.position());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Rule update — lock-free atomic swap
    // ─────────────────────────────────────────────────────────────────────────

    /** Replace URL patterns at runtime (e.g., after fetching updated blocklist). */
    public void updateUrlPatterns(String[] patterns) {
        urlFilter.set(AhoCorasick.build(patterns));
        SentinelLog.i("SSLInterceptor", "URL patterns updated: " + patterns.length);
    }

    /** Replace domain patterns at runtime. */
    public void updateDomainPatterns(String[] patterns) {
        domainFilter.set(AhoCorasick.build(patterns));
        SentinelLog.i("SSLInterceptor", "domain patterns updated: " + patterns.length);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internals
    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Find the start of the Host header value in an HTTP request.
     * Returns -1 if not found.
     * Case-insensitive, operates on raw bytes.
     */
    private static int findHostHeader(byte[] buf, int len) {
        // Look for "\nHost:" or "\r\nHost:"
        for (int i = 0; i < len - 7; i++) {
            if (buf[i] == '\n'
                    && (buf[i+1] == 'H' || buf[i+1] == 'h')
                    && (buf[i+2] == 'o' || buf[i+2] == 'O')
                    && (buf[i+3] == 's' || buf[i+3] == 'S')
                    && (buf[i+4] == 't' || buf[i+4] == 'T')
                    &&  buf[i+5] == ':') {
                int off = i + 6;
                while (off < len && buf[off] == ' ') off++; // trim leading space
                return off;
            }
        }
        return -1;
    }

    /**
     * Erase <script src="...ad..."> tags in HTML in-place.
     * Replaces tag content with spaces — length preserved, TCP seq unaffected.
     * Only erases script tags whose src attribute matches ad URL patterns.
     */
    private void eraseAdScriptTags(byte[] buf, int len) {
        AhoCorasick uf = urlFilter.get();
        int i = 0;
        while (i < len - AD_JS_TAG_OPEN.length) {
            // Find "<script"
            if (!matchAt(buf, i, AD_JS_TAG_OPEN)) { i++; continue; }

            int tagStart = i;
            // Find end of opening tag ">"
            int tagEnd = i + AD_JS_TAG_OPEN.length;
            while (tagEnd < len && buf[tagEnd] != '>') tagEnd++;
            if (tagEnd >= len) break;

            // Check if src= within this tag matches an ad pattern
            boolean isAd = uf.matchBytes(buf, tagStart, tagEnd - tagStart + 1, true);
            if (isAd) {
                // Find </script>
                int closeIdx = indexOfBytes(buf, tagEnd, len, AD_JS_TAG_CLOSE);
                int eraseEnd = (closeIdx >= 0)
                    ? closeIdx + AD_JS_TAG_CLOSE.length
                    : Math.min(tagEnd + 1024, len); // cap at 1 KB if no close tag

                // Overwrite with spaces — length unchanged
                java.util.Arrays.fill(buf, tagStart, eraseEnd, (byte) ' ');
                SentinelLog.hit("SCRIPT-ERASE", buf, tagStart, Math.min(64, eraseEnd - tagStart));
                i = eraseEnd;
            } else {
                i = tagEnd + 1;
            }
        }
    }

    private static boolean matchAt(byte[] buf, int off, byte[] pattern) {
        if (off + pattern.length > buf.length) return false;
        for (int i = 0; i < pattern.length; i++) {
            if ((buf[off + i] | 0x20) != (pattern[i] | 0x20)) return false; // case-insensitive
        }
        return true;
    }

    private static int indexOfBytes(byte[] buf, int from, int len, byte[] pattern) {
        outer:
        for (int i = from; i <= len - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if ((buf[i + j] | 0x20) != (pattern[j] | 0x20)) continue outer;
            }
            return i;
        }
        return -1;
    }
}
