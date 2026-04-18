package com.flow.validator.mitm;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

/**
 * StreamInspector -- HTTP/1.x request parser and mock injection engine.
 *
 * Operates on the decrypted plaintext byte stream from MitmProxy after a
 * successful TLS handshake. Reads one HTTP request at a time, checks the
 * URI against the intercept table, and either:
 *
 *   INTERCEPTS -- suppresses the original request and writes a hardcoded
 *   HTTP/1.1 200 OK mock response directly to the client output stream.
 *
 *   RELAYS -- forwards the request bytes verbatim to the upstream server
 *   output stream and pipes the response back.
 *
 * Intercept targets (exact URI path match):
 *   /v1/verify
 *   /get_reward
 *   /complete_task
 *   /ads/v2/callback
 *   /v[0-9]+/verify  (any version segment)
 *   /reward variants
 *
 * Mock response body: {"status":"success","reward_granted":true}
 *
 * Threading: stateless -- multiple threads may call
 * inspect() concurrently for different connections without synchronization.
 */
public final class StreamInspector {

    private static final String TAG = "StreamInspector";

    // Mock response injected when a URI is intercepted
    // Body: {"status":"success","reward_granted":true}  (42 bytes)
    private static final String MOCK_BODY   = "{\"status\":\"success\",\"reward_granted\":true}";
    private static final byte[] MOCK_RESPONSE;

    static {
        String header = "HTTP/1.1 200 OK\r\n"
                + "Content-Type: application/json; charset=utf-8\r\n"
                + "Content-Length: " + MOCK_BODY.length() + "\r\n"
                + "Cache-Control: no-store\r\n"
                + "X-Sentinel: intercepted\r\n"
                + "Connection: keep-alive\r\n"
                + "\r\n"
                + MOCK_BODY;
        MOCK_RESPONSE = header.getBytes(StandardCharsets.UTF_8);
    }

    // Intercept table -- exact paths (fast lookup before regex)
    private static final List<String> EXACT_PATHS = Arrays.asList(
            "/v1/verify",
            "/get_reward",
            "/complete_task",
            "/ads/v2/callback",
            "/reward",
            "/verify",
            "/claim_reward",
            "/task_complete",
            "/ad_complete",
            "/offerwall/complete"
    );

    // Regex patterns for URIs that don't match exactly
    private static final Pattern[] REGEX_PATTERNS = {
            Pattern.compile("^/v\\d+/verify.*",        Pattern.CASE_INSENSITIVE),
            Pattern.compile("^/reward[s]?(/.*)?$",     Pattern.CASE_INSENSITIVE),
            Pattern.compile("^/ads?/.*callback.*",     Pattern.CASE_INSENSITIVE),
            Pattern.compile("^/complete[_/]task.*",    Pattern.CASE_INSENSITIVE),
            Pattern.compile("^/.*verify[_\\-]?reward", Pattern.CASE_INSENSITIVE),
    };

    // Max bytes to buffer per request line/header before giving up
    private static final int MAX_LINE_BYTES   = 8192;
    private static final int MAX_HEADER_COUNT = 64;
    // Buffer size for relay pipe
    private static final int RELAY_BUF_SIZE   = 32768;

    // Singleton
    private static final StreamInspector INSTANCE = new StreamInspector();
    public static StreamInspector getInstance() { return INSTANCE; }
    private StreamInspector() {}

    /**
     * Inspect one HTTP/1.x request from clientIn and either inject a mock
     * response to clientOut or relay the request to serverOut.
     *
     * @param clientIn  Decrypted bytes arriving from the client app.
     * @param clientOut Bytes sent back to the client app.
     * @param serverOut Bytes forwarded to the real upstream server.
     * @param hostname  Hostname of the upstream server (for logging).
     * @return true if the request was intercepted, false if relayed.
     */
    public boolean inspect(InputStream  clientIn,
                           OutputStream clientOut,
                           OutputStream serverOut,
                           String       hostname) {
        try {
            // 1. Read request line
            String requestLine = readLine(clientIn);
            if (requestLine == null || requestLine.isEmpty()) return false;

            // 2. Parse method + path
            String[] parts = requestLine.split(" ", 3);
            if (parts.length < 2) {
                relay(requestLine, clientIn, serverOut);
                return false;
            }
            String method  = parts[0];
            String fullUri = parts[1];
            String path    = extractPath(fullUri);

            Log.d(TAG, "Inspecting: " + method + " " + path + " @" + hostname);

            // 3. Read all headers (need Content-Length for body skip)
            StringBuilder rawHeaders = new StringBuilder();
            int contentLength = 0;
            int headerCount   = 0;
            String line;
            while ((line = readLine(clientIn)) != null && !line.isEmpty()) {
                rawHeaders.append(line).append("\r\n");
                String lower = line.toLowerCase();
                if (lower.startsWith("content-length:")) {
                    try {
                        contentLength = Integer.parseInt(line.split(":", 2)[1].trim());
                    } catch (NumberFormatException ignored) {}
                }
                if (++headerCount > MAX_HEADER_COUNT) break;
            }

            // 4. Intercept check
            if (shouldIntercept(path)) {
                // Skip request body if present
                if (contentLength > 0) skipBytes(clientIn, contentLength);
                // Write mock response to client
                clientOut.write(MOCK_RESPONSE);
                clientOut.flush();
                Log.i(TAG, "INTERCEPTED: " + method + " " + path
                        + " | host=" + hostname + " | mock=reward_granted");
                return true;
            }

            // 5. Relay -- forward original request to server
            String fullRequest = requestLine + "\r\n" + rawHeaders + "\r\n";
            serverOut.write(fullRequest.getBytes(StandardCharsets.ISO_8859_1));
            if (contentLength > 0) {
                pipeBytes(clientIn, serverOut, contentLength);
            }
            serverOut.flush();
            return false;

        } catch (Exception e) {
            Log.e(TAG, "Inspect error: " + e.getMessage());
            return false;
        }
    }

    /**
     * Pipe bytes from upstream (server response) back to clientOut
     * until the connection closes. Uses a 32 KB relay buffer.
     */
    public void pipeResponse(InputStream upstream, OutputStream clientOut) {
        byte[] buf = new byte[RELAY_BUF_SIZE];
        try {
            int n;
            while ((n = upstream.read(buf)) != -1) {
                clientOut.write(buf, 0, n);
                clientOut.flush();
            }
        } catch (Exception ignored) {
            // Connection closed by either side -- expected
        }
    }

    // URI matching helpers

    private boolean shouldIntercept(String path) {
        if (path == null || path.isEmpty()) return false;
        for (String exact : EXACT_PATHS) {
            if (path.equalsIgnoreCase(exact)
                    || path.toLowerCase().startsWith(exact.toLowerCase())) {
                return true;
            }
        }
        for (Pattern p : REGEX_PATTERNS) {
            if (p.matcher(path).find()) return true;
        }
        return false;
    }

    private static String extractPath(String uri) {
        if (uri == null) return "";
        int q = uri.indexOf('?');
        int f = uri.indexOf('#');
        int end = uri.length();
        if (q > 0 && q < end) end = q;
        if (f > 0 && f < end) end = f;
        int slashSlash = uri.indexOf("//");
        if (slashSlash >= 0) {
            int pathStart = uri.indexOf('/', slashSlash + 2);
            if (pathStart > 0) return uri.substring(pathStart, end);
        }
        return uri.substring(0, end);
    }

    // Stream I/O helpers

    /** Read one CRLF-terminated line from the stream. Returns null on EOF. */
    private static String readLine(InputStream in) throws IOException {
        StringBuilder sb   = new StringBuilder(128);
        int           prev = -1;
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\n' && prev == '\r') {
                if (sb.length() > 0) sb.setLength(sb.length() - 1);
                return sb.toString();
            }
            sb.append((char) b);
            prev = b;
            if (sb.length() > MAX_LINE_BYTES) break;
        }
        return sb.length() > 0 ? sb.toString() : null;
    }

    /** Skip exactly n bytes from in. */
    private static void skipBytes(InputStream in, int n) throws IOException {
        long remaining = n;
        while (remaining > 0) {
            long skipped = in.skip(remaining);
            if (skipped <= 0) break;
            remaining -= skipped;
        }
    }

    /** Copy exactly n bytes from in to out. */
    private static void pipeBytes(InputStream in, OutputStream out, int n)
            throws IOException {
        byte[] buf       = new byte[Math.min(n, 8192)];
        int    remaining = n;
        while (remaining > 0) {
            int chunk = in.read(buf, 0, Math.min(buf.length, remaining));
            if (chunk < 0) break;
            out.write(buf, 0, chunk);
            remaining -= chunk;
        }
    }

    /** Fallback relay for unrecognisable request lines. */
    private void relay(String firstLine,
                       InputStream  clientIn,
                       OutputStream serverOut) throws IOException {
        serverOut.write((firstLine + "\r\n").getBytes(StandardCharsets.ISO_8859_1));
        pipeResponse(clientIn, serverOut);
    }
}
