package com.flow.validator.util;

import android.util.Log;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.atomic.AtomicLong;

/**
 * SentinelLog — async, non-blocking logger for the hot path.
 *
 * The VPN/MITM read loop MUST NOT block on I/O. SentinelLog uses a
 * single background thread draining an ArrayBlockingQueue — the caller
 * does a non-blocking offer() and moves on immediately.
 *
 * Prefixes:
 *   [HIT]  — blocked domain/URL (pattern match)
 *   [SSL]  — TLS handshake info (hostname, cipher)
 *   [PERF] — nanosecond timing for one operation
 *   [W]    — warnings (non-fatal errors)
 *   [I]    — info
 */
public final class SentinelLog {

    private static final String TAG   = "Sentinel";
    private static final int    QUEUE = 2048; // drop when overwhelmed

    // Single bounded queue — offer() never blocks
    private static final ArrayBlockingQueue<String> QUEUE_REF =
            new ArrayBlockingQueue<>(QUEUE);

    // Counters
    private static final AtomicLong dropped = new AtomicLong(0);
    private static volatile boolean debug   = false;

    static {
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    String msg = QUEUE_REF.take(); // blocks only when idle
                    Log.d(TAG, msg);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "sentinel-log");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
    }

    private SentinelLog() {}

    public static void setDebug(boolean on) { debug = on; }

    // ── Public API ─────────────────────────────────────────────────────────

    /** [HIT] blocked domain/URL — byte[] version, no String allocation. */
    public static void hit(String type, byte[] buf, int off, int len) {
        if (!debug) return;
        enqueue("[HIT][" + type + "] " + ascii(buf, off, len));
    }

    /** [HIT] blocked domain/URL — String version for DNS/SNI. */
    public static void hit(String type, String value) {
        if (!debug) return;
        enqueue("[HIT][" + type + "] " + value);
    }

    /** [SSL] TLS handshake info. */
    public static void ssl(String hostname, String cipher) {
        if (!debug) return;
        enqueue("[SSL] " + hostname + " cipher=" + cipher);
    }

    /** [PERF] nanosecond timing. */
    public static void perf(String op, long nanos) {
        if (!debug) return;
        enqueue("[PERF][" + op + "] " + nanos + "ns");
    }

    /** Warning — always logged regardless of debug flag. */
    public static void w(String tag, String msg) {
        // Warnings go to logcat directly (they're infrequent)
        Log.w(TAG, "[W][" + tag + "] " + msg);
    }

    /** Info — always logged. */
    public static void i(String tag, String msg) {
        Log.i(TAG, "[I][" + tag + "] " + msg);
    }

    // ── Internals ──────────────────────────────────────────────────────────

    private static void enqueue(String msg) {
        if (!QUEUE_REF.offer(msg)) {
            // Queue full — caller is overwhelmed; count drops silently
            dropped.incrementAndGet();
        }
    }

    private static String ascii(byte[] buf, int off, int len) {
        return new String(buf, off, Math.min(len, 128), StandardCharsets.US_ASCII);
    }

    public static long getDropCount() { return dropped.get(); }
}
