package com.flow.validator.util;

import java.util.ArrayList;
import java.util.List;

/**
 * CircularLogBuffer — Lock-free ring buffer for audit log strings.
 *
 * <p>Fixed-capacity, overwrite-on-full semantics. Newest entries are kept
 * when the buffer wraps. All operations are O(1) except {@link #snapshot()}.
 *
 * <p>Thread-safety: uses {@code synchronized} on the object monitor so
 * concurrent writer threads (VpnService, LogAnalyzer) and a single UI reader
 * can operate without data corruption.
 */
public final class CircularLogBuffer {

    private final String[] buf;
    private final int      capacity;
    private int            head;   // next write position
    private int            count;  // number of valid entries

    public CircularLogBuffer(int capacity) {
        if (capacity <= 0) throw new IllegalArgumentException("capacity must be > 0");
        this.capacity = capacity;
        this.buf      = new String[capacity];
    }

    /** Append a log line. Overwrites the oldest entry when full. */
    public synchronized void add(String line) {
        buf[head] = line;
        head = (head + 1) % capacity;
        if (count < capacity) count++;
    }

    /**
     * Snapshot the buffer contents in insertion order (oldest → newest).
     *
     * @return New list; safe to iterate outside synchronization.
     */
    public synchronized List<String> snapshot() {
        List<String> result = new ArrayList<>(count);
        if (count < capacity) {
            // Buffer not yet wrapped — entries are 0..count-1
            for (int i = 0; i < count; i++) {
                result.add(buf[i]);
            }
        } else {
            // Wrapped — oldest entry is at 'head'
            for (int i = 0; i < capacity; i++) {
                result.add(buf[(head + i) % capacity]);
            }
        }
        return result;
    }

    /** Most recent N entries, newest-first (suitable for UI display). */
    public synchronized List<String> latestN(int n) {
        int take = Math.min(n, count);
        List<String> result = new ArrayList<>(take);
        // Walk backwards from (head-1)
        for (int i = 0; i < take; i++) {
            int idx = (head - 1 - i + capacity) % capacity;
            result.add(buf[idx]);
        }
        return result;
    }

    public synchronized int size()     { return count; }
    public synchronized void clear()   { head = 0; count = 0; }
}
