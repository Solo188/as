package com.flow.validator.util;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongArray;

/**
 * LatencyTracker — nanosecond-resolution per-packet latency measurement.
 *
 * BUG FIX: заменён samples[] на AtomicLongArray для thread-safe доступа
 * из нескольких ForkJoinPool потоков без data race на ARM.
 * (оригинальный long[] давал torn reads/writes на 64-bit значениях)
 */
public final class LatencyTracker {

    private static final int WINDOW_SIZE = 256; // степень двойки для быстрого маскирования

    // FIX: AtomicLongArray вместо long[] — thread-safe без lock
    private final AtomicLongArray samples  = new AtomicLongArray(WINDOW_SIZE);
    private final AtomicInteger   writePos = new AtomicInteger(0);
    private final AtomicInteger   filled   = new AtomicInteger(0);
    private final AtomicLong      totalNs  = new AtomicLong(0);

    // ThreadLocal start time — без аллокаций, работает с несколькими воркерами
    private final ThreadLocal<Long> startNs = ThreadLocal.withInitial(() -> 0L);

    /** Отметить начало обработки пакета. */
    public void begin() {
        startNs.set(System.nanoTime());
    }

    /** Отметить конец обработки и записать сэмпл. */
    public void end() {
        long elapsed = System.nanoTime() - startNs.get();
        int pos = writePos.getAndIncrement() & (WINDOW_SIZE - 1);
        // FIX: AtomicLongArray.getAndSet() — атомарная операция
        long old = samples.getAndSet(pos, elapsed);
        totalNs.addAndGet(elapsed - old);
        if (filled.get() < WINDOW_SIZE) filled.incrementAndGet();
    }

    /** Среднее за последние WINDOW_SIZE сэмплов, в микросекундах. */
    public double averageUs() {
        int n = Math.max(1, filled.get());
        return (totalNs.get() / (double) n) / 1_000.0;
    }

    /** Среднее в миллисекундах. */
    public double averageMs() {
        return averageUs() / 1_000.0;
    }

    /** Пиковая задержка в текущем окне, в микросекундах. */
    public double peakUs() {
        long max = 0;
        int n = filled.get();
        for (int i = 0; i < n; i++) {
            long v = samples.get(i);
            if (v > max) max = v;
        }
        return max / 1_000.0;
    }

    /** Строка для UI: "avg 0.123 ms | peak 0.456 ms". */
    public String summary() {
        return String.format("avg %.3f ms | peak %.3f ms",
                averageMs(), peakUs() / 1_000.0);
    }
}
