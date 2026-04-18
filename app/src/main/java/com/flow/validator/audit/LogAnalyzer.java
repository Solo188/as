package com.flow.validator.audit;

import android.util.Log;

import com.flow.validator.util.AhoCorasick;
import com.flow.validator.util.CircularLogBuffer;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * LogAnalyzer — High-speed real-time log intelligence engine.
 *
 * BUG FIX: утечка Process в readLoop() исправлена — Process теперь
 * закрывается в finally. Также исправлена утечка FD при exec("logcat -c").
 *
 * ПРИМЕЧАНИЕ: READ_LOGS требует системного разрешения на Android 8+.
 * Без него logcat процесс запустится, но вернёт пустой вывод.
 * injectFilteredEvent() работает всегда и не зависит от logcat.
 */
public final class LogAnalyzer {

    private static final String TAG = "LogAnalyzer";
    public  static final int    BUFFER_CAPACITY = 512;

    // -------------------------------------------------------------------------
    // Pattern definitions — LOWERCASE для case-insensitive matching
    // -------------------------------------------------------------------------
    private static final String[] PATTERNS = {
            // Ad SDKs
            "admob", "adrequest", "rewardedinterstitial", "interstitialad",
            "unityads", "unity rewarded",
            "applovin", "mrecad",
            // Reward / verify signals
            "ads/verify", "adsterms", "get_reward", "/v1/verify",
            "rewarded", "reward_granted",
            // Analytics SDKs
            "analytics", "firebaseanalytics", "amplitude", "mixpanel",
            "segment.io", "braze", "clevertap",
            // Error / crash telemetry
            "crashlytics", "sentry", "bugsnag",
            // Generic ad indicators
            "adsense", "dfp", "doubleclick", "mopub"
    };

    private static final AhoCorasick AUTOMATON = AhoCorasick.build(PATTERNS);

    // -------------------------------------------------------------------------
    // Listener API
    // -------------------------------------------------------------------------

    public interface DetectionListener {
        void onDetected(String logLine, int patternIdx, String patternName);
    }

    private final CopyOnWriteArrayList<DetectionListener> listeners
            = new CopyOnWriteArrayList<>();

    private final CircularLogBuffer buffer = new CircularLogBuffer(BUFFER_CAPACITY);

    private Thread          logThread;
    private volatile boolean isRunning = false;

    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    public LogAnalyzer() {}

    public LogAnalyzer(DetectionListener listener) {
        addListener(listener);
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    public void addListener(DetectionListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(DetectionListener listener) {
        listeners.remove(listener);
    }

    /**
     * Inject a synthetic audit event directly (from VPN filter layer).
     * Работает без READ_LOGS разрешения — не зависит от logcat.
     */
    public void injectFilteredEvent(String eventLine) {
        buffer.add(eventLine);
        dispatchToListeners(eventLine, -1, "VPN_FILTER");
    }

    public List<String> latestEvents(int n) {
        return buffer.latestN(n);
    }

    public List<String> allEvents() {
        return buffer.snapshot();
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    public void start() {
        if (isRunning) return;
        isRunning = true;
        logThread = new Thread(this::readLoop, "loganalyzer-reader");
        logThread.setDaemon(true);
        logThread.setPriority(Thread.MIN_PRIORITY + 1);
        logThread.start();
        Log.i(TAG, "LogAnalyzer started | patterns=" + PATTERNS.length);
    }

    public void stop() {
        isRunning = false;
        if (logThread != null) {
            logThread.interrupt();
            logThread = null;
        }
    }

    // -------------------------------------------------------------------------
    // Logcat reader loop
    // BUG FIX: Process закрывается в finally блоке → нет утечки FD
    // BUG FIX: "logcat -c" — Process корректно закрывается
    // -------------------------------------------------------------------------

    private void readLoop() {
        // FIX: корректно закрываем процесс очистки логов
        try {
            Process clearProc = Runtime.getRuntime().exec("logcat -c");
            try { clearProc.waitFor(); } catch (InterruptedException ignored) {}
            clearProc.destroy();
        } catch (Exception e) {
            Log.w(TAG, "logcat -c failed (normal without READ_LOGS): " + e.getMessage());
        }

        Process logcatProcess = null;
        try {
            logcatProcess = Runtime.getRuntime().exec(
                    new String[]{"logcat", "-v", "brief", "-b", "main", "-b", "system"});

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(logcatProcess.getInputStream()), 8192);

            String line;
            while (isRunning && !Thread.currentThread().isInterrupted()
                    && (line = reader.readLine()) != null) {
                inspectLine(line);
            }
        } catch (java.io.IOException e) {
            if (isRunning) Log.w(TAG, "logcat unavailable (need READ_LOGS): " + e.getMessage());
        } catch (Exception e) {
            if (isRunning) Log.e(TAG, "readLoop error: " + e.getMessage());
        } finally {
            // FIX: всегда уничтожаем процесс чтобы освободить FD
            if (logcatProcess != null) {
                logcatProcess.destroy();
            }
        }
    }

    private void inspectLine(String line) {
        String lower = line.toLowerCase();
        List<Integer> hits = AUTOMATON.search(lower);
        if (hits.isEmpty()) return;

        int    firstIdx = hits.get(0);
        String firstPat = PATTERNS[firstIdx];
        String formatted = "[AC-HIT:" + firstPat + "] " + line;

        buffer.add(formatted);
        dispatchToListeners(formatted, firstIdx, firstPat);
    }

    private void dispatchToListeners(String line, int idx, String pattern) {
        for (DetectionListener l : listeners) {
            try {
                l.onDetected(line, idx, pattern);
            } catch (Exception e) {
                Log.e(TAG, "Listener error: " + e.getMessage());
            }
        }
    }

    public static String[] getPatterns() {
        return PATTERNS.clone();
    }
}
