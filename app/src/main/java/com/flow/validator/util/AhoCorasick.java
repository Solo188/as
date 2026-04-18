package com.flow.validator.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Queue;

/**
 * AhoCorasick — многопаттерновый поиск за O(n) по тексту/байтам.
 *
 * ПОТОКОБЕЗОПАСНОСТЬ:
 *   После построения автомат полностью иммутабелен (все поля final).
 *   Любое количество потоков может вызывать containsAny/matchBytes/search
 *   одновременно без синхронизации — нет shared mutable state на горячем пути.
 *   Единственный mutable state — volatile-ссылка в AdFilter.instance,
 *   защищённая double-checked locking при записи.
 *
 * ZERO-COPY HOT PATH:
 *   matchBytes(byte[], off, len, toLower) — работает прямо по byte[],
 *   без создания String, без аллокаций. Используй его из VPN read-loop.
 *
 *   containsAny(String) — создаёт charAt итерацию, без аллокаций.
 *
 * ПОСТРОЕНИЕ (вне hot path, однократно):
 *   - build(String[])              — из массива паттернов
 *   - AdFilter.initDefault()       — предустановленный рекламный набор
 *   - AdFilter.loadFromStream(is)  — загрузка из файла/assets (по одному домену в строке)
 *   - AdFilter.addPatterns(extra)  — динамическое добавление паттернов
 */
public final class AhoCorasick {

    // Размер алфавита — только printable ASCII (0..127).
    // Символы >= 128 (multibyte UTF-8) принудительно маппятся в 0 (root),
    // что безопасно: паттерны доменов никогда не содержат non-ASCII.
    private static final int ALPHA = 128;

    // Все поля final → объект иммутабелен после построения → thread-safe reads без lock
    private final int[][] go;      // go[state][char] → next_state
    private final int[]   fail;    // fail[state]     → fallback_state  (suffix link)
    private final int[][] output;  // output[state]   → int[] matched pattern indices
    private final int     size;    // количество реально используемых состояний

    private AhoCorasick(int[][] go, int[] fail, int[][] output, int size) {
        this.go     = go;
        this.fail   = fail;
        this.output = output;
        this.size   = size;
    }

    // =========================================================================
    // Builder
    // =========================================================================

    /**
     * Построить автомат из массива паттернов.
     *
     * Все паттерны должны быть в нижнем регистре (matching регистрозависимый).
     * Null-паттерны и пустые строки игнорируются.
     * Вызов не потокобезопасен — выполняй однократно при инициализации.
     *
     * @param patterns массив строк для поиска, lowercase
     * @return иммутабельный автомат, безопасный для многопоточного чтения
     */
    public static AhoCorasick build(String[] patterns) {
        // Верхняя оценка состояний: сумма длин всех паттернов + корень
        int maxStates = 1;
        for (String p : patterns) {
            if (p != null && !p.isEmpty()) maxStates += p.length();
        }

        int[][] go   = new int[maxStates][ALPHA];
        int[]   fail = new int[maxStates];
        // Используем List<List> только при построении — на hot path не попадёт
        List<List<Integer>> out = new ArrayList<>(maxStates);

        for (int i = 0; i < maxStates; i++) {
            java.util.Arrays.fill(go[i], 0); // 0 = root, безопаснее чем -1 для runtime
            out.add(new ArrayList<>(2));
        }
        // Явно помечаем "не инициализировано" как отдельное значение при построении
        // Используем -1 временно, потом заменяем на go[fail][c] в фазе 2
        for (int i = 0; i < maxStates; i++) java.util.Arrays.fill(go[i], -1);

        // ── Фаза 1: строим trie ────────────────────────────────────────────────
        int stateCount = 1; // state 0 = root
        for (int pi = 0; pi < patterns.length; pi++) {
            String p = patterns[pi];
            if (p == null || p.isEmpty()) continue;
            int cur = 0;
            for (int ci = 0; ci < p.length(); ci++) {
                int c = p.charAt(ci) & 0x7F; // маскируем в [0, 127]
                if (go[cur][c] == -1) go[cur][c] = stateCount++;
                cur = go[cur][c];
            }
            out.get(cur).add(pi);
        }

        // ── Фаза 2: fail-links (BFS из корня) ────────────────────────────────
        Queue<Integer> q = new ArrayDeque<>(stateCount);
        // Дочерние корня: fail → 0, остальные переходы корня → 0
        for (int c = 0; c < ALPHA; c++) {
            if (go[0][c] == -1) {
                go[0][c] = 0; // нет перехода из корня → остаёмся в корне
            } else {
                fail[go[0][c]] = 0;
                q.add(go[0][c]);
            }
        }
        while (!q.isEmpty()) {
            int u = q.poll();
            // Наследуем output fail-состояния (suffix link outputs)
            out.get(u).addAll(out.get(fail[u]));
            for (int c = 0; c < ALPHA; c++) {
                if (go[u][c] == -1) {
                    // Нет перехода → используем goto fail-состояния (сжатый trie)
                    go[u][c] = go[fail[u]][c];
                } else {
                    fail[go[u][c]] = go[fail[u]][c];
                    q.add(go[u][c]);
                }
            }
        }

        // ── Материализация output в int[][] (нет List на hot path) ───────────
        int[][] outputArr = new int[stateCount][];
        for (int i = 0; i < stateCount; i++) {
            List<Integer> lst = out.get(i);
            outputArr[i] = new int[lst.size()];
            for (int j = 0; j < lst.size(); j++) outputArr[i][j] = lst.get(j);
        }

        return new AhoCorasick(go, fail, outputArr, stateCount);
    }

    // =========================================================================
    // Hot path — search API (все методы thread-safe, нет аллокаций)
    // =========================================================================

    /**
     * Проверяет byte[] на наличие хотя бы одного паттерна.
     * Early-exit при первом совпадении.
     *
     * ZERO ALLOCATION: никаких объектов не создаётся, только примитивные операции.
     * Вызывай из VPN read-loop напрямую по packet buffer.
     *
     * @param buf     буфер с данными
     * @param off     смещение начала сканируемого диапазона
     * @param len     длина сканируемого диапазона в байтах
     * @param toLower если true — ASCII-буквы A-Z приводятся к a-z на лету
     * @return true если найдено совпадение
     */
    public boolean matchBytes(byte[] buf, int off, int len, boolean toLower) {
        final int[][] g = this.go;      // локальные ссылки — JIT может убрать
        final int[][] o = this.output;  // повторную разыменовку поля
        int cur = 0;
        final int end = off + len;
        for (int i = off; i < end; i++) {
            int c = buf[i] & 0x7F;
            // Брanchless lower-case: если A≤c≤Z добавляем 32, иначе 0
            if (toLower && c >= 'A' && c <= 'Z') c |= 0x20;
            cur = g[cur][c];
            if (o[cur].length > 0) return true; // early exit
        }
        return false;
    }

    /**
     * Проверяет String — ноль аллокаций (charAt итерация, нет копий).
     * Строка должна быть в нижнем регистре если паттерны lowercase.
     */
    public boolean containsAny(String text) {
        final int[][] g = this.go;
        final int[][] o = this.output;
        int cur = 0;
        for (int i = 0, len = text.length(); i < len; i++) {
            cur = g[cur][text.charAt(i) & 0x7F];
            if (o[cur].length > 0) return true;
        }
        return false;
    }

    /**
     * Полный поиск всех совпадений с позициями.
     * Только для аудита/отладки — аллоцирует List.
     */
    public List<int[]> searchAll(String text) {
        List<int[]> results = new ArrayList<>();
        int cur = 0;
        for (int i = 0, len = text.length(); i < len; i++) {
            cur = go[cur][text.charAt(i) & 0x7F];
            for (int patIdx : output[cur]) {
                results.add(new int[]{patIdx, i});
            }
        }
        return results;
    }

    /** @return количество состояний автомата (для диагностики) */
    public int stateCount() { return size; }

    // =========================================================================
    // AdFilter — singleton с предустановленными рекламными паттернами
    // =========================================================================

    /**
     * AdFilter управляет единственным экземпляром AhoCorasick для фильтрации рекламы.
     *
     * Паттерны выбраны как подстроки доменов второго уровня:
     * "doubleclick.net" поймает любой поддомен автоматически.
     *
     * THREAD SAFETY: get() и все read-методы автомата — thread-safe.
     * addPatterns()/loadFromStream() — синхронизированы, пересоздают автомат атомарно.
     */
    public static final class AdFilter {

        /**
         * Дефолтные паттерны — подстроки доменов в нижнем регистре.
         * Покрывают Google Ads, Unity, AppLovin, Yandex, Facebook/Meta,
         * Crashlytics, MoPub, IronSource, Vungle, AppFlyer и другие.
         */
        private static final String[] DEFAULT_PATTERNS = {
            // ── Google Ads ────────────────────────────────────────────────────
            "googleads",          // googleads.g.doubleclick.net и любые googleads.*
            "doubleclick.net",    // pagead.googlesyndication через doubleclick
            "admob.googleapis.com",
            "pagead2.googlesyndication.com",
            "adservice.google.",
            "googleadservices.com",
            "app-measurement.com",
            "googlesyndication.com",
            // ── Unity Ads ─────────────────────────────────────────────────────
            "unityads.unity3d.com",
            "config.unityads",
            "auctions.unityads",
            // ── AppLovin ──────────────────────────────────────────────────────
            "applovin.com",
            // ── Yandex Ads ────────────────────────────────────────────────────
            "an.yandex.ru",
            "bs.yandex.ru",
            "yandexadexchange.net",
            "adsdk.yandex.ru",
            // ── Facebook / Meta Ads ───────────────────────────────────────────
            "an.facebook.com",
            "graph.facebook.com",   // только рекламные эндпоинты
            // ── Crashlytics / Firebase ────────────────────────────────────────
            "crashlytics.com",
            "firebase-settings.crashlytics.com",
            // ── Analytics (телеметрия) ────────────────────────────────────────
            "google-analytics.com",
            "analytics.google.com",
            "stats.g.doubleclick.net",
            // ── MoPub ─────────────────────────────────────────────────────────
            "mopub.com",
            // ── Sentry / error tracking ───────────────────────────────────────
            "ingest.sentry.io",
            // ── AppsFlyer ─────────────────────────────────────────────────────
            "appsflyer.com",
            // ── IronSource ────────────────────────────────────────────────────
            "ironsource.com",
            // ── Vungle ────────────────────────────────────────────────────────
            "vungle.com",
            // ── Chartboost ────────────────────────────────────────────────────
            "chartboost.com",
            // ── AdColony ──────────────────────────────────────────────────────
            "adcolony.com",
            // ── InMobi ────────────────────────────────────────────────────────
            "inmobi.com",
            // ── Mintegral ─────────────────────────────────────────────────────
            "mintegral.com",
            // ── Snap Ads ──────────────────────────────────────────────────────
            "ads.snapchat.com",
            // ── TikTok Ads ────────────────────────────────────────────────────
            "ads.tiktok.com",
            "analytics.byteoversea.com",
        };

        // volatile гарантирует видимость обновлённой ссылки во всех потоках
        // после синхронизированной записи (double-checked locking pattern)
        private static volatile AhoCorasick instance;

        private AdFilter() {}

        /**
         * Получить singleton-экземпляр автомата.
         * Thread-safe: double-checked locking, instance volatile.
         * Первый вызов инициализирует автомат (~1-5 мс, однократно).
         */
        public static AhoCorasick get() {
            AhoCorasick local = instance;
            if (local == null) {
                synchronized (AdFilter.class) {
                    local = instance;
                    if (local == null) {
                        local = build(DEFAULT_PATTERNS);
                        instance = local;
                    }
                }
            }
            return local;
        }

        /**
         * Инициализация с дефолтными паттернами.
         * Вызывай из VpnService.onCreate() — не на горячем пути.
         */
        public static void initDefault() {
            get(); // triggers lazy init
        }

        /**
         * Добавить дополнительные паттерны поверх DEFAULT_PATTERNS.
         * Пересоздаёт автомат атомарно — все новые вызовы get() получат новый экземпляр.
         * Старые потоки, держащие ссылку на предыдущий экземпляр, продолжат
         * работать корректно (иммутабельный объект).
         *
         * @param extra массив паттернов в lowercase
         */
        public static synchronized void addPatterns(String[] extra) {
            if (extra == null || extra.length == 0) return;
            String[] merged = new String[DEFAULT_PATTERNS.length + extra.length];
            System.arraycopy(DEFAULT_PATTERNS, 0, merged, 0, DEFAULT_PATTERNS.length);
            System.arraycopy(extra, 0, merged, DEFAULT_PATTERNS.length, extra.length);
            instance = build(merged);
        }

        /**
         * Загрузить паттерны из InputStream (один домен/паттерн на строку).
         * Строки начинающиеся с '#' считаются комментариями и пропускаются.
         * Все паттерны автоматически приводятся к lowercase.
         * Объединяет загруженные паттерны с DEFAULT_PATTERNS.
         *
         * Пример файла:
         * <pre>
         * # My custom ad domains
         * ads.example.com
         * tracker.myapp.net
         * </pre>
         *
         * @param is  поток с паттернами (кодировка UTF-8)
         * @throws IOException при ошибке чтения
         */
        public static synchronized void loadFromStream(InputStream is) throws IOException {
            List<String> loaded = new ArrayList<>();
            // Добавляем дефолтные паттерны первыми
            for (String p : DEFAULT_PATTERNS) loaded.add(p);

            try (BufferedReader reader =
                     new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    line = line.trim().toLowerCase();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    loaded.add(line);
                }
            }
            instance = build(loaded.toArray(new String[0]));
        }

        /**
         * Заменить все паттерны кастомным набором (без DEFAULT_PATTERNS).
         * Используй если хочешь полный контроль над правилами.
         */
        public static synchronized void replaceWith(String[] patterns) {
            if (patterns == null || patterns.length == 0) return;
            String[] lower = new String[patterns.length];
            for (int i = 0; i < patterns.length; i++) {
                lower[i] = patterns[i] != null ? patterns[i].toLowerCase() : null;
            }
            instance = build(lower);
        }
    }
}
