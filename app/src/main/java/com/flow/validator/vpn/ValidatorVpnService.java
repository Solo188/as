package com.flow.validator.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.VpnService;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.flow.validator.audit.LogAnalyzer;
import com.flow.validator.mitm.MitmProxyServer;
import com.flow.validator.mitm.SSLInterceptor;
import com.flow.validator.util.SentinelLog;
import com.flow.validator.util.AhoCorasick;
import com.flow.validator.util.LatencyTracker;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

/**
 * ValidatorVpnService — системный фильтр трафика на базе AhoCorasick.
 *
 * ════════════════════════════════════════════════════════════════════
 *  КАК РАБОТАЕТ ПЕРЕХВАТ БЕЗ ПЕРЕГРУЗКИ CPU
 * ════════════════════════════════════════════════════════════════════
 *
 *  Принцип «умного дропа» вместо «анализа всего»:
 *
 *  1. EARLY PROTOCOL FILTER (O(1)):
 *     Каждый пакет проходит проверку за 3-4 байтовых чтения:
 *       buf[9]  == 17 (UDP) → проверяем dst-port 53  → DNS?
 *       buf[9]  == 6  (TCP) → проверяем dst-port 80  → HTTP?
 *                           → проверяем dst-port 443 → TLS?
 *     Все остальные пакеты (TCP/443 без TLS header, ICMP, UDP не-DNS и т.д.)
 *     немедленно PASS без какого-либо сканирования.
 *     На практике 95%+ пакетов проходят за ~5 инструкций.
 *
 *  2. DNS PARSING (O(имя)):
 *     Парсим wire-format DNS question section прямо по byte[], без String.
 *     Имя складывается в thread-local byte[256] (нет аллокации на пакет).
 *     AhoCorasick.matchBytes() сканирует имя за один проход O(n).
 *     Средний DNS-запрос: 20-40 байт имени → < 0.01 мс.
 *
 *  3. TLS SNI PARSING (O(ClientHello size)):
 *     Только первый пакет нового TCP-соединения содержит ClientHello.
 *     Детектируем по первому байту payload: 0x16 = TLS Handshake.
 *     Пропускаем fixed-size поля (random, session_id, cipher_suites) без копирования.
 *     Находим extension type=0x0000 (SNI) и читаем hostname in-place.
 *     Последующие пакеты того же соединения не содержат ClientHello → PASS без парсинга.
 *
 *  4. BLOCKING:
 *     DROP = просто не вызываем tunOut.write().
 *     PASS = tunOut.write(buf, 0, n) — тот же буфер без копирования.
 *     Ядро видит только PASS пакеты и обрабатывает их штатно.
 *
 *  5. THREADING:
 *     Один поток чтения. setBlocking(true) → read() блокируется до прихода пакета.
 *     Нет spin-wait, нет polling, нет sleep() в нормальном режиме.
 *     CPU использует 0% когда трафика нет.
 *
 *  6. ZERO GC PRESSURE:
 *     buf[32768]          — один буфер, живёт весь сервис
 *     domainBuf[256]      — thread-local, без new на каждый пакет
 *     matchBytes()        — нет аллокаций внутри метода
 *     logBlock()          — аллоцирует String только если DEBUG включён
 *
 *  7. NETWORK SWITCH (Wi-Fi ↔ 4G):
 *     ConnectivityManager.CONNECTIVITY_ACTION → перестраиваем TUN.
 *     Закрываем старый PFD → читающий поток получает IOException → завершается.
 *     Открываем новый TUN → запускаем новый читающий поток.
 *     Никаких утечек FD: closeTun() идемпотентен, закрывает в правильном порядке.
 */
public class ValidatorVpnService extends VpnService {

    private static final String TAG = "SentinelVPN";

    // ── Intent extras для управления режимами ─────────────────────────────────
    public static final String EXTRA_MODE_DNS   = "mode_dns";
    public static final String EXTRA_MODE_HTTP  = "mode_http";
    public static final String EXTRA_MODE_HTTPS = "mode_https";

    // ── Конфигурация ──────────────────────────────────────────────────────────
    private static final String NOTIF_CHANNEL  = "sentinel_vpn";
    private static final int    NOTIF_ID       = 1001;
    private static final int    MTU            = 1500;   // стандартный Ethernet MTU
    //   BUF_SIZE > MTU намеренно: некоторые устройства могут отдавать
    //   сегменты больше MTU из TUN (GRO/GSO offloading). 4096 — безопасный запас.
    private static final int    BUF_SIZE       = 4096;
    private static final String TUN_ADDR       = "10.99.0.1";
    private static final int    TUN_PREFIX     = 24;
    // Максимальная длина DNS-имени по RFC 1035 — 253 символа
    private static final int    MAX_DNS_NAME   = 256;

    // ── Режимы (задаются через Intent, изменяются только при перезапуске) ─────
    private volatile boolean modeDns   = true;
    private volatile boolean modeHttp  = true;
    private volatile boolean modeHttps = true; // SNI блокировка без расшифровки

    // ── IO-ресурсы — создаются/уничтожаются вместе с TUN ─────────────────────
    private volatile ParcelFileDescriptor vpnPfd;
    private volatile FileInputStream      tunIn;
    private volatile FileOutputStream     tunOut;

    // ── Состояние сервиса ─────────────────────────────────────────────────────
    private volatile boolean running      = false;
    private          Thread  readerThread = null;

    // ── Зависимости (опциональные) ────────────────────────────────────────────
    private LogAnalyzer    logAnalyzer;
    private LatencyTracker latencyTracker;
    private MitmProxyServer mitmServer;
    private SSLInterceptor  sslInterceptor;

    // ── AhoCorasick автомат — иммутабелен, один экземпляр на весь сервис ──────
    private AhoCorasick filter;

    // ── thread-local буфер для DNS-имени (нет new byte[] на каждый пакет) ─────
    private final ThreadLocal<byte[]> domainBufTL =
        ThreadLocal.withInitial(() -> new byte[MAX_DNS_NAME]);

    // ── Пакеты, которые не попадают в VPN-туннель ─────────────────────────────
    private static final String[] BYPASS_PKGS = {
        "com.android.vending",       // Google Play (обновления приложений)
        "com.google.android.gms",    // Google Mobile Services
        "com.google.android.gsf",    // Google Services Framework
        "com.android.providers.downloads",
        "com.android.systemui",
    };

    // ── BroadcastReceiver для переключения сетей ──────────────────────────────
    @SuppressWarnings("deprecation")
    private final BroadcastReceiver connectivityReceiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            if (!ConnectivityManager.CONNECTIVITY_ACTION.equals(intent.getAction())) return;

            ConnectivityManager cm =
                (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) return;

            @SuppressWarnings("deprecation")
            NetworkInfo active = cm.getActiveNetworkInfo();
            boolean connected  = active != null && active.isConnected();

            Log.i(TAG, "Network change: connected=" + connected);

            if (connected && running) {
                // Сеть переключилась — пересоздаём TUN чтобы получить
                // корректный routing на новом интерфейсе (Wi-Fi ↔ LTE)
                restartTun();
            }
        }
    };

    // =========================================================================
    // Binder — для ServiceConnection из MainService
    // =========================================================================

    public class LocalBinder extends Binder {
        public ValidatorVpnService getService() { return ValidatorVpnService.this; }
    }
    private final IBinder localBinder = new LocalBinder();

    @Override
    public IBinder onBind(Intent intent) {
        // VpnService обрабатывает android.net.VpnService интент сам
        IBinder vpnBinder = super.onBind(intent);
        return vpnBinder != null ? vpnBinder : localBinder;
    }

    // =========================================================================
    // Публичный API
    // =========================================================================

    public void attachLogAnalyzer(LogAnalyzer a)       { this.logAnalyzer    = a; }
    public void attachLatencyTracker(LatencyTracker t) { this.latencyTracker  = t; }
    public LatencyTracker getLatencyTracker()           { return latencyTracker; }
    public boolean isRunning()                          { return running; }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        startForeground(NOTIF_ID, buildNotification());

        // Строим автомат один раз — ~1-5 мс, потом read-only навсегда
        AhoCorasick.AdFilter.initDefault();
        filter = AhoCorasick.AdFilter.get();

        if (latencyTracker == null) latencyTracker = new LatencyTracker();
        mitmServer    = new MitmProxyServer();
        sslInterceptor = new SSLInterceptor();
        SentinelLog.setDebug(true);

        // Регистрируем listener на переключение сетей
        IntentFilter netFilter = new IntentFilter();
        //noinspection deprecation
        netFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        registerReceiver(connectivityReceiver, netFilter);

        Log.i(TAG, "VpnService created | filter.states=" + filter.stateCount());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null) {
            modeDns   = intent.getBooleanExtra(EXTRA_MODE_DNS,   true);
            modeHttp  = intent.getBooleanExtra(EXTRA_MODE_HTTP,  true);
            modeHttps = intent.getBooleanExtra(EXTRA_MODE_HTTPS, true);
        }
        Log.i(TAG, "onStartCommand | DNS=" + modeDns
                + " HTTP=" + modeHttp + " HTTPS=" + modeHttps);

        if (!running) {
            if (establishTun()) {
                if (modeHttps) startMitmServer();
                startReader();
            }
        }
        return START_STICKY;
    }

    /**
     * Вызывается системой когда пользователь отзывает VPN-разрешение.
     * Должны корректно завершиться — иначе Android убьёт процесс принудительно.
     */
    @Override
    public void onRevoke() {
        Log.i(TAG, "VPN permission revoked by user");
        shutdown();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        try {
            unregisterReceiver(connectivityReceiver);
        } catch (Exception ignored) {} // на случай если не был зарегистрирован
        shutdown();
        super.onDestroy();
        Log.i(TAG, "VpnService destroyed");
    }

    // =========================================================================
    // TUN — создание, перезапуск, закрытие
    // =========================================================================

    /**
     * Создаёт TUN-интерфейс и открывает FileInputStream/FileOutputStream.
     * @return true если успешно, false если нет разрешения или ошибка.
     */
    private boolean establishTun() {
        try {
            Builder b = new Builder();
            b.setSession("Sentinel")
             .addAddress(TUN_ADDR, TUN_PREFIX)
             .addRoute("0.0.0.0", 0)   // весь IPv4 → TUN
             .addDnsServer("8.8.8.8")
             .addDnsServer("1.1.1.1")
             .setMtu(MTU)
             .setBlocking(true);        // blocking read → нет busy-wait

            // Исключаем себя: иначе трафик нашего сервиса зациклится в TUN
            try { b.addDisallowedApplication(getPackageName()); }
            catch (Exception e) { Log.w(TAG, "Exclude self failed: " + e.getMessage()); }

            for (String pkg : BYPASS_PKGS) {
                try { b.addDisallowedApplication(pkg); }
                catch (Exception ignored) {}
            }

            ParcelFileDescriptor pfd = b.establish();
            if (pfd == null) {
                // VpnService.prepare() не был вызван или пользователь отказал.
                // DashboardActivity должен сначала показать диалог разрешения.
                Log.e(TAG, "establish() returned null — VPN permission not granted");
                running = false;
                stopSelf();
                return false;
            }

            // Присваиваем volatile поля — видны из readLoop() немедленно
            vpnPfd = pfd;
            tunIn  = new FileInputStream(pfd.getFileDescriptor());
            tunOut = new FileOutputStream(pfd.getFileDescriptor());
            running = true;

            Log.i(TAG, "TUN established | MTU=" + MTU);
            return true;

        } catch (Exception e) {
            Log.e(TAG, "establishTun failed: " + e.getMessage(), e);
            closeTunResources();
            running = false;
            stopSelf();
            return false;
        }
    }

    /**
     * Пересоздаёт TUN при переключении сетей.
     * Закрывает старый интерфейс → читающий поток завершится через IOException →
     * запускаем новый поток с новым TUN.
     */
    private synchronized void restartTun() {
        Log.i(TAG, "Restarting TUN due to network change");
        // Сигнализируем потоку чтобы он завершился при IOException
        running = false;

        // Закрытие PFD разблокирует заблокированный read() — тот бросит IOException
        closeTunResources();

        // Ждём завершения старого потока (не более 1 секунды)
        if (readerThread != null) {
            try { readerThread.join(1000); }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        // Поднимаем TUN заново
        if (establishTun()) {
            startReader();
        }
    }

    /**
     * Полное завершение сервиса. Идемпотентен.
     */
    private void shutdown() {
        running = false;
        if (readerThread != null) readerThread.interrupt();
        if (mitmServer != null) mitmServer.stop();
        closeTunResources();
        Log.i(TAG, "Shutdown complete");
    }

    /**
     * Закрывает IO-ресурсы в правильном порядке. Идемпотентен.
     * Порядок: streams → PFD (важно: закрытие PFD без закрытия streams может
     * вызвать IOException в потоке чтения, что ожидаемо и обрабатывается).
     */
    private void closeTunResources() {
        FileInputStream  in  = tunIn;
        FileOutputStream out = tunOut;
        ParcelFileDescriptor pfd = vpnPfd;

        // Обнуляем volatile поля до закрытия, чтобы readLoop() увидел null
        tunIn  = null;
        tunOut = null;
        vpnPfd = null;

        try { if (in  != null) in.close();  } catch (Exception ignored) {}
        try { if (out != null) out.close(); } catch (Exception ignored) {}
        try { if (pfd != null) pfd.close(); } catch (Exception ignored) {}
    }

    // =========================================================================
    // Читающий поток
    // =========================================================================

    private void startMitmServer() {
        try {
            mitmServer.start(this, sslInterceptor);
        } catch (Exception e) {
            SentinelLog.w(TAG, "MitmProxyServer start failed: " + e.getMessage());
        }
    }

    private void startReader() {
        readerThread = new Thread(this::readLoop, "sentinel-reader");
        readerThread.setPriority(Thread.NORM_PRIORITY + 1); // чуть выше среднего
        readerThread.setDaemon(true);
        readerThread.start();
    }

    /**
     * Главный цикл чтения/фильтрации пакетов.
     *
     * ZERO-COPY DESIGN:
     *   buf[BUF_SIZE] — единственный буфер, живёт весь жизненный цикл потока.
     *   domainBuf     — через ThreadLocal, нет new byte[] на каждый DNS-пакет.
     *   PASS пакеты   — tunOut.write(buf, 0, n) без промежуточного копирования.
     *
     * CPU USAGE:
     *   setBlocking(true): read() спит в ядре пока нет пакета.
     *   Нет polling, нет sleep(), нет spin-loop.
     *   На idle девайсе: 0% CPU от этого потока.
     */
    private void readLoop() {
        Log.i(TAG, "Reader started");
        final byte[] buf = new byte[BUF_SIZE]; // единственная аллокация в потоке

        while (running) {
            FileInputStream in  = tunIn;
            FileOutputStream out = tunOut;

            // Defensive: если TUN пересоздаётся, ждём
            if (in == null || out == null) {
                try { Thread.sleep(10); } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
                continue;
            }

            try {
                // Блокирующее чтение: поток спит пока не придёт пакет из TUN
                int n = in.read(buf);
                if (n <= 0) continue;

                if (latencyTracker != null) latencyTracker.begin();

                // CORE DECISION: drop или pass?
                boolean drop = shouldDrop(buf, n);

                if (!drop) {
                    // PASS: возвращаем пакет в TUN — ядро отправит его в реальную сеть
                    out.write(buf, 0, n);
                }
                // DROP: не пишем ничего — пакет исчезает

                if (latencyTracker != null) latencyTracker.end();

            } catch (IOException e) {
                if (!running) break; // нормальное завершение при shutdown

                // Временная ошибка (например, во время restart TUN)
                Log.w(TAG, "IO in readLoop: " + e.getMessage());
                if (!running) break;

                // Небольшая пауза перед retry чтобы не спамить лог
                try { Thread.sleep(50); }
                catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }

        Log.i(TAG, "Reader stopped");
    }

    // =========================================================================
    // DROP/PASS решение — горячий путь
    // =========================================================================

    /**
     * Определяет нужно ли дропнуть пакет.
     *
     * Большинство пакетов проходят первые 3 проверки (O(1)) и возвращают false
     * без какого-либо сканирования. AhoCorasick вызывается только для:
     *   - UDP dst-port 53     (DNS запросы)
     *   - TCP dst-port 80     (HTTP первый пакет)
     *   - TCP dst-port 443    (TLS ClientHello с SNI)
     */
    private boolean shouldDrop(byte[] buf, int len) {
        // ── Минимальная валидация IPv4 ──────────────────────────────────────
        if (len < 20) return false;

        // Версия IP (старшие 4 бита первого байта)
        if (((buf[0] >> 4) & 0xF) != 4) return false; // не IPv4 → PASS

        // Длина IP-заголовка в байтах (младшие 4 бита * 4)
        int ipHdrLen = (buf[0] & 0x0F) * 4;
        if (ipHdrLen < 20 || ipHdrLen >= len) return false;

        int proto = buf[9] & 0xFF; // IP Protocol field

        // ── UDP: ищем DNS (dst-port 53) ────────────────────────────────────
        if (proto == 17 && modeDns) {
            if (ipHdrLen + 4 > len) return false;
            int dstPort = readU16(buf, ipHdrLen + 2);
            if (dstPort == 53) {
                return checkDns(buf, len, ipHdrLen);
            }
        }

        // ── TCP: ищем HTTP (80) и TLS (443) ────────────────────────────────
        if (proto == 6) {
            if (ipHdrLen + 4 > len) return false;
            int dstPort = readU16(buf, ipHdrLen + 2);

            if (modeHttp && (dstPort == 80 || dstPort == 8080)) {
                return checkHttp(buf, len, ipHdrLen);
            }
            if (modeHttps && dstPort == 443) {
                return checkTlsSni(buf, len, ipHdrLen);
            }
        }

        return false; // PASS — не наш протокол/порт
    }

    // ── Inline utility: читаем unsigned 16-bit big-endian ──────────────────
    private static int readU16(byte[] buf, int off) {
        return ((buf[off] & 0xFF) << 8) | (buf[off + 1] & 0xFF);
    }

    // =========================================================================
    // DNS парсинг — zero allocation
    // =========================================================================

    /**
     * Парсит DNS question section из wire-format прямо в buf.
     *
     * DNS Wire Format (question):
     *   [IP header][UDP header 8B][DNS header 12B][Question Section]
     *   Question = sequence of labels: [length:1B][data:length B]... [0x00]
     *
     * Собираем имя в domainBuf (thread-local), не создаём String.
     * AhoCorasick.matchBytes() сканирует domainBuf за один проход.
     */
    private boolean checkDns(byte[] buf, int len, int ipHdrLen) {
        // Позиция начала DNS question section:
        // IP header + UDP header(8) + DNS header(12)
        int pos = ipHdrLen + 8 + 12;
        if (pos >= len) return false;

        byte[] domain = domainBufTL.get(); // thread-local, нет аллокации
        int    dLen   = 0;

        while (pos < len) {
            int labelLen = buf[pos] & 0xFF;

            if (labelLen == 0) break;          // конец имени

            // DNS pointer compression (0xC0..): не следуем в целях безопасности
            if ((labelLen & 0xC0) == 0xC0) break;

            // Проверка bounds перед чтением метки
            if (labelLen > 63 || pos + 1 + labelLen > len) return false;

            pos++; // пропускаем байт длины

            // Добавляем точку-разделитель (кроме первой метки)
            if (dLen > 0 && dLen < domain.length - 1) {
                domain[dLen++] = '.';
            }

            // Копируем метку в domain буфер
            int toCopy = Math.min(labelLen, domain.length - dLen);
            System.arraycopy(buf, pos, domain, dLen, toCopy);
            dLen += toCopy;
            pos  += labelLen;

            if (dLen >= domain.length - 1) break; // защита от переполнения
        }

        if (dLen == 0) return false;

        // Сканируем прямо по byte[] — toLower=true, нет String
        boolean blocked = filter.matchBytes(domain, 0, dLen, true);
        if (blocked) logDrop("DNS", domain, dLen);
        return blocked;
    }

    // =========================================================================
    // HTTP Host header парсинг — zero allocation
    // =========================================================================

    /**
     * Ищет заголовок "Host:" в TCP payload и проверяет значение через фильтр.
     *
     * Оптимизация: быстрая проверка первого байта payload — HTTP-запрос
     * начинается с ASCII буквы метода (G/P/D/H/O/C). Все другие TCP пакеты
     * (ACK, данные без заголовков, FIN) отклоняются за O(1).
     */
    private boolean checkHttp(byte[] buf, int len, int ipHdrLen) {
        // TCP data offset (старшие 4 бита байта [ipHdrLen+12]) * 4
        if (ipHdrLen + 13 >= len) return false;
        int tcpHdrLen  = ((buf[ipHdrLen + 12] >> 4) & 0xF) * 4;
        int payloadOff = ipHdrLen + tcpHdrLen;
        int payloadLen = len - payloadOff;

        if (payloadLen < 16) return false;

        // Быстрый фильтр: первый байт HTTP-запроса всегда ASCII буква метода
        int b0 = buf[payloadOff] & 0xFF;
        if (b0 != 'G' && b0 != 'P' && b0 != 'D' &&
            b0 != 'H' && b0 != 'O' && b0 != 'C') {
            return false; // не HTTP-запрос
        }

        // Линейный поиск "Host:" (case-insensitive для H,o,s,t)
        int hostValOff = -1;
        for (int i = payloadOff; i < len - 6; i++) {
            byte prev = (i > payloadOff) ? buf[i - 1] : (byte) '\n';
            // Ищем начало строки с "Host:"
            if ((prev == '\n')
                    && (buf[i]     == 'H' || buf[i]     == 'h')
                    && (buf[i + 1] == 'o' || buf[i + 1] == 'O')
                    && (buf[i + 2] == 's' || buf[i + 2] == 'S')
                    && (buf[i + 3] == 't' || buf[i + 3] == 'T')
                    &&  buf[i + 4] == ':') {
                hostValOff = i + 5;
                // Пропускаем пробелы после ':'
                while (hostValOff < len && buf[hostValOff] == ' ') hostValOff++;
                break;
            }
        }
        if (hostValOff < 0) return false;

        // Читаем значение до \r или \n
        int hostValEnd = hostValOff;
        while (hostValEnd < len
               && buf[hostValEnd] != '\r'
               && buf[hostValEnd] != '\n') {
            hostValEnd++;
        }
        int hostLen = hostValEnd - hostValOff;
        if (hostLen <= 0 || hostLen > 253) return false;

        boolean blocked = filter.matchBytes(buf, hostValOff, hostLen, true);
        if (blocked) logDrop("HTTP", buf, hostValOff, hostLen);
        return blocked;
    }

    // =========================================================================
    // TLS SNI парсинг — zero allocation
    // =========================================================================

    /**
     * Извлекает SNI hostname из TLS ClientHello.
     *
     * TLS ClientHello wire structure:
     *   [TLS Record: 5B][Handshake Header: 4B][client_version: 2B][random: 32B]
     *   [session_id_len: 1B][session_id: N][cipher_suites_len: 2B][cipher_suites: N]
     *   [comp_methods_len: 1B][comp_methods: N][extensions_len: 2B]
     *   [Extension: type(2) + len(2) + data]...
     *     Extension type 0x0000 = SNI:
     *       [list_len: 2B][name_type: 1B][name_len: 2B][hostname bytes]
     *
     * Все поля читаются in-place из buf — нет промежуточных объектов.
     */
    private boolean checkTlsSni(byte[] buf, int len, int ipHdrLen) {
        if (ipHdrLen + 13 >= len) return false;
        int tcpHdrLen  = ((buf[ipHdrLen + 12] >> 4) & 0xF) * 4;
        int p          = ipHdrLen + tcpHdrLen; // p = начало TCP payload

        // ── TLS Record ──────────────────────────────────────────────────────
        // Byte 0: Content Type = 0x16 (Handshake)
        // Byte 1: Major version = 0x03
        if (p + 5 >= len) return false;
        if ((buf[p] & 0xFF) != 0x16) return false; // не TLS Handshake
        if ((buf[p + 1] & 0xFF) != 0x03) return false; // не TLS 1.x

        // ── Handshake Header ────────────────────────────────────────────────
        // Byte 5: Handshake Type = 0x01 (ClientHello)
        if (p + 5 >= len) return false;
        if ((buf[p + 5] & 0xFF) != 0x01) return false; // не ClientHello

        // Пропускаем: TLS record(5) + HS type(1) + HS length(3) +
        //              client_version(2) + random(32) = 43 байта
        int pos = p + 43;
        if (pos + 1 >= len) return false;

        // ── session_id ──────────────────────────────────────────────────────
        int sidLen = buf[pos] & 0xFF;
        pos += 1 + sidLen;
        if (pos + 2 >= len) return false;

        // ── cipher_suites ───────────────────────────────────────────────────
        int csLen = readU16(buf, pos);
        pos += 2 + csLen;
        if (pos + 1 >= len) return false;

        // ── compression_methods ─────────────────────────────────────────────
        int cmLen = buf[pos] & 0xFF;
        pos += 1 + cmLen;
        if (pos + 2 >= len) return false;

        // ── Extensions ──────────────────────────────────────────────────────
        int extBlockLen = readU16(buf, pos);
        pos += 2;
        int extBlockEnd = pos + extBlockLen;

        while (pos + 4 <= extBlockEnd && pos + 4 <= len) {
            int extType = readU16(buf, pos);
            int extLen  = readU16(buf, pos + 2);
            pos += 4;

            if (pos + extLen > len) return false; // обрезанный пакет

            if (extType == 0x0000) {
                // ── SNI Extension ────────────────────────────────────────────
                // Format: list_length(2) + entry_type(1) + name_length(2) + name
                if (pos + 5 > len) return false;
                // name_type == 0x00 → host_name
                if ((buf[pos + 2] & 0xFF) != 0x00) { pos += extLen; continue; }
                int nameLen = readU16(buf, pos + 3);
                int nameOff = pos + 5;
                if (nameOff + nameLen > len) return false;

                // Сканируем имя in-place — нет String, нет аллокаций
                boolean blocked = filter.matchBytes(buf, nameOff, nameLen, true);
                if (blocked) logDrop("SNI", buf, nameOff, nameLen);
                return blocked;
            }

            pos += extLen;
        }

        return false; // SNI extension не найден → PASS
    }

    // =========================================================================
    // Logging — аллоцирует String только если реально нужно
    // =========================================================================

    /** Логирование DNS блокировок — принимает byte[], не String. */
    private void logDrop(String proto, byte[] nameBuf, int nameLen) {
        // Создаём String только если есть кто слушает или debug включён
        if (logAnalyzer == null && !Log.isLoggable(TAG, Log.DEBUG)) return;
        String name = new String(nameBuf, 0, nameLen, java.nio.charset.StandardCharsets.US_ASCII);
        String msg  = "[DROP:" + proto + "] " + name;
        Log.d(TAG, msg);
        if (logAnalyzer != null) logAnalyzer.injectFilteredEvent(msg);
    }

    /** Перегрузка для HTTP/SNI (смещение в пакетном буфере). */
    private void logDrop(String proto, byte[] buf, int off, int len) {
        if (logAnalyzer == null && !Log.isLoggable(TAG, Log.DEBUG)) return;
        String name = new String(buf, off, len, java.nio.charset.StandardCharsets.US_ASCII);
        String msg  = "[DROP:" + proto + "] " + name;
        Log.d(TAG, msg);
        if (logAnalyzer != null) logAnalyzer.injectFilteredEvent(msg);
    }

    // =========================================================================
    // Уведомление (foreground service requirement)
    // =========================================================================

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                NOTIF_CHANNEL, "Sentinel VPN", NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    @SuppressWarnings("deprecation")
    private Notification buildNotification() {
        Notification.Builder b = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O
            ? new Notification.Builder(this, NOTIF_CHANNEL)
            : new Notification.Builder(this).setPriority(Notification.PRIORITY_LOW);
        return b.setContentTitle("Sentinel")
                .setContentText("Ad blocking active")
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setOngoing(true)
                .build();
    }
}
