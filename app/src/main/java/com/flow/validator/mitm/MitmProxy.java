package com.flow.validator.mitm;

import android.net.VpnService;
import android.util.Log;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * MitmProxy — локальный HTTPS перехватчик.
 *
 * ВАЖНО: Без root на Android 11+ этот прокси перехватывает ТОЛЬКО трафик
 * самого приложения (com.flow.validator) если в его network_security_config.xml
 * добавлен <certificates src="user"/>.
 *
 * Трафик СТОРОННИХ приложений расшифровать невозможно без root —
 * они не доверяют user-installed CA.
 *
 * Архитектура:
 *   SSLServerSocket → acceptLoop → handleConnection (per-thread)
 *     ↓ startHandshake() — SniKeyManager выбирает сертификат по SNI
 *     ↓ StreamInspector.inspect() — URI matching
 *     ↓ openUpstream() — VpnService.protect() + SSLSocket к реальному серверу
 */
public final class MitmProxy {

    private static final String TAG = "MitmProxy";

    public static final int LOCAL_PORT          = 8443;
    private static final int CONNECT_TIMEOUT_MS = 10_000;
    private static final int READ_TIMEOUT_MS    = 15_000;
    private static final int HTTPS_PORT         = 443;

    private SSLServerSocket serverSocket;
    private VpnService      vpnService;
    private ExecutorService workerPool;

    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread acceptThread;

    // =========================================================================
    // Lifecycle
    // =========================================================================

    public void start(VpnService vpn, ExecutorService pool) throws Exception {
        if (!running.compareAndSet(false, true)) return;

        this.vpnService = vpn;
        this.workerPool = pool;

        // Инициализируем CA (загружаем с диска или генерируем)
        CertificateManager.getInstance().initialize(vpn);

        // SSLContext с SniKeyManager — выбирает сертификат динамически по SNI
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(new KeyManager[]{new SniKeyManager()}, new TrustManager[]{TRUST_ALL}, null);

        SSLServerSocketFactory ssf = ctx.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);

        SSLParameters params = serverSocket.getSSLParameters();
        params.setNeedClientAuth(false);
        serverSocket.setSSLParameters(params);

        serverSocket.bind(new InetSocketAddress("127.0.0.1", LOCAL_PORT));

        acceptThread = new Thread(this::acceptLoop, "mitm-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();

        Log.i(TAG, "MitmProxy started on 127.0.0.1:" + LOCAL_PORT);
    }

    public void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (Exception ignored) {}
        if (acceptThread != null) acceptThread.interrupt();
    }

    // =========================================================================
    // Accept loop
    // =========================================================================

    private void acceptLoop() {
        while (running.get()) {
            try {
                SSLSocket client = (SSLSocket) serverSocket.accept();
                client.setSoTimeout(READ_TIMEOUT_MS);
                workerPool.execute(() -> handleConnection(client));
            } catch (Exception e) {
                if (running.get()) Log.e(TAG, "Accept error: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // Per-connection handler
    // =========================================================================

    private void handleConnection(SSLSocket client) {
        String key = client.getInetAddress().getHostAddress() + ":" + client.getPort();
        try {
            // SniKeyManager выберет сертификат во время handshake
            client.startHandshake();

            // Извлекаем hostname из сессии после handshake
            String hostname = getSniFromSession(client);
            if (hostname == null || hostname.isEmpty()) {
                Log.w(TAG, "No SNI for " + key + ", closing");
                return;
            }
            Log.d(TAG, "MITM: " + key + " → " + hostname);

            // Upstream соединение к реальному серверу (защищено от VPN loop)
            SSLSocket upstream = openUpstream(hostname, HTTPS_PORT);
            if (upstream == null) return;

            try {
                InputStream  cIn  = client.getInputStream();
                OutputStream cOut = client.getOutputStream();
                InputStream  sIn  = upstream.getInputStream();
                OutputStream sOut = upstream.getOutputStream();

                StreamInspector inspector = StreamInspector.getInstance();
                boolean intercepted = inspector.inspect(cIn, cOut, sOut, hostname);
                if (!intercepted) {
                    inspector.pipeResponse(sIn, cOut);
                }
            } finally {
                try { upstream.close(); } catch (Exception ignored) {}
            }

        } catch (Exception e) {
            Log.d(TAG, "Handler [" + key + "]: " + e.getMessage());
        } finally {
            try { client.close(); } catch (Exception ignored) {}
        }
    }

    // =========================================================================
    // SNI extraction — ИСПРАВЛЕНО: используем getAsciiName() из SNIHostName
    // =========================================================================

    private static String getSniFromSession(SSLSocket socket) {
        try {
            if (socket.getSession() instanceof ExtendedSSLSession) {
                ExtendedSSLSession session = (ExtendedSSLSession) socket.getSession();
                List<SNIServerName> names = session.getRequestedServerNames();
                if (names != null && !names.isEmpty()) {
                    SNIServerName sni = names.get(0);
                    // ФИКС: getAsciiName() вместо new String(getEncoded(), UTF-8)
                    if (sni instanceof SNIHostName) {
                        return ((SNIHostName) sni).getAsciiName();
                    }
                    // Fallback для нестандартных реализаций
                    return new String(sni.getEncoded(), StandardCharsets.US_ASCII);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "SNI extraction error: " + e.getMessage());
        }
        return null;
    }

    // =========================================================================
    // Upstream TLS connection (VpnService.protect → не попадает в VPN туннель)
    // =========================================================================

    private SSLSocket openUpstream(String host, int port) {
        try {
            // Создаём raw TCP сокет и защищаем его от VPN routing
            Socket raw = new Socket();
            if (!vpnService.protect(raw)) {
                Log.e(TAG, "protect() failed for upstream to " + host);
                raw.close();
                return null;
            }
            raw.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            raw.setSoTimeout(READ_TIMEOUT_MS);

            // Оборачиваем в TLS
            SSLSocketFactory sf = buildTrustAllSslContext().getSocketFactory();
            SSLSocket ssl = (SSLSocket) sf.createSocket(raw, host, port, true);
            ssl.setUseClientMode(true);

            // Передаём SNI серверу
            SSLParameters p = ssl.getSSLParameters();
            p.setServerNames(java.util.Collections.singletonList(new SNIHostName(host)));
            ssl.setSSLParameters(p);

            ssl.startHandshake();
            Log.d(TAG, "Upstream connected: " + host + ":" + port);
            return ssl;
        } catch (Exception e) {
            Log.e(TAG, "Upstream failed [" + host + "]: " + e.getMessage());
            return null;
        }
    }

    // =========================================================================
    // SniKeyManager — выбирает per-domain сертификат по SNI во время handshake
    // =========================================================================

    private static final class SniKeyManager extends X509ExtendedKeyManager {

        // Кэш: hostname → [leafCert, caCert]
        private final ConcurrentHashMap<String, X509Certificate[]> certCache
            = new ConcurrentHashMap<>();
        private final ConcurrentHashMap<String, PrivateKey> keyCache
            = new ConcurrentHashMap<>();

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers,
                                              SSLEngine engine) {
            try {
                if (engine.getHandshakeSession() instanceof ExtendedSSLSession) {
                    ExtendedSSLSession hs = (ExtendedSSLSession) engine.getHandshakeSession();
                    List<SNIServerName> names = hs.getRequestedServerNames();
                    if (names != null && !names.isEmpty()) {
                        SNIServerName sni = names.get(0);
                        // ФИКС: правильное извлечение hostname через getAsciiName()
                        String hostname = (sni instanceof SNIHostName)
                            ? ((SNIHostName) sni).getAsciiName()
                            : new String(sni.getEncoded(), StandardCharsets.US_ASCII);
                        ensureCertLoaded(hostname);
                        return hostname;
                    }
                }
            } catch (Exception e) {
                Log.e(TAG, "chooseEngineServerAlias: " + e.getMessage());
            }
            return "default";
        }

        @Override
        public String chooseServerAlias(String keyType, Principal[] issuers,
                                        java.net.Socket socket) { return "default"; }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            X509Certificate[] chain = certCache.get(alias);
            if (chain != null) return chain;
            try {
                X509Certificate ca = CertificateManager.getInstance().getCaCert();
                return new X509Certificate[]{ca};
            } catch (Exception e) {
                return new X509Certificate[0];
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) { return keyCache.get(alias); }

        @Override
        public String[] getServerAliases(String kt, Principal[] i) {
            return certCache.keySet().toArray(new String[0]);
        }
        @Override
        public String[] getClientAliases(String kt, Principal[] i) { return null; }
        @Override
        public String chooseClientAlias(String[] kt, Principal[] i,
                                        java.net.Socket s) { return null; }

        private void ensureCertLoaded(String hostname) {
            if (certCache.containsKey(hostname)) return;
            try {
                KeyStore ks = CertificateManager.getInstance().buildKeyStoreForHost(hostname);
                if (ks == null) return;
                PrivateKey pk = (PrivateKey) ks.getKey("leaf", new char[0]);
                java.security.cert.Certificate[] chain = ks.getCertificateChain("leaf");
                if (pk == null || chain == null) return;
                keyCache.put(hostname, pk);
                X509Certificate[] x509 = new X509Certificate[chain.length];
                for (int i = 0; i < chain.length; i++) x509[i] = (X509Certificate) chain[i];
                certCache.put(hostname, x509);
            } catch (Exception e) {
                Log.e(TAG, "ensureCertLoaded [" + hostname + "]: " + e.getMessage());
            }
        }
    }

    // =========================================================================
    // Trust-all TrustManager (для upstream — доверяем любому серверу)
    // =========================================================================

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
        @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
        @Override public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    };

    private static SSLContext buildTrustAllSslContext() {
        try {
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(null, new TrustManager[]{TRUST_ALL}, null);
            return ctx;
        } catch (Exception e) {
            throw new RuntimeException("TrustAll SSLContext failed", e);
        }
    }
}
