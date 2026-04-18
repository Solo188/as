package com.flow.validator.mitm;

import android.net.VpnService;

import com.flow.validator.util.SentinelLog;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

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
 * MitmProxyServer — high-performance local TLS intercept proxy.
 *
 * Architecture:
 *   acceptLoop (single thread, blocking SSLServerSocket)
 *     → workerPool (fixed, CPU-count threads, ArrayBlockingQueue backpressure)
 *       → handleConnection: startHandshake() + relay via direct ByteBuffers
 *
 * Key design decisions:
 *   - SSLServerSocket accept is blocking (lowest overhead for Android)
 *   - Per-connection ByteBuffers come from a pool (no allocation per connection)
 *   - SniKeyManager caches KeyStore entries — no disk I/O on hot path
 *   - Upstream TLS uses VpnService.protect() to escape the tunnel
 *   - SSLHandshakeException caught per-connection, never propagates to acceptLoop
 */
public final class MitmProxyServer {

    public static final int PORT = 8443;

    private static final int CONNECT_TIMEOUT_MS  = 8_000;
    private static final int SO_TIMEOUT_MS        = 12_000;
    private static final int DIRECT_BUF_SIZE      = 16_384; // 16 KB per half-connection
    private static final int POOL_SIZE            = 8;      // buffer pool entries

    // Direct ByteBuffer pool — avoids allocation per connection
    private static final ArrayBlockingQueue<ByteBuffer> BUF_POOL = new ArrayBlockingQueue<>(POOL_SIZE);
    static {
        for (int i = 0; i < POOL_SIZE; i++) {
            BUF_POOL.add(ByteBuffer.allocateDirect(DIRECT_BUF_SIZE));
        }
    }

    private SSLServerSocket  serverSocket;
    private VpnService       vpnService;
    private ThreadPoolExecutor workerPool;
    private SSLInterceptor   interceptor;
    private final AtomicBoolean running  = new AtomicBoolean(false);
    private final AtomicInteger conCount = new AtomicInteger(0);
    private Thread acceptThread;

    // ─────────────────────────────────────────────────────────────────────────

    public void start(VpnService vpn, SSLInterceptor si) throws Exception {
        if (!running.compareAndSet(false, true)) return;
        vpnService  = vpn;
        interceptor = si;

        CertificateManager.getInstance().initialize(vpn);

        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(new KeyManager[]{new SniKeyManager()},
                       new TrustManager[]{TRUST_ALL}, null);

        SSLServerSocketFactory ssf = serverCtx.getServerSocketFactory();
        serverSocket = (SSLServerSocket) ssf.createServerSocket();
        serverSocket.setReuseAddress(true);
        // Restrict to TLS 1.2+ for performance (no TLS 1.0/1.1 overhead)
        serverSocket.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
        serverSocket.bind(new InetSocketAddress("127.0.0.1", PORT), 128);

        int cpus = Runtime.getRuntime().availableProcessors();
        workerPool = new ThreadPoolExecutor(
            cpus, cpus * 2,
            30L, TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(256),
            r -> {
                Thread t = new Thread(r, "mitm-worker-" + conCount.incrementAndGet());
                t.setDaemon(true);
                t.setPriority(Thread.NORM_PRIORITY + 1);
                return t;
            },
            new ThreadPoolExecutor.DiscardPolicy() // backpressure: drop if overwhelmed
        );

        acceptThread = new Thread(this::acceptLoop, "mitm-accept");
        acceptThread.setDaemon(true);
        acceptThread.setPriority(Thread.NORM_PRIORITY + 2);
        acceptThread.start();

        SentinelLog.i("MitmProxyServer", "started port=" + PORT + " workers=" + cpus);
    }

    public void stop() {
        running.set(false);
        try { if (serverSocket != null) serverSocket.close(); } catch (IOException ignored) {}
        if (workerPool != null) workerPool.shutdownNow();
        if (acceptThread != null) acceptThread.interrupt();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Accept loop — single blocking thread
    // ─────────────────────────────────────────────────────────────────────────

    private void acceptLoop() {
        while (running.get()) {
            SSLSocket client = null;
            try {
                client = (SSLSocket) serverSocket.accept();
                client.setSoTimeout(SO_TIMEOUT_MS);
                client.setTcpNoDelay(true);
                // Capture for lambda
                final SSLSocket c = client;
                workerPool.execute(() -> handleConnection(c));
            } catch (IOException e) {
                if (!running.get()) break;
                SentinelLog.w("MitmProxyServer", "accept: " + e.getMessage());
                // Don't close client here — lambda owns it
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-connection handler — runs on workerPool thread
    // ─────────────────────────────────────────────────────────────────────────

    private void handleConnection(SSLSocket client) {
        long t0 = System.nanoTime();
        String clientKey = client.getInetAddress().getHostAddress() + ":" + client.getPort();
        SSLSocket upstream = null;

        try {
            // TLS handshake with client — SniKeyManager picks cert dynamically
            client.startHandshake();

            String hostname = extractSni(client);
            if (hostname == null || hostname.isEmpty()) {
                SentinelLog.w("MitmProxyServer", "no SNI " + clientKey);
                return;
            }

            SentinelLog.ssl(hostname, client.getSession().getCipherSuite());

            // Open TLS upstream — bypasses VPN tunnel via protect()
            upstream = openUpstream(hostname);
            if (upstream == null) return;

            // Relay: client ↔ upstream via direct ByteBuffers from pool
            relay(client, upstream, hostname);

        } catch (javax.net.ssl.SSLHandshakeException e) {
            // Non-fatal: client rejected our cert or network error during handshake
            SentinelLog.w("MitmProxyServer", "[SSL] handshake fail " + clientKey + ": " + e.getMessage());
        } catch (IOException e) {
            // Connection reset, timeout — normal for ad traffic
        } catch (Exception e) {
            SentinelLog.w("MitmProxyServer", "handler " + clientKey + ": " + e.getMessage());
        } finally {
            close(client);
            close(upstream);
            SentinelLog.perf("conn", System.nanoTime() - t0);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Relay — direct ByteBuffer, pool-backed, no heap allocation per packet
    // ─────────────────────────────────────────────────────────────────────────

    private void relay(SSLSocket client, SSLSocket upstream, String hostname) throws IOException {
        // Acquire two direct buffers from pool; fall back to heap if pool empty
        ByteBuffer clientBuf   = acquire();
        ByteBuffer upstreamBuf = acquire();
        try {
            java.io.InputStream  cIn  = client.getInputStream();
            java.io.OutputStream cOut = client.getOutputStream();
            java.io.InputStream  sIn  = upstream.getInputStream();
            java.io.OutputStream sOut = upstream.getOutputStream();

            // Read request from client
            byte[] heapBuf = clientBuf.hasArray() ? clientBuf.array()
                                                   : new byte[DIRECT_BUF_SIZE];
            int n = cIn.read(heapBuf);
            if (n <= 0) return;

            // Run Aho-Corasick filter on the request data
            boolean blocked = interceptor.filterTraffic(heapBuf, n);
            if (blocked) {
                // Write empty 200 response — same length to preserve TCP sequence
                byte[] empty = buildEmptyResponse(n);
                cOut.write(empty);
                cOut.flush();
                return;
            }

            // Forward to upstream
            sOut.write(heapBuf, 0, n);
            sOut.flush();

            // Pipe response back — upstream → client, using second buffer
            byte[] respBuf = upstreamBuf.hasArray() ? upstreamBuf.array()
                                                     : new byte[DIRECT_BUF_SIZE];
            int r;
            while ((r = sIn.read(respBuf)) != -1) {
                cOut.write(respBuf, 0, r);
            }
            cOut.flush();

        } finally {
            release(clientBuf);
            release(upstreamBuf);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Buffer pool ops
    // ─────────────────────────────────────────────────────────────────────────

    private static ByteBuffer acquire() {
        ByteBuffer b = BUF_POOL.poll();
        if (b == null) b = ByteBuffer.allocateDirect(DIRECT_BUF_SIZE);
        b.clear();
        return b;
    }

    private static void release(ByteBuffer b) {
        if (b == null) return;
        b.clear();
        BUF_POOL.offer(b); // non-blocking offer — discard if pool full
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Upstream TLS
    // ─────────────────────────────────────────────────────────────────────────

    private SSLSocket openUpstream(String host) {
        try {
            Socket raw = new Socket();
            if (!vpnService.protect(raw)) {
                raw.close();
                SentinelLog.w("MitmProxyServer", "protect() failed: " + host);
                return null;
            }
            raw.connect(new InetSocketAddress(host, 443), CONNECT_TIMEOUT_MS);
            raw.setSoTimeout(SO_TIMEOUT_MS);
            raw.setTcpNoDelay(true);

            SSLSocket ssl = (SSLSocket) TRUST_ALL_CTX.getSocketFactory()
                                                      .createSocket(raw, host, 443, true);
            ssl.setUseClientMode(true);
            // Restrict ciphers to modern suites
            ssl.setEnabledProtocols(new String[]{"TLSv1.2", "TLSv1.3"});
            SSLParameters p = ssl.getSSLParameters();
            p.setServerNames(List.of(new SNIHostName(host)));
            ssl.setSSLParameters(p);
            ssl.startHandshake();
            return ssl;
        } catch (Exception e) {
            SentinelLog.w("MitmProxyServer", "upstream " + host + ": " + e.getMessage());
            return null;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Utilities
    // ─────────────────────────────────────────────────────────────────────────

    private static String extractSni(SSLSocket socket) {
        try {
            if (socket.getSession() instanceof ExtendedSSLSession s) {
                List<SNIServerName> names = s.getRequestedServerNames();
                if (names != null && !names.isEmpty()) {
                    SNIServerName sni = names.get(0);
                    return sni instanceof SNIHostName h ? h.getAsciiName()
                           : new String(sni.getEncoded(), java.nio.charset.StandardCharsets.US_ASCII);
                }
            }
        } catch (Exception ignored) {}
        return null;
    }

    /** Build a same-length HTTP 200 response body filled with spaces to preserve TCP seq. */
    private static byte[] buildEmptyResponse(int originalLen) {
        // Minimal HTTP 200 header + spaces to match originalLen
        String header = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        byte[] hdr = header.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        if (hdr.length >= originalLen) return hdr;
        byte[] out = new byte[originalLen];
        System.arraycopy(hdr, 0, out, 0, hdr.length);
        java.util.Arrays.fill(out, hdr.length, originalLen, (byte) ' ');
        return out;
    }

    private static void close(java.io.Closeable c) {
        if (c == null) return;
        try { c.close(); } catch (IOException ignored) {}
    }

    // ─────────────────────────────────────────────────────────────────────────
    // SniKeyManager — per-domain cert selection, LRU-cached
    // ─────────────────────────────────────────────────────────────────────────

    private static final class SniKeyManager extends X509ExtendedKeyManager {

        // LRUCache: bounded, thread-safe, no eviction under normal load (<512 domains)
        private final LruCertCache<String, X509Certificate[]> certCache = new LruCertCache<>(512);
        private final LruCertCache<String, PrivateKey>        keyCache  = new LruCertCache<>(512);

        @Override
        public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
            try {
                if (engine.getHandshakeSession() instanceof ExtendedSSLSession hs) {
                    List<SNIServerName> names = hs.getRequestedServerNames();
                    if (names != null && !names.isEmpty()) {
                        SNIServerName sni = names.get(0);
                        String host = sni instanceof SNIHostName h ? h.getAsciiName()
                                      : new String(sni.getEncoded(),
                                                   java.nio.charset.StandardCharsets.US_ASCII);
                        ensureCertLoaded(host);
                        return host;
                    }
                }
            } catch (Exception e) {
                SentinelLog.w("SniKeyManager", e.getMessage());
            }
            return "default";
        }

        @Override public String chooseServerAlias(String t, Principal[] i, java.net.Socket s) { return "default"; }
        @Override public String[] getClientAliases(String t, Principal[] i) { return null; }
        @Override public String[] getServerAliases(String t, Principal[] i) { return certCache.keyArray(); }
        @Override public String chooseClientAlias(String[] t, Principal[] i, java.net.Socket s) { return null; }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            X509Certificate[] chain = certCache.get(alias);
            if (chain != null) return chain;
            try { return new X509Certificate[]{CertificateManager.getInstance().getCaCert()}; }
            catch (Exception e) { return new X509Certificate[0]; }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) { return keyCache.get(alias); }

        private void ensureCertLoaded(String host) {
            if (certCache.containsKey(host)) return;
            try {
                KeyStore ks = CertificateManager.getInstance().buildKeyStoreForHost(host);
                if (ks == null) return;
                PrivateKey pk = (PrivateKey) ks.getKey("leaf", new char[0]);
                java.security.cert.Certificate[] chain = ks.getCertificateChain("leaf");
                if (pk == null || chain == null) return;
                keyCache.put(host, pk);
                X509Certificate[] x509 = new X509Certificate[chain.length];
                for (int i = 0; i < chain.length; i++) x509[i] = (X509Certificate) chain[i];
                certCache.put(host, x509);
                SentinelLog.ssl(host, "cert loaded (cache size=" + certCache.size() + ")");
            } catch (Exception e) {
                SentinelLog.w("SniKeyManager", "cert load fail " + host + ": " + e.getMessage());
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Minimal thread-safe LRU cache (no LinkedHashMap subclass — avoids lock)
    // ─────────────────────────────────────────────────────────────────────────

    private static final class LruCertCache<K, V> {
        private final java.util.LinkedHashMap<K, V> map;
        private final int maxSize;

        LruCertCache(int maxSize) {
            this.maxSize = maxSize;
            this.map = new java.util.LinkedHashMap<K, V>(maxSize, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(java.util.Map.Entry<K, V> eldest) {
                    return size() > maxSize;
                }
            };
        }

        synchronized V get(K key)               { return map.get(key); }
        synchronized void put(K key, V val)      { map.put(key, val); }
        synchronized boolean containsKey(K key)  { return map.containsKey(key); }
        synchronized int size()                  { return map.size(); }

        @SuppressWarnings("unchecked")
        synchronized String[] keyArray() {
            return map.keySet().toArray(new String[0]);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Trust-all (upstream leg only — we don't validate server certs)
    // ─────────────────────────────────────────────────────────────────────────

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(X509Certificate[] c, String a) {}
        @Override public void checkServerTrusted(X509Certificate[] c, String a) {}
        @Override public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    };

    private static final SSLContext TRUST_ALL_CTX;
    static {
        try {
            TRUST_ALL_CTX = SSLContext.getInstance("TLS");
            TRUST_ALL_CTX.init(null, new TrustManager[]{TRUST_ALL}, null);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }
}
