package com.flow.validator.mitm;

import android.content.Context;
import android.util.Log;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * CertificateManager — Root CA generation, persistence, and per-domain cert spoofing.
 *
 * <p><b>Lifecycle:</b>
 * <ol>
 *   <li>Call {@link #initialize(Context)} once at VPN service startup. On first run this
 *       generates a 2048-bit RSA Root CA key pair and a self-signed X.509 CA certificate
 *       valid for 10 years, then persists both to {@code context.getFilesDir()} as
 *       {@code ca.key} (PKCS#8 DER) and {@code ca.crt} (DER-encoded certificate).</li>
 *   <li>On subsequent startups the saved key and certificate are loaded from disk,
 *       so the same CA is reused across app restarts — avoiding the need to
 *       re-install the certificate on the device.</li>
 *   <li>For each intercepted TLS hostname, call {@link #getOrCreateSpoofedCert(String)}
 *       to obtain an {@link SSLContext} backed by a dynamically signed leaf certificate.
 *       Results are cached in a bounded {@link ConcurrentHashMap}.</li>
 *   <li>The generated CA certificate (DER bytes) is exposed via
 *       {@link #getCaCertDer()} for export and user-installation into Android's
 *       "User trusted credentials" store.</li>
 * </ol>
 *
 * <p><b>Persistence files (in context.getFilesDir()):</b>
 * <ul>
 *   <li>{@code sentinel_ca.crt} — DER-encoded Root CA certificate</li>
 *   <li>{@code sentinel_ca.key} — PKCS#8 DER-encoded Root CA private key</li>
 * </ul>
 *
 * <p><b>Thread safety:</b> all public methods are safe to call concurrently.
 */
public final class CertificateManager {

    private static final String TAG          = "CertManager";
    private static final String BC_PROVIDER  = "BC";
    private static final String KEY_ALG      = "RSA";
    private static final int    KEY_BITS     = 2048;
    private static final String SIG_ALG      = "SHA256withRSA";
    private static final int    CACHE_LIMIT  = 256;

    // Filenames for persisted CA material
    private static final String CA_CERT_FILE = "sentinel_ca.crt";
    private static final String CA_KEY_FILE  = "sentinel_ca.key";

    static {
        if (Security.getProvider(BC_PROVIDER) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    // -------------------------------------------------------------------------
    // Singleton
    // -------------------------------------------------------------------------

    private static volatile CertificateManager instance;

    public static CertificateManager getInstance() {
        if (instance == null) {
            synchronized (CertificateManager.class) {
                if (instance == null) instance = new CertificateManager();
            }
        }
        return instance;
    }

    private CertificateManager() {}

    // -------------------------------------------------------------------------
    // Root CA state
    // -------------------------------------------------------------------------

    private volatile KeyPair         caKeyPair;
    private volatile X509Certificate caCert;
    private volatile byte[]          caCertDer;
    private volatile boolean         initialized = false;

    private final AtomicLong serialCounter = new AtomicLong(1000);

    private final ConcurrentHashMap<String, SSLContext> sslContextCache
            = new ConcurrentHashMap<>(64);

    // -------------------------------------------------------------------------
    // Initialization — with persistence
    // -------------------------------------------------------------------------

    /**
     * Initialize the Root CA. On first run generates and persists the CA.
     * On subsequent runs loads the persisted CA from {@code context.getFilesDir()}.
     * Safe to call multiple times — subsequent calls after success are no-ops.
     *
     * @param context Android context used to resolve the private files directory.
     * @throws Exception if RSA or BouncyCastle operations fail.
     */
    public synchronized void initialize(Context context) throws Exception {
        if (initialized) return;

        File certFile = new File(context.getFilesDir(), CA_CERT_FILE);
        File keyFile  = new File(context.getFilesDir(), CA_KEY_FILE);

        if (certFile.exists() && keyFile.exists()) {
            // ── Load persisted CA ────────────────────────────────────────────
            try {
                loadCaFromDisk(certFile, keyFile);
                Log.i(TAG, "Root CA loaded from disk | subject=" + caCert.getSubjectDN());
                initialized = true;
                return;
            } catch (Exception e) {
                Log.w(TAG, "Failed to load persisted CA, regenerating: " + e.getMessage());
                // Fall through to regeneration
            }
        }

        // ── Generate new CA ──────────────────────────────────────────────────
        Log.i(TAG, "Generating new Root CA key pair…");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG, BC_PROVIDER);
        kpg.initialize(KEY_BITS);
        caKeyPair = kpg.generateKeyPair();

        long now       = System.currentTimeMillis();
        Date notBefore = new Date(now - 24L * 3600 * 1000);
        Date notAfter  = new Date(now + 10L * 365 * 24 * 3600 * 1000);

        X500Name caName = new X500Name("CN=SentinelNode CA, O=SentinelNode, C=US");

        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName,
                BigInteger.valueOf(1),
                notBefore, notAfter,
                caName,
                caKeyPair.getPublic()
        );

        caBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG)
                .setProvider(BC_PROVIDER)
                .build(caKeyPair.getPrivate());

        X509CertificateHolder holder = caBuilder.build(signer);
        caCert    = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(holder);
        caCertDer = caCert.getEncoded();
        initialized = true;

        Log.i(TAG, "Root CA generated | subject=" + caCert.getSubjectDN());

        // ── Persist to internal storage ──────────────────────────────────────
        saveCaToDisk(certFile, keyFile);
    }

    /**
     * No-context overload — generates an ephemeral CA (not persisted).
     * Use only when a Context is unavailable (e.g., unit tests).
     */
    public synchronized void initialize() throws Exception {
        if (initialized) return;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG, BC_PROVIDER);
        kpg.initialize(KEY_BITS);
        caKeyPair = kpg.generateKeyPair();

        long now       = System.currentTimeMillis();
        Date notBefore = new Date(now - 24L * 3600 * 1000);
        Date notAfter  = new Date(now + 10L * 365 * 24 * 3600 * 1000);

        X500Name caName = new X500Name("CN=SentinelNode CA, O=SentinelNode, C=US");
        X509v3CertificateBuilder caBuilder = new JcaX509v3CertificateBuilder(
                caName, BigInteger.valueOf(1), notBefore, notAfter, caName,
                caKeyPair.getPublic());

        caBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        caBuilder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG)
                .setProvider(BC_PROVIDER).build(caKeyPair.getPrivate());

        X509CertificateHolder holder = caBuilder.build(signer);
        caCert    = new JcaX509CertificateConverter().setProvider(BC_PROVIDER)
                .getCertificate(holder);
        caCertDer = caCert.getEncoded();
        initialized = true;

        Log.i(TAG, "Root CA generated (ephemeral) | subject=" + caCert.getSubjectDN());
    }

    // -------------------------------------------------------------------------
    // Disk persistence
    // -------------------------------------------------------------------------

    /**
     * Save CA private key (PKCS#8 DER) and certificate (DER) to internal storage.
     * Files are written atomically via temp-file rename.
     */
    private void saveCaToDisk(File certFile, File keyFile) {
        try {
            // Write certificate DER
            writeBytesAtomic(certFile, caCertDer);
            // Write private key as PKCS#8 DER
            writeBytesAtomic(keyFile, caKeyPair.getPrivate().getEncoded());
            Log.i(TAG, "Root CA persisted to " + certFile.getParent());
        } catch (Exception e) {
            Log.e(TAG, "Failed to persist CA: " + e.getMessage());
            // Non-fatal — CA is still usable in memory
        }
    }

    /** Write bytes atomically: write to .tmp then rename. */
    private static void writeBytesAtomic(File dest, byte[] data) throws Exception {
        File tmp = new File(dest.getParent(), dest.getName() + ".tmp");
        try (FileOutputStream fos = new FileOutputStream(tmp)) {
            fos.write(data);
            fos.getFD().sync();
        }
        if (!tmp.renameTo(dest)) {
            // renameTo can fail across filesystems — fall back to copy+delete
            try (FileOutputStream fos = new FileOutputStream(dest)) {
                fos.write(data);
            }
            tmp.delete();
        }
    }

    /**
     * Load CA private key and certificate from disk.
     * Reconstructs the full {@link KeyPair} from the persisted PKCS#8 private key
     * and the DER certificate (which contains the public key).
     */
    private void loadCaFromDisk(File certFile, File keyFile) throws Exception {
        // Load certificate
        byte[] certDer = readAllBytes(certFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
        try (java.io.ByteArrayInputStream bais = new java.io.ByteArrayInputStream(certDer)) {
            caCert = (X509Certificate) cf.generateCertificate(bais);
        }
        caCertDer = certDer;

        // Load private key (PKCS#8 DER)
        byte[] keyDer = readAllBytes(keyFile);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyDer);
        KeyFactory kf = KeyFactory.getInstance(KEY_ALG, BC_PROVIDER);
        PrivateKey privateKey = kf.generatePrivate(keySpec);

        // Reconstruct KeyPair — public key extracted from the certificate
        caKeyPair = new KeyPair(caCert.getPublicKey(), privateKey);
    }

    private static byte[] readAllBytes(File file) throws Exception {
        byte[] buf = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            int offset = 0;
            int read;
            while (offset < buf.length &&
                    (read = fis.read(buf, offset, buf.length - offset)) != -1) {
                offset += read;
            }
        }
        return buf;
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /**
     * Get the Root CA certificate as raw DER bytes for user installation.
     */
    public byte[] getCaCertDer() {
        ensureInitialized();
        return caCertDer.clone();
    }

    public X509Certificate getCaCert() {
        ensureInitialized();
        return caCert;
    }

    /**
     * Build a {@link KeyStore} containing a freshly signed leaf certificate for
     * {@code hostname}. Called by {@link MitmProxy.SniKeyManager} to supply
     * per-domain key material during the TLS handshake.
     *
     * @param hostname Target hostname.
     * @return Populated KeyStore with alias {@code "leaf"}, or {@code null} on error.
     */
    public KeyStore buildKeyStoreForHost(String hostname) {
        ensureInitialized();
        try {
            long now       = System.currentTimeMillis();
            Date notBefore = new Date(now - 3_600_000L);
            Date notAfter  = new Date(now + 365L * 24 * 3600 * 1000);

            X500Name issuer  = new X500Name("CN=SentinelNode CA, O=SentinelNode, C=US");
            X500Name subject = new X500Name("CN=" + hostname + ", O=SentinelNode");

            KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG, BC_PROVIDER);
            kpg.initialize(KEY_BITS);
            KeyPair leafKp = kpg.generateKeyPair();

            X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                    issuer,
                    BigInteger.valueOf(serialCounter.getAndIncrement()),
                    notBefore, notAfter,
                    subject,
                    leafKp.getPublic()
            );
            leafBuilder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
            leafBuilder.addExtension(Extension.basicConstraints, true,
                    new BasicConstraints(false));

            ContentSigner signer = new JcaContentSignerBuilder(SIG_ALG)
                    .setProvider(BC_PROVIDER)
                    .build(caKeyPair.getPrivate());

            X509Certificate leafCert = new JcaX509CertificateConverter()
                    .setProvider(BC_PROVIDER)
                    .getCertificate(leafBuilder.build(signer));

            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setKeyEntry("leaf", leafKp.getPrivate(), new char[0],
                    new X509Certificate[]{ leafCert, caCert });
            return ks;
        } catch (Exception e) {
            Log.e(TAG, "buildKeyStoreForHost failed [" + hostname + "]: " + e.getMessage());
            return null;
        }
    }

    /**
     * Retrieve (or create) an {@link SSLContext} presenting a certificate
     * dynamically signed by the Root CA for the given {@code hostname}.
     *
     * Results are cached. If the cache exceeds {@link #CACHE_LIMIT} entries
     * the oldest third is evicted.
     *
     * @param hostname Target server hostname (e.g., "ads.example.com").
     * @return A configured {@link SSLContext} ready for use in a local
     *         {@link javax.net.ssl.SSLServerSocket}.
     */
    public SSLContext getOrCreateSpoofedCert(String hostname) throws Exception {
        ensureInitialized();

        if (sslContextCache.size() >= CACHE_LIMIT) {
            evictOldestThird();
        }

        return sslContextCache.computeIfAbsent(hostname, h -> {
            try {
                return buildSpoofedSslContext(h);
            } catch (Exception e) {
                Log.e(TAG, "Failed to create spoofed cert for " + h + ": " + e.getMessage());
                return null;
            }
        });
    }

    private SSLContext buildSpoofedSslContext(String hostname) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_ALG, BC_PROVIDER);
        kpg.initialize(KEY_BITS);
        KeyPair leafKp = kpg.generateKeyPair();

        long now       = System.currentTimeMillis();
        Date notBefore = new Date(now - 3_600_000L);
        Date notAfter  = new Date(now + 365L * 24 * 3600 * 1000);

        X500Name issuer  = new X500Name("CN=SentinelNode CA, O=SentinelNode, C=US");
        X500Name subject = new X500Name("CN=" + hostname + ", O=SentinelNode");

        X509v3CertificateBuilder leafBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(serialCounter.getAndIncrement()),
                notBefore, notAfter,
                subject,
                leafKp.getPublic()
        );

        leafBuilder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.dNSName, hostname)));
        leafBuilder.addExtension(Extension.basicConstraints, true,
                new BasicConstraints(false));

        ContentSigner leafSigner = new JcaContentSignerBuilder(SIG_ALG)
                .setProvider(BC_PROVIDER)
                .build(caKeyPair.getPrivate());

        X509Certificate leafCert = new JcaX509CertificateConverter()
                .setProvider(BC_PROVIDER)
                .getCertificate(leafBuilder.build(leafSigner));

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setKeyEntry("leaf", leafKp.getPrivate(), new char[0],
                new X509Certificate[]{ leafCert, caCert });

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
                KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);

        TrustManager[] trustAll = new TrustManager[]{ TRUST_ALL };

        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), trustAll, null);

        Log.d(TAG, "Spoofed cert created for: " + hostname);
        return ctx;
    }

    // -------------------------------------------------------------------------
    // Trust-all TrustManager (upstream outbound leg only)
    // -------------------------------------------------------------------------

    private static final X509TrustManager TRUST_ALL = new X509TrustManager() {
        @Override public void checkClientTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}
        @Override public void checkServerTrusted(
                java.security.cert.X509Certificate[] chain, String authType) {}
        @Override public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
    };

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    private void ensureInitialized() {
        if (!initialized) {
            throw new IllegalStateException(
                    "CertificateManager not initialized — call initialize(Context) first");
        }
    }

    private void evictOldestThird() {
        int target  = CACHE_LIMIT / 3;
        int removed = 0;
        for (String key : sslContextCache.keySet()) {
            if (removed >= target) break;
            sslContextCache.remove(key);
            removed++;
        }
        Log.d(TAG, "Evicted " + removed + " cached SSL contexts");
    }
}
