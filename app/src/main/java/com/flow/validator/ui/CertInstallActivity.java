package com.flow.validator.ui;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.security.KeyChain;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;

import com.flow.validator.R;
import com.flow.validator.mitm.CertificateManager;

import java.io.File;
import java.io.FileOutputStream;

/**
 * CertInstallActivity — Certificate Authority Installation Flow.
 *
 * <p>Guides the user through installing the SentinelNode Root CA certificate
 * into Android's "User trusted credentials" store. Once installed, HTTPS
 * connections whose certs were signed by this CA will be trusted by client
 * apps — enabling MitmProxy to intercept TLS traffic transparently.
 *
 * <p>Uses {@link ActivityResultLauncher} (non-deprecated) for the system
 * certificate installer Intent.
 *
 * <p><b>Flow:</b>
 * <ol>
 *   <li>Generate / load Root CA from {@code filesDir} in a background thread.</li>
 *   <li>Export {@code sentinel_ca.crt} to both app-private and external files dirs.</li>
 *   <li>Launch system installer via {@link KeyChain#createInstallIntent()}.</li>
 *   <li>On return, reflect installation result in UI.</li>
 * </ol>
 */
public class CertInstallActivity extends AppCompatActivity {

    private static final String TAG         = "CertInstall";
    private static final String CA_FILENAME = "sentinel_ca.crt";

    private TextView    tvStatus;
    private TextView    tvManualSteps;
    private Button      btnInstall;
    private Button      btnOpenSettings;
    private ProgressBar progressBar;

    private byte[] caCertDer;

    /** Non-deprecated replacement for startActivityForResult. */
    private final ActivityResultLauncher<Intent> installLauncher =
            registerForActivityResult(
                    new ActivityResultContracts.StartActivityForResult(),
                    result -> {
                        if (result.getResultCode() == RESULT_OK) {
                            tvStatus.setText(
                                    "Certificate installed successfully!\n"
                                    + "HTTPS interception is now active.");
                            tvStatus.setTextColor(0xFF3FB950);
                            btnInstall.setEnabled(false);
                            btnInstall.setText("Installed ✓");
                        } else {
                            tvStatus.setText(
                                    "Installation cancelled or failed.\n"
                                    + "Try the manual steps below.");
                            tvStatus.setTextColor(0xFFD29922);
                        }
                    });

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_cert_install);
        bindViews();
        setupButtons();
        generateOrLoadCaInBackground();
    }

    // -------------------------------------------------------------------------
    // View setup
    // -------------------------------------------------------------------------

    private void bindViews() {
        tvStatus        = findViewById(R.id.tv_cert_status);
        tvManualSteps   = findViewById(R.id.tv_manual_steps);
        btnInstall      = findViewById(R.id.btn_install_cert);
        btnOpenSettings = findViewById(R.id.btn_open_settings);
        progressBar     = findViewById(R.id.progress_cert);

        btnInstall.setEnabled(false);
        tvStatus.setText("Generating / loading Root CA…");
        progressBar.setVisibility(View.VISIBLE);

        tvManualSteps.setText(
                "Manual installation steps:\n\n"
                + "1. Tap \"Install Certificate\" below.\n"
                + "2. Android will ask you to name the cert.\n"
                + "   → Enter: SentinelNode CA\n"
                + "3. Choose \"VPN and apps\" as the usage.\n"
                + "4. Tap OK and confirm your screen lock.\n\n"
                + "Alternative (if button fails):\n"
                + "Settings → Security → Encryption & credentials\n"
                + "→ Install a certificate → CA certificate\n"
                + "→ Select sentinel_ca.crt from Downloads."
        );
    }

    private void setupButtons() {
        btnInstall.setOnClickListener(v -> launchSystemInstaller());
        btnOpenSettings.setOnClickListener(v -> {
            Intent i = new Intent(android.provider.Settings.ACTION_SECURITY_SETTINGS);
            startActivity(i);
        });
    }

    // -------------------------------------------------------------------------
    // CA generation / loading (background thread → main thread UI update)
    // -------------------------------------------------------------------------

    private void generateOrLoadCaInBackground() {
        new Thread(() -> {
            try {
                CertificateManager cm = CertificateManager.getInstance();
                // Persist to / load from context.getFilesDir()
                cm.initialize(CertInstallActivity.this);

                caCertDer = cm.getCaCertDer();

                // Write to app-private storage (no permission needed)
                File privateFile = new File(getFilesDir(), CA_FILENAME);
                writeFile(privateFile, caCertDer);

                // Write to external app-specific storage for manual install fallback
                File extDir = getExternalFilesDir(null);
                if (extDir != null) {
                    writeFile(new File(extDir, CA_FILENAME), caCertDer);
                }

                runOnUiThread(() -> {
                    tvStatus.setText(
                            "Root CA ready (" + caCertDer.length + " bytes)\n"
                            + "Tap below to install as a trusted certificate.");
                    btnInstall.setEnabled(true);
                    progressBar.setVisibility(View.GONE);
                });

            } catch (Exception e) {
                runOnUiThread(() -> {
                    tvStatus.setText("CA initialisation failed:\n" + e.getMessage());
                    progressBar.setVisibility(View.GONE);
                });
            }
        }, "ca-init").start();
    }

    private static void writeFile(File dest, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(dest)) {
            fos.write(data);
        }
    }

    // -------------------------------------------------------------------------
    // System certificate installer
    // -------------------------------------------------------------------------

    private void launchSystemInstaller() {
        if (caCertDer == null) {
            Toast.makeText(this, "CA not ready yet — please wait",
                    Toast.LENGTH_SHORT).show();
            return;
        }
        try {
            Intent installIntent = KeyChain.createInstallIntent();
            installIntent.putExtra(KeyChain.EXTRA_CERTIFICATE, caCertDer);
            installIntent.putExtra(KeyChain.EXTRA_NAME, "SentinelNode CA");
            installLauncher.launch(installIntent);
        } catch (Exception e) {
            // Fallback: open Security Settings for manual install
            Toast.makeText(this,
                    "Auto-install unavailable — use manual steps below.",
                    Toast.LENGTH_LONG).show();
            startActivity(new Intent(
                    android.provider.Settings.ACTION_SECURITY_SETTINGS));
        }
    }
}
