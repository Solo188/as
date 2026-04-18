package com.flow.validator.ui;

import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.flow.validator.R;
import com.flow.validator.admin.AdminReceiver;
import com.flow.validator.service.MainService;
import com.flow.validator.ui.adapter.LogAdapter;
import com.flow.validator.vpn.ValidatorVpnService;
import com.google.android.material.materialswitch.MaterialSwitch;

import java.util.ArrayList;
import java.util.List;

/**
 * DashboardActivity — управление тремя независимыми режимами:
 *   toggle_mode_dns   — DNS блокировка (работает без root)
 *   toggle_mode_http  — HTTP DPI (работает без root)
 *   toggle_mode_https — HTTPS блокировка по SNI (без расшифровки, без root)
 *
 * VPN запускается один раз, режимы передаются как Intent extras.
 */
public class DashboardActivity extends AppCompatActivity
        implements MainService.EventListener {

    // UI
    private MaterialSwitch toggleDns;
    private MaterialSwitch toggleHttp;
    private MaterialSwitch toggleHttps;
    private MaterialSwitch toggleVpn;
    private TextView       tvOwnerStatus;
    private TextView       tvLatencyValue;
    private TextView       tvLatencyStatus;
    private TextView       tvFilterCount;
    private RecyclerView   rvLogs;
    private LogAdapter     logAdapter;

    // Service
    private MainService mainService;
    private boolean     isBound = false;

    private final List<String> logLines = new ArrayList<>();
    private int filteredCount = 0;
    private final Handler uiHandler = new Handler(Looper.getMainLooper());

    // VPN permission launcher
    private final ActivityResultLauncher<Intent> vpnPermLauncher =
        registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            result -> {
                if (result.getResultCode() == RESULT_OK) {
                    startVpnWithCurrentModes();
                } else {
                    setToggleChecked(toggleVpn, false);
                    Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show();
                }
            });

    // =========================================================================
    // Lifecycle
    // =========================================================================

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_dashboard);
        bindViews();
        setupRecyclerView();
        setupSwitches();

        Intent svc = new Intent(this, MainService.class);
        startService(svc);
        bindService(svc, serviceConnection, Context.BIND_AUTO_CREATE);
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshComplianceStatus();
    }

    @Override
    protected void onDestroy() {
        if (isBound && mainService != null) {
            mainService.removeEventListener(this);
            unbindService(serviceConnection);
            isBound = false;
        }
        super.onDestroy();
    }

    // =========================================================================
    // View setup
    // =========================================================================

    private void bindViews() {
        toggleDns      = findViewById(R.id.toggle_mode_dns);
        toggleHttp     = findViewById(R.id.toggle_mode_http);
        toggleHttps    = findViewById(R.id.toggle_mode_https);
        toggleVpn      = findViewById(R.id.toggle_protection);
        tvOwnerStatus  = findViewById(R.id.tv_owner_status);
        tvLatencyValue = findViewById(R.id.tv_latency_value);
        tvLatencyStatus= findViewById(R.id.tv_latency_status);
        tvFilterCount  = findViewById(R.id.tv_filter_count);
        rvLogs         = findViewById(R.id.rv_logs);
    }

    private void setupRecyclerView() {
        logAdapter = new LogAdapter(logLines);
        rvLogs.setLayoutManager(new LinearLayoutManager(this));
        rvLogs.setAdapter(logAdapter);
    }

    private void setupSwitches() {
        // Режимы — только изменение флагов, не перезапуск VPN
        toggleDns.setOnCheckedChangeListener((btn, checked) -> {
            // Режим применится при следующем запуске VPN
            if (toggleVpn.isChecked()) {
                Toast.makeText(this, "Перезапустите VPN для применения", Toast.LENGTH_SHORT).show();
            }
        });
        toggleHttp.setOnCheckedChangeListener((btn, checked) -> {
            if (toggleVpn.isChecked()) {
                Toast.makeText(this, "Перезапустите VPN для применения", Toast.LENGTH_SHORT).show();
            }
        });
        toggleHttps.setOnCheckedChangeListener((btn, checked) -> {
            if (toggleVpn.isChecked()) {
                Toast.makeText(this, "Перезапустите VPN для применения", Toast.LENGTH_SHORT).show();
            }
        });

        // Главный VPN toggle
        toggleVpn.setOnCheckedChangeListener((btn, checked) -> {
            if (!isBound || mainService == null) {
                setToggleChecked(toggleVpn, false);
                Toast.makeText(this, "Service not ready", Toast.LENGTH_SHORT).show();
                return;
            }
            if (checked) {
                requestVpnAndStart();
            } else {
                if (mainService != null) mainService.stopVpn();
            }
        });
    }

    private void setToggleChecked(MaterialSwitch sw, boolean checked) {
        sw.setOnCheckedChangeListener(null);
        sw.setChecked(checked);
        setupSwitches();
    }

    // =========================================================================
    // VPN permission + start
    // =========================================================================

    private void requestVpnAndStart() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) {
            vpnPermLauncher.launch(prepare);
        } else {
            startVpnWithCurrentModes();
        }
    }

    private void startVpnWithCurrentModes() {
        if (mainService == null) return;
        mainService.startVpn(
            toggleDns.isChecked(),
            toggleHttp.isChecked(),
            toggleHttps.isChecked()
        );
    }

    // =========================================================================
    // Compliance status
    // =========================================================================

    private void refreshComplianceStatus() {
        DevicePolicyManager dpm =
            (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        boolean isOwner = dpm != null && dpm.isDeviceOwnerApp(getPackageName());
        ComponentName cn = AdminReceiver.getComponentName(this);
        boolean isAdmin  = dpm != null && dpm.isAdminActive(cn);

        if (isOwner) {
            tvOwnerStatus.setText("DEVICE OWNER");
            tvOwnerStatus.setTextColor(0xFF3FB950);
        } else if (isAdmin) {
            tvOwnerStatus.setText("DEVICE ADMIN");
            tvOwnerStatus.setTextColor(0xFFD29922);
        } else {
            tvOwnerStatus.setText("NO ADMIN — DNS+HTTP modes active");
            tvOwnerStatus.setTextColor(0xFF8B949E);
        }
    }

    // =========================================================================
    // MainService.EventListener
    // =========================================================================

    @Override
    public void onFilteredEvent(String logLine) {
        uiHandler.post(() -> {
            filteredCount++;
            tvFilterCount.setText("Filtered: " + filteredCount);
            logLines.add(0, logLine);
            if (logLines.size() > 150) logLines.remove(logLines.size() - 1);
            logAdapter.notifyItemInserted(0);
            rvLogs.scrollToPosition(0);
        });
    }

    @Override
    public void onVpnStateChanged(boolean running) {
        uiHandler.post(() -> {
            setToggleChecked(toggleVpn, running);
            Toast.makeText(this,
                running ? "VPN ON" : "VPN OFF",
                Toast.LENGTH_SHORT).show();
        });
    }

    @Override
    public void onLatencyUpdate(String summary) {
        uiHandler.post(() -> {
            if (tvLatencyValue == null) return;
            tvLatencyValue.setText(summary);
            double avgMs = parseAvgMs(summary);
            if (avgMs < 1.0) {
                tvLatencyStatus.setText("< 1ms OK");
                tvLatencyStatus.setTextColor(0xFF3FB950);
            } else if (avgMs < 5.0) {
                tvLatencyStatus.setText(String.format("%.2f ms WARN", avgMs));
                tvLatencyStatus.setTextColor(0xFFD29922);
            } else {
                tvLatencyStatus.setText(String.format("%.2f ms HIGH", avgMs));
                tvLatencyStatus.setTextColor(0xFFFF7B72);
            }
        });
    }

    private static double parseAvgMs(String summary) {
        try {
            int s = summary.indexOf("avg ") + 4;
            int e = summary.indexOf(" ms");
            if (s > 3 && e > s) return Double.parseDouble(summary.substring(s, e).trim());
        } catch (Exception ignored) {}
        return 0.0;
    }

    // =========================================================================
    // Service connection
    // =========================================================================

    private final ServiceConnection serviceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            mainService = ((MainService.LocalBinder) service).getService();
            isBound     = true;
            mainService.addEventListenerSafe(DashboardActivity.this);

            setToggleChecked(toggleVpn, mainService.isVpnRunning());

            List<String> existing = mainService.latestLogEvents(100);
            logLines.clear();
            logLines.addAll(existing);
            logAdapter.notifyDataSetChanged();
            filteredCount = existing.size();
            tvFilterCount.setText("Filtered: " + filteredCount);
            refreshComplianceStatus();
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            mainService = null;
            isBound     = false;
        }
    };
}
