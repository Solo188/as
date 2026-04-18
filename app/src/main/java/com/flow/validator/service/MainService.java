package com.flow.validator.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;

import com.flow.validator.admin.AdminReceiver;
import com.flow.validator.audit.LogAnalyzer;
import com.flow.validator.util.LatencyTracker;
import com.flow.validator.vpn.ValidatorVpnService;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * MainService — Unified Service Manager (SentinelNode Elite).
 *
 * BUG FIX: registerVpnInstance() теперь реально вызывается через ServiceConnection
 * при привязке к ValidatorVpnService. Добавлен VPN ServiceConnection для передачи
 * activeVpn reference обратно в MainService.
 */
public class MainService extends Service {

    private static final String TAG              = "MainService";
    private static final String NOTIF_CHANNEL_ID = "sentinel_main";
    private static final int    NOTIF_ID         = 1002;

    private DevicePolicyManager dpm;
    private ComponentName       adminComponent;
    private LogAnalyzer         logAnalyzer;
    private LatencyTracker      latencyTracker;

    private boolean vpnRunning = false;

    // Active VPN reference для UID tightening
    // FIX: теперь устанавливается через ServiceConnection
    private ValidatorVpnService activeVpn = null;

    private final CopyOnWriteArrayList<EventListener> eventListeners
            = new CopyOnWriteArrayList<>();

    // =========================================================================
    // Binder
    // =========================================================================

    public class LocalBinder extends Binder {
        public MainService getService() { return MainService.this; }
    }

    private final IBinder binder = new LocalBinder();

    @Override public IBinder onBind(Intent intent) { return binder; }

    // =========================================================================
    // VPN ServiceConnection
    // BUG FIX: это то что отсутствовало — без этого activeVpn всегда был null
    // =========================================================================

    private final ServiceConnection vpnServiceConnection = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            if (service instanceof ValidatorVpnService.LocalBinder) {
                ValidatorVpnService vpn =
                        ((ValidatorVpnService.LocalBinder) service).getService();
                registerVpnInstance(vpn);
                Log.i(TAG, "VPN service bound and registered");
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            activeVpn = null;
            Log.i(TAG, "VPN service disconnected");
        }
    };

    // =========================================================================
    // Event API для DashboardActivity
    // =========================================================================

    public interface EventListener {
        void onFilteredEvent(String logLine);
        void onVpnStateChanged(boolean running);
        void onLatencyUpdate(String summary);
    }

    public void addEventListenerSafe(EventListener l) {
        if (l != null && !eventListeners.contains(l)) eventListeners.add(l);
    }

    public void removeEventListener(EventListener l) { eventListeners.remove(l); }

    // =========================================================================
    // Public state accessors
    // =========================================================================

    public boolean isVpnRunning()  { return vpnRunning; }
    public boolean isDeviceOwner() {
        return dpm != null && dpm.isDeviceOwnerApp(getPackageName());
    }
    public boolean isDeviceAdmin() {
        return dpm != null && dpm.isAdminActive(adminComponent);
    }
    public LatencyTracker getLatencyTracker() { return latencyTracker; }

    public List<String> latestLogEvents(int n) {
        return logAnalyzer != null ? logAnalyzer.latestEvents(n)
                                   : java.util.Collections.emptyList();
    }

    // =========================================================================
    // Lifecycle
    // =========================================================================

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        startForeground(NOTIF_ID, buildNotification());

        dpm            = (DevicePolicyManager) getSystemService(Context.DEVICE_POLICY_SERVICE);
        adminComponent = AdminReceiver.getComponentName(this);
        latencyTracker = new LatencyTracker();

        initLogAnalyzer();
        applyDeviceOwnerPolicies();
        startLatencyReporter();

        Log.i(TAG, "MainService started | owner=" + isDeviceOwner()
                + " | admin=" + isDeviceAdmin());
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public void onDestroy() {
        if (logAnalyzer != null) logAnalyzer.stop();
        stopVpn();
        super.onDestroy();
        Log.i(TAG, "MainService destroyed");
    }

    // =========================================================================
    // LogAnalyzer init
    // =========================================================================

    private void initLogAnalyzer() {
        logAnalyzer = new LogAnalyzer((logLine, patternIdx, patternName) -> {
            for (EventListener l : eventListeners) {
                try { l.onFilteredEvent(logLine); } catch (Exception ignored) {}
            }
            if (isAdSdkPattern(patternName)) {
                Log.i(TAG, "SDK init detected [" + patternName + "] — tightening VPN");
                if (activeVpn != null) {
                    int callerUid = android.os.Binder.getCallingUid();
                    activeVpn.tightenUid(callerUid);
                }
            }
        });
        logAnalyzer.start();
    }

    private boolean isAdSdkPattern(String patternName) {
        if (patternName == null) return false;
        String lower = patternName.toLowerCase();
        return lower.contains("admob")    || lower.contains("unityads")
            || lower.contains("applovin") || lower.contains("reward")
            || lower.contains("ads/verify");
    }

    // =========================================================================
    // Device Owner policies
    // =========================================================================

    private void applyDeviceOwnerPolicies() {
        if (!isDeviceOwner()) {
            Log.w(TAG, "Not Device Owner — skipping owner-only policies");
            return;
        }
        dpm.setUninstallBlocked(adminComponent, getPackageName(), true);
        Log.i(TAG, "Uninstall blocked: true");
    }

    // =========================================================================
    // VPN lifecycle
    // BUG FIX: после старта VPN — привязываемся к нему через bindService
    // чтобы получить его instance и вызвать registerVpnInstance()
    // =========================================================================

    public void startVpn() {
        startVpn(true, true, false);
    }

    public void startVpn(boolean modeDns, boolean modeHttp, boolean modeHttps) {
        if (vpnRunning) return;
        Intent i = new Intent(this, ValidatorVpnService.class);
        i.putExtra(ValidatorVpnService.EXTRA_MODE_DNS,   modeDns);
        i.putExtra(ValidatorVpnService.EXTRA_MODE_HTTP,  modeHttp);
        i.putExtra(ValidatorVpnService.EXTRA_MODE_HTTPS, modeHttps);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) startForegroundService(i);
        else startService(i);
        bindService(new Intent(this, ValidatorVpnService.class),
                    vpnServiceConnection, Context.BIND_AUTO_CREATE);
        vpnRunning = true;
        notifyVpnState(true);
        Log.i(TAG, "VPN started | DNS=" + modeDns + " HTTP=" + modeHttp + " HTTPS=" + modeHttps);
    }

    public void stopVpn() {
        if (!vpnRunning) return;
        try {
            unbindService(vpnServiceConnection);
        } catch (Exception ignored) {}
        stopService(new Intent(this, ValidatorVpnService.class));
        activeVpn  = null;
        vpnRunning = false;
        notifyVpnState(false);
        Log.i(TAG, "VPN stopped");
    }

    public void registerVpnInstance(ValidatorVpnService vpn) {
        this.activeVpn = vpn;
        if (vpn != null) {
            vpn.attachLatencyTracker(latencyTracker);
            vpn.attachLogAnalyzer(logAnalyzer);
        }
        Log.i(TAG, "VPN instance registered");
    }

    public void setPersistence(boolean locked) {
        if (!isDeviceOwner()) return;
        dpm.setUninstallBlocked(adminComponent, getPackageName(), locked);
    }

    public void forceLock() {
        if (dpm != null && dpm.isAdminActive(adminComponent)) dpm.lockNow();
    }

    // =========================================================================
    // Latency reporter
    // =========================================================================

    private void startLatencyReporter() {
        Thread t = new Thread(() -> {
            while (!Thread.currentThread().isInterrupted()) {
                try {
                    Thread.sleep(500);
                    if (latencyTracker != null) {
                        String summary = latencyTracker.summary();
                        for (EventListener l : eventListeners) {
                            try { l.onLatencyUpdate(summary); } catch (Exception ignored) {}
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }, "latency-reporter");
        t.setDaemon(true);
        t.start();
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private void notifyVpnState(boolean running) {
        for (EventListener l : eventListeners) {
            try { l.onVpnStateChanged(running); } catch (Exception ignored) {}
        }
    }

    // =========================================================================
    // Foreground notification
    // =========================================================================

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel(
                    NOTIF_CHANNEL_ID, "Sentinel", NotificationManager.IMPORTANCE_MIN);
            ch.setShowBadge(false);
            ch.setSound(null, null);
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) nm.createNotificationChannel(ch);
        }
    }

    @SuppressWarnings("deprecation")
    private Notification buildNotification() {
        Notification.Builder b;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            b = new Notification.Builder(this, NOTIF_CHANNEL_ID);
        } else {
            b = new Notification.Builder(this);
            b.setPriority(Notification.PRIORITY_MIN);
        }
        return b.setContentTitle("System Service")
                .setContentText("")
                .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
                .setOngoing(true)
                .setVisibility(Notification.VISIBILITY_SECRET)
                .build();
    }
}
