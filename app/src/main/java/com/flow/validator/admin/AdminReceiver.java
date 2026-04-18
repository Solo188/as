package com.flow.validator.admin;

import android.app.admin.DeviceAdminReceiver;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * AdminReceiver — Device Policy Management receiver (SentinelNode Elite).
 *
 * <p>Handles admin enable/disable lifecycle events and provides static
 * helpers for policy enforcement called from {@link com.flow.validator.service.MainService}.
 *
 * <p>Policies applied on admin activation (Device Owner required for *):
 * <ul>
 *   <li>Minimum password quality: ALPHANUMERIC (PIN/pattern not enough)</li>
 *   <li>Minimum password length: 8 characters</li>
 *   <li>{@code setUninstallBlocked} * — prevents app removal</li>
 *   <li>{@code setKeyguardDisabled} * — optional kiosk mode</li>
 *   <li>{@code setCameraDisabled}   * — optional high-security mode</li>
 * </ul>
 */
public class AdminReceiver extends DeviceAdminReceiver {

    private static final String TAG = "AdminReceiver";

    // =========================================================================
    // Lifecycle callbacks
    // =========================================================================

    @Override
    public void onEnabled(Context context, Intent intent) {
        super.onEnabled(context, intent);
        Log.i(TAG, "Device Admin enabled");
        applyBaselinePolicies(context);
    }

    @Override
    public void onDisabled(Context context, Intent intent) {
        super.onDisabled(context, intent);
        Log.w(TAG, "Device Admin disabled — compliance policies removed");
    }

    @Override
    public CharSequence onDisableRequested(Context context, Intent intent) {
        // Return a warning message shown to the user attempting to deactivate admin
        return "Disabling SentinelNode will remove all compliance policies from this device.";
    }

    @Override
    public void onPasswordFailed(Context context, Intent intent, android.os.UserHandle user) {
        Log.w(TAG, "Password attempt failed — possible brute force");
    }

    @Override
    public void onLockTaskModeEntering(Context context, Intent intent, String pkg) {
        Log.i(TAG, "Lock task mode entering for: " + pkg);
    }

    // =========================================================================
    // Public static API — called from MainService
    // =========================================================================

    public static ComponentName getComponentName(Context context) {
        return new ComponentName(context.getApplicationContext(), AdminReceiver.class);
    }

    /**
     * Block / unblock app uninstallation.
     * Requires Device Owner status. Safe to call speculatively — checks ownership first.
     */
    public static void setPersistence(Context context, boolean locked) {
        DevicePolicyManager dpm = getDpm(context);
        ComponentName cn = getComponentName(context);
        if (dpm.isDeviceOwnerApp(context.getPackageName())) {
            dpm.setUninstallBlocked(cn, context.getPackageName(), locked);
            Log.i(TAG, "Uninstall blocked: " + locked);
        }
    }

    /**
     * Enable or disable the device keyguard (lock screen).
     * Requires Device Owner. Use for kiosk / single-app deployments only.
     *
     * @param disabled {@code true} to disable the keyguard entirely.
     */
    public static void setKeyguardPolicy(Context context, boolean disabled) {
        DevicePolicyManager dpm = getDpm(context);
        ComponentName cn = getComponentName(context);
        if (dpm.isDeviceOwnerApp(context.getPackageName())) {
            dpm.setKeyguardDisabled(cn, disabled);
            Log.i(TAG, "Keyguard disabled: " + disabled);
        }
    }

    /**
     * Enable or disable all device cameras.
     * Requires active Device Admin (not necessarily Device Owner).
     */
    public static void setCameraPolicy(Context context, boolean disabled) {
        DevicePolicyManager dpm = getDpm(context);
        ComponentName cn = getComponentName(context);
        if (dpm.isAdminActive(cn)) {
            dpm.setCameraDisabled(cn, disabled);
            Log.i(TAG, "Camera disabled: " + disabled);
        }
    }

    /**
     * Perform a factory reset (wipe) of the device.
     * DESTRUCTIVE — gate behind multi-step confirmation in the calling UI.
     *
     * @param flags 0 for soft wipe; DevicePolicyManager.WIPE_RESET_PROTECTION_DATA
     *              to also remove Factory Reset Protection credentials.
     */
    public static void wipeDevice(Context context, int flags) {
        DevicePolicyManager dpm = getDpm(context);
        if (dpm.isAdminActive(getComponentName(context))) {
            Log.w(TAG, "Device wipe initiated with flags=" + flags);
            dpm.wipeData(flags);
        }
    }

    /**
     * Immediately lock the device screen.
     * Requires FORCE-LOCK policy declared in device_admin_rules.xml.
     */
    public static void lockNow(Context context) {
        DevicePolicyManager dpm = getDpm(context);
        if (dpm.isAdminActive(getComponentName(context))) {
            dpm.lockNow();
        }
    }

    // =========================================================================
    // Internal helpers
    // =========================================================================

    private static DevicePolicyManager getDpm(Context context) {
        return (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
    }

    /**
     * Apply baseline MDM policies immediately after admin is granted.
     * Non-destructive — only sets password quality and length minimums.
     */
    private void applyBaselinePolicies(Context context) {
        DevicePolicyManager dpm = getDpm(context);
        ComponentName cn = getComponentName(context);

        // Require at least alphanumeric password
        dpm.setPasswordQuality(cn, DevicePolicyManager.PASSWORD_QUALITY_ALPHANUMERIC);
        dpm.setPasswordMinimumLength(cn, 8);
        Log.i(TAG, "Baseline password policy applied");

        // Lock screen timeout — max 5 minutes of inactivity
        dpm.setMaximumTimeToLock(cn, 5 * 60 * 1000L);

        // If Device Owner: apply uninstall block immediately
        if (dpm.isDeviceOwnerApp(context.getPackageName())) {
            dpm.setUninstallBlocked(cn, context.getPackageName(), true);
            Log.i(TAG, "Device Owner policies applied on admin enable");
        }
    }
}
