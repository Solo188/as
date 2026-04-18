package com.flow.validator.service;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.util.Log;

/**
 * BootReceiver — Restarts MainService after device reboot.
 *
 * Handles both BOOT_COMPLETED (normal boot) and LOCKED_BOOT_COMPLETED
 * (direct-boot mode on API 24+) so the compliance engine activates as
 * early in the boot sequence as possible.
 *
 * RECEIVE_BOOT_COMPLETED permission is declared in AndroidManifest.xml.
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "BootReceiver";

    @Override
    public void onReceive(Context context, Intent intent) {
        String action = intent.getAction();
        if (Intent.ACTION_BOOT_COMPLETED.equals(action)
                || "android.intent.action.LOCKED_BOOT_COMPLETED".equals(action)) {

            Log.i(TAG, "Boot detected (" + action + ") — starting MainService");

            Intent svcIntent = new Intent(context, MainService.class);
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(svcIntent);
            } else {
                context.startService(svcIntent);
            }
        }
    }
}
