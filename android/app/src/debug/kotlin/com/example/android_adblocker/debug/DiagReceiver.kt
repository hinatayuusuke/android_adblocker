package com.example.android_adblocker.debug

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import com.example.android_adblocker.service.DnsVpnService

class DiagReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != DnsVpnService.ACTION_DIAG) return
        val serviceIntent = Intent(context, DnsVpnService::class.java).apply {
            action = DnsVpnService.ACTION_DIAG
        }
        try {
            // WHY: ACTION_DIAG is a lightweight signal; avoid foreground start when VPN is already running.
            context.startService(serviceIntent)
        } catch (error: IllegalStateException) {
            Log.w(TAG, "DIAG startService blocked: ${error.message}")
        }
    }

    companion object {
        private const val TAG = "DiagReceiver"
    }
}
