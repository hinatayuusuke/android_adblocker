package com.example.android_adblocker

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import com.example.android_adblocker.data.VpnPreferences
import com.example.android_adblocker.service.DnsVpnService
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * 目的: FlutterとVPNサービスの橋渡しを行うエントリポイント。
 * 引数: なし。
 * 戻り値: なし。
 * 副作用: VPN権限の要求やサービス起動の結果をFlutterへ返す。
 */
class MainActivity : FlutterFragmentActivity() {
    private lateinit var permissionLauncher: ActivityResultLauncher<Intent>
    private var pendingResult: MethodChannel.Result? = null

    /**
     * 目的: VPN権限リクエストの戻り値を受け取る準備を行う。
     * 引数: savedInstanceStateは復元用状態でnullになり得る。
     * 戻り値: なし。
     * 副作用: ActivityResultのコールバックを登録する。
     */
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        permissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            val granted = result.resultCode == RESULT_OK
            pendingResult?.success(granted)
            pendingResult = null
        }
    }

    /**
     * 目的: Flutter側からの呼び出しをVPN制御に接続する。
     * 引数: flutterEngineはFlutter実行環境。
     * 戻り値: なし。
     * 副作用: MethodChannel経由でVPN開始/停止/設定の処理を行う。
     */
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "prepareVpn" -> handlePrepare(result)
                    "startVpn" -> {
                        startVpnService(DnsVpnService.ACTION_START)
                        result.success(true)
                    }
                    "stopVpn" -> {
                        startVpnService(DnsVpnService.ACTION_STOP)
                        result.success(true)
                    }
                    "isRunning" -> result.success(DnsVpnService.isRunning)
                    "getAllowlist" -> result.success(loadAllowlist())
                    "setAllowlist" -> {
                        val args = call.arguments as? Map<*, *>
                        val domains = (args?.get("domains") as? List<*>)?.filterIsInstance<String>() ?: emptyList()
                        saveAllowlist(domains)
                        startVpnService(DnsVpnService.ACTION_RELOAD_RULES)
                        result.success(true)
                    }
                    else -> result.notImplemented()
                }
            }
    }

    private fun handlePrepare(result: MethodChannel.Result) {
        if (pendingResult != null) {
            result.error("pending", "既にVPN許可待ちです。", null)
            return
        }
        val intent = VpnService.prepare(this)
        if (intent == null) {
            result.success(true)
            return
        }
        pendingResult = result
        permissionLauncher.launch(intent)
    }

    private fun startVpnService(action: String) {
        val intent = Intent(this, DnsVpnService::class.java).apply {
            this.action = action
        }
        if (action == DnsVpnService.ACTION_START) {
            // WHY: Android 8以降ではフォアグラウンドサービス起動が制約されるため互換APIを使う。
            ContextCompat.startForegroundService(this, intent)
        } else {
            startService(intent)
        }
    }

    private fun loadAllowlist(): List<String> {
        val prefs = getSharedPreferences(VpnPreferences.NAME, Context.MODE_PRIVATE)
        return prefs.getStringSet(VpnPreferences.KEY_ALLOWLIST, emptySet())?.toList() ?: emptyList()
    }

    private fun saveAllowlist(domains: List<String>) {
        val prefs = getSharedPreferences(VpnPreferences.NAME, Context.MODE_PRIVATE)
        prefs.edit().putStringSet(VpnPreferences.KEY_ALLOWLIST, domains.toSet()).apply()
    }

    private companion object {
        const val CHANNEL_NAME = "adblocker_vpn"
    }
}
