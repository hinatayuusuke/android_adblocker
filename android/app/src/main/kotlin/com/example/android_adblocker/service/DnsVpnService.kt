package com.example.android_adblocker.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.android_adblocker.BuildConfig
import com.example.android_adblocker.MainActivity
import com.example.android_adblocker.R
import com.example.android_adblocker.core.DnsPacketProcessor
import com.example.android_adblocker.core.DomainRuleMatcher
import com.example.android_adblocker.data.BlocklistLoader
import com.example.android_adblocker.data.VpnPreferences
import com.example.android_adblocker.net.UpstreamResolver
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * 目的: 端末内でDNSクエリのみを処理するVPNサービスを提供する。
 * 引数: なし。
 * 戻り値: なし。
 * 副作用: VPNインタフェースの確立、フォアグラウンド通知、DNS通信を行う。
 */
class DnsVpnService : VpnService() {
    /**
     * 目的: 通知チャネルを初期化してVPN稼働通知の準備を整える。
     * 引数: なし。
     * 戻り値: なし。
     * 副作用: 通知チャネルを登録する。
     */
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    /**
     * 目的: VPNの開始/停止要求を受けてサービス状態を更新する。
     * 引数: intentは開始/停止/再読込アクションを含み得る。flagsはシステムから付与される制御値。startIdはサービス識別子。
     * 戻り値: 再起動方針としてSTART_STICKYを返す。
     * 副作用: VPNインタフェースの生成/破棄、通知表示、バックグラウンド処理を行う。
     */
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> stopVpn()
            ACTION_RELOAD_RULES -> reloadAllowlist()
            else -> startVpn()
        }
        return START_STICKY
    }

    /**
     * 目的: サービス終了時にVPN関連のリソースを解放する。
     * 引数: なし。
     * 戻り値: なし。
     * 副作用: VPNインタフェースとソケットを閉じる。
     */
    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    /**
     * 目的: システムによりVPNが取り消された際に状態を整合させる。
     * 引数: なし。
     * 戻り値: なし。
     * 副作用: VPNインタフェースとソケットを閉じ、サービスを停止する。
     */
    override fun onRevoke() {
        stopVpn()
        super.onRevoke()
    }

    private fun startVpn() {
        if (isRunning) return
        val builder = Builder()
            .setSession("DNS AdBlocker")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_SERVER)
            .addRoute(DNS_SERVER, 32)

        val vpnInterface = builder.establish() ?: return
        val allowlist = loadAllowlist()
        val matcher = DomainRuleMatcher(emptySet(), allowlist)
        val sockets = createUpstreamSockets()
        if (sockets.isEmpty()) {
            vpnInterface.close()
            return
        }

        vpnFd = vpnInterface
        upstreamSockets = sockets
        ruleMatcher = matcher
        stopSignal.set(false)

        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // WHY: targetSdk 34+ ではFGS種別指定が必須のため。
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        isRunning = true
        startNetworkMonitor()

        workerThread = Thread {
            runPacketLoop(vpnInterface, sockets, matcher)
        }.apply { start() }

        // WHY: FGS開始猶予を超えないよう、重いブロックリスト読込は別スレッドで行う。
        Thread {
            val blocklist = BlocklistLoader.load(applicationContext, BLOCKLIST_ASSET)
            if (!stopSignal.get()) {
                matcher.updateBlocklist(blocklist)
            }
        }.start()
    }

    private fun stopVpn() {
        if (!isRunning) return
        stopSignal.set(true)
        stopNetworkMonitor()
        workerThread?.interrupt()
        workerThread = null
        responseWriter?.interrupt()
        responseWriter = null
        synchronized(upstreamResetLock) {
            shutdownUpstreamLocked()
        }
        vpnFd?.close()
        vpnFd = null
        ruleMatcher = null
        processor = null
        requestQueue = null
        responseQueue = null
        stopForeground(true)
        isRunning = false
        stopSelf()
    }

    private fun reloadAllowlist() {
        ruleMatcher?.updateAllowlist(loadAllowlist())
    }

    private fun runPacketLoop(
        vpnInterface: ParcelFileDescriptor,
        sockets: List<DatagramSocket>,
        matcher: DomainRuleMatcher
    ) {
        val input = FileInputStream(vpnInterface.fileDescriptor)
        val output = FileOutputStream(vpnInterface.fileDescriptor)
        val buffer = ByteArray(PACKET_BUFFER_SIZE)
        val processor = DnsPacketProcessor(
            dnsServer = DNS_SERVER_INT,
            matcher = matcher
        )
        this.processor = processor
         // WHY: 上流遅延時に無制限に溜めないよう、キューは上限を設ける。
        val requestQueue = ArrayBlockingQueue<DnsPacketProcessor.UpstreamJob>(UPSTREAM_QUEUE_CAPACITY)
        val responseQueue = ArrayBlockingQueue<ByteArray>(RESPONSE_QUEUE_CAPACITY)
        this.requestQueue = requestQueue
        this.responseQueue = responseQueue
        startResponseWriter(output, responseQueue)
        startUpstreamWorkers(sockets, requestQueue, responseQueue, processor)

        try {
            while (!stopSignal.get()) {
                val length = try {
                    input.read(buffer)
                } catch (error: IOException) {
                    Log.w(TAG, "VPN読み込み失敗: ${error.message}")
                    break
                }
                if (length < 0) {
                    Log.w(TAG, "VPN読み込みが終了したため停止します。")
                    break
                }
                if (length == 0) continue
                val outcome = processor.handlePacket(buffer, length) ?: continue
                when (outcome) {
                    is DnsPacketProcessor.Outcome.Immediate -> enqueueResponse(responseQueue, outcome.response)
                    is DnsPacketProcessor.Outcome.Upstream -> {
                        // WHY: 短時間待機の offer(timeout) を入れて、キュー満杯時の即SERVFAILを減らす
                        val offered = try {
                            requestQueue.offer(outcome.job, REQUEST_QUEUE_WAIT_MS, TimeUnit.MILLISECONDS)
                        } catch (_: InterruptedException) {
                            Thread.currentThread().interrupt()
                            return
                        }
                        if (!offered) {
                            // WHY: 読み取りスレッドを塞がないため、即時に失敗応答を返す。
                            val responsePayload = processor.buildServfailResponse(outcome.job.query)
                            val response = processor.buildUdpResponse(outcome.job.packetInfo, responsePayload)
                            enqueueResponse(responseQueue, response)
                            val count = servfailCount.incrementAndGet()
                            if (DEBUG_LOGS) {
                                Log.d(TAG, "servfail fallback count=$count requestQueueSize=${requestQueue.size}")
                            }
                        }
                    }
                }
            }
        } finally {
            if (!stopSignal.get()) {
                Log.w(TAG, "VPN処理が中断したためサービスを終了します。")
                stopVpn()
            }
        }
    }

    private fun startResponseWriter(
        output: FileOutputStream,
        responseQueue: BlockingQueue<ByteArray>
    ) {
        responseWriter = Thread {
            val batch = ArrayList<ByteArray>(RESPONSE_DRAIN_MAX)
            while (!stopSignal.get()) {
                val response = try {
                    responseQueue.take()
                } catch (_: InterruptedException) {
                    break
                }
                // WHY: ロック取得とwrite回数を減らすため、まとめて書き込む。
                batch.clear()
                batch.add(response)
                responseQueue.drainTo(batch, RESPONSE_DRAIN_MAX - 1)
                try {
                    for (payload in batch) {
                        output.write(payload)
                    }
                } catch (error: IOException) {
                    Log.w(TAG, "VPN書き込み失敗: ${error.message}")
                    break
                }
            }
        }.apply { start() }
    }

    private fun startUpstreamWorkers(
        sockets: List<DatagramSocket>,
        requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>,
        responseQueue: BlockingQueue<ByteArray>,
        processor: DnsPacketProcessor
    ) {
        upstreamWorkers = sockets.map { socket ->
            Thread {
                val resolver = UpstreamResolver(socket, UPSTREAM_DNS)
                while (!stopSignal.get()) {
                    val job = try {
                        requestQueue.take()
                    } catch (_: InterruptedException) {
                        break
                    }
                    val responsePayload = resolver.resolve(job.queryPayload)
                        ?: processor.buildServfailResponse(job.query)
                    val response = processor.buildUdpResponse(job.packetInfo, responsePayload)
                    enqueueResponse(responseQueue, response)
                }
            }.apply { start() }
        }
    }

    private fun enqueueResponse(queue: BlockingQueue<ByteArray>, response: ByteArray) {
        if (!queue.offer(response)) {
            Log.w(TAG, "DNS応答キューが満杯のため破棄します。")
            val count = responseDropCount.incrementAndGet()
            if (DEBUG_LOGS) {
                Log.d(TAG, "response drop count=$count responseQueueSize=${queue.size}")
            }
        }
    }

    private fun startNetworkMonitor() {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                handleNetworkChange()
            }

            override fun onLost(network: Network) {
                handleNetworkChange()
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                handleNetworkChange()
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            manager.registerDefaultNetworkCallback(callback)
        } else {
            manager.registerNetworkCallback(NetworkRequest.Builder().build(), callback)
        }
        connectivityManager = manager
        networkCallback = callback
    }

    private fun stopNetworkMonitor() {
        val manager = connectivityManager ?: return
        val callback = networkCallback ?: return
        try {
            manager.unregisterNetworkCallback(callback)
        } catch (_: IllegalArgumentException) {
            // WHY: コールバックが登録されていない場合に発生する。
        }
        connectivityManager = null
        networkCallback = null
    }

    private fun handleNetworkChange() {
        if (!isRunning || stopSignal.get()) return
        val currentProcessor = processor ?: return
        val currentRequestQueue = requestQueue ?: return
        val currentResponseQueue = responseQueue ?: return
        synchronized(upstreamResetLock) {
            if (!isRunning || stopSignal.get()) return
            // WHY: 旧経路の滞留を残さず復旧後詰まりを減らす。
            currentResponseQueue.clear()
            shutdownUpstreamLocked()
            val sockets = createUpstreamSockets()
            if (sockets.isEmpty()) return
            upstreamSockets = sockets
            startUpstreamWorkers(sockets, currentRequestQueue, currentResponseQueue, currentProcessor)
        }
    }

    private fun createUpstreamSockets(): List<DatagramSocket> {
        val sockets = mutableListOf<DatagramSocket>()
        repeat(UPSTREAM_WORKER_COUNT) {
            val socket = DatagramSocket().apply {
                soTimeout = UPSTREAM_TIMEOUT_MS
            }
            if (!protect(socket)) {
                socket.close()
                sockets.forEach { it.close() }
                return emptyList()
            }
            sockets.add(socket)
        }
        return sockets
    }

    private fun shutdownUpstreamLocked() {
        upstreamWorkers.forEach { it.interrupt() }
        upstreamWorkers = emptyList()
        upstreamSockets.forEach { it.close() }
        upstreamSockets = emptyList()
    }

    private fun buildNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("DNS AdBlocker")
            .setContentText("DNSフィルタが稼働中です。")
            .setSmallIcon(R.mipmap.ic_launcher)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "DNS AdBlocker",
            NotificationManager.IMPORTANCE_LOW
        )
        manager.createNotificationChannel(channel)
    }

    private fun loadAllowlist(): Set<String> {
        val prefs = getSharedPreferences(VpnPreferences.NAME, Context.MODE_PRIVATE)
        return prefs.getStringSet(VpnPreferences.KEY_ALLOWLIST, emptySet())?.toSet() ?: emptySet()
    }

    companion object {
        const val ACTION_START = "com.example.android_adblocker.action.START"
        const val ACTION_STOP = "com.example.android_adblocker.action.STOP"
        const val ACTION_RELOAD_RULES = "com.example.android_adblocker.action.RELOAD_RULES"
        const val NOTIFICATION_CHANNEL_ID = "adblocker_vpn"
        const val NOTIFICATION_ID = 1001

        private const val TAG = "DnsVpnService"

        private const val VPN_ADDRESS = "10.0.0.2"
        private const val DNS_SERVER = "10.0.0.1"
        private const val DNS_SERVER_INT = 0x0A000001
        private val UPSTREAM_DNS = InetSocketAddress("1.1.1.1", 53)
        private const val UPSTREAM_TIMEOUT_MS = 2000
        private const val UPSTREAM_WORKER_COUNT = 6
        private const val UPSTREAM_QUEUE_CAPACITY = 512
        private const val RESPONSE_QUEUE_CAPACITY = 512
        private const val RESPONSE_DRAIN_MAX = 32
        private const val BLOCKLIST_ASSET = "blocklist.txt"
        private const val PACKET_BUFFER_SIZE = 32767
        private const val REQUEST_QUEUE_WAIT_MS = 10L
        private val DEBUG_LOGS = BuildConfig.DEBUG

        @Volatile
        var isRunning: Boolean = false
            private set
    }

    private var vpnFd: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private var responseWriter: Thread? = null
    private var upstreamWorkers: List<Thread> = emptyList()
    private var upstreamSockets: List<DatagramSocket> = emptyList()
    private var ruleMatcher: DomainRuleMatcher? = null
    private var processor: DnsPacketProcessor? = null
    private var requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>? = null
    private var responseQueue: BlockingQueue<ByteArray>? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val upstreamResetLock = Any()
    private val servfailCount = AtomicInteger(0)
    private val responseDropCount = AtomicInteger(0)
    private val stopSignal = AtomicBoolean(false)
}
