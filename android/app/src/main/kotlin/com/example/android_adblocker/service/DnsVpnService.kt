package com.example.android_adblocker.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import android.util.Log
import androidx.core.app.NotificationCompat
import com.example.android_adblocker.BuildConfig
import com.example.android_adblocker.MainActivity
import com.example.android_adblocker.R
import com.example.android_adblocker.core.DnsCache
import com.example.android_adblocker.core.DnsMetrics
import com.example.android_adblocker.core.DnsPacketProcessor
import com.example.android_adblocker.core.DomainRuleMatcher
import com.example.android_adblocker.data.BlocklistLoader
import com.example.android_adblocker.data.VpnPreferences
import com.example.android_adblocker.net.UpstreamResolver
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

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
        powerManager = getSystemService(Context.POWER_SERVICE) as PowerManager
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
            ACTION_DIAG -> logDiagnosticSnapshot("intent")
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
        resetScheduler?.shutdownNow()
        resetScheduler = null
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
        val nowMs = System.currentTimeMillis()
        val remainingMs = cooldownRemainingMs(nowMs)
        if (remainingMs > 0) {
            // WHY: Cooldown prevents rapid restart loops from starving the UI thread.
            Log.w(TAG, "VPN restart cooldown active (${remainingMs}ms remaining, lastFatalStopAtMs=$lastFatalStopAtMs)")
            stopSelf()
            return
        }
        val builder = Builder()
            .setSession("DNS AdBlocker")
            .addAddress(VPN_ADDRESS, 32)
            .addDnsServer(DNS_SERVER)
            .addRoute(DNS_SERVER, 32)
            .apply {
                try {
                    addDisallowedApplication(packageName)
                } catch (error: Exception) {
                    // WHY: Some devices throw NameNotFoundException; exclude failure should not block VPN start.
                    Log.w(TAG, "Failed to exclude self from VPN: ${error.message}")
                }
            }

        val vpnInterface = builder.establish() ?: return
        val allowlist = loadAllowlist()
        val matcher = DomainRuleMatcher(emptySet(), allowlist)
        startNetworkMonitor()
        startScreenMonitor()
        val sockets = createUpstreamSockets(currentNetwork)
        val startWithoutUpstream = sockets.isEmpty()
        if (startWithoutUpstream) {
            val caps = connectivityManager?.getNetworkCapabilities(currentNetwork)
            val validated = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            Log.w(TAG, "Upstream socket creation failed on start; network=$currentNetwork validated=$validated")
        }

        vpnFd = vpnInterface
        upstreamSockets = sockets
        ruleMatcher = matcher
        stopSignal.set(false)
        fatalStopRequested = false
        lastPacketAtMs = 0
        lastResponseWriteAtMs = 0
        pendingNetworkReset = false
        lastTunStallResetAtMs = 0
        lastUpstreamSendAtMs = 0
        lastTunPacketAtMs = 0
        lastTunStatsReportAtMs = 0
        tunPacketsInWindow.set(0)
        tunReadableCount.set(0)
        tunReadZeroCount.set(0)
        upstreamConsecutiveFailures.set(0)
        lastUpstreamSuccessAtMs.set(0)
        lastUpstreamFailureAtMs.set(0)
        resetSequence.set(0)
        resetCount.set(0)
        lastResetReason = STATE_STOPPED
        lastResetAtMs = 0
        currentState = STATE_STOPPED
        lastStateChangeAtMs = 0
        upstreamCreateAttempt.set(0)
        resetBackoffMs.set(0)
        resetPending.set(false)
        resetInFlight.set(false)
        resetRetryScheduled.set(false)
        resetCoalesceScheduled.set(false)
        val metrics = DnsMetrics(DEBUG_LOGS)
        this.metrics = metrics
        dnsCache = DnsCache(DNS_CACHE_MAX_ENTRIES, DNS_CACHE_TTL_MS)
        wakeupPipe?.close()
        wakeupPipe = if (USE_POLL_LOOP) {
            createWakeupPipe()
        } else {
            null
        }

        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            // WHY: targetSdk 34+ ではFGS種別指定が必須のため。
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        isRunning = true

        workerThread = Thread(
            {
                runPacketLoop(vpnInterface, sockets, matcher, metrics)
            },
            "packetLoop"
        ).apply { start() }

        if (startWithoutUpstream) {
            updateState(STATE_WAIT_RETRY, "start_no_upstream")
            val delayMs = computeResetBackoffMs()
            Log.w(TAG, "Upstream unavailable at start; scheduling reset in ${delayMs}ms")
            scheduleNetworkResetDelayed("start_no_upstream", delayMs)
        } else {
            updateState(STATE_RUNNING_OK, "start")
        }

        // WHY: FGS開始猶予を超えないよう、重いブロックリスト読込は別スレッドで行う。
        Thread(
            {
                val blocklist = BlocklistLoader.load(applicationContext, BLOCKLIST_ASSET)
                if (!stopSignal.get()) {
                    matcher.updateBlocklist(blocklist)
                }
            },
            "blocklistLoader"
        ).start()
    }

    private fun stopVpn() {
        if (!isRunning) return
        stopSignal.set(true)
        wakeupPipe?.wake()
        lastPacketAtMs = 0
        pendingNetworkReset = false
        lastTunStallResetAtMs = 0
        lastUpstreamSendAtMs = 0
        lastTunPacketAtMs = 0
        lastTunStatsReportAtMs = 0
        tunPacketsInWindow.set(0)
        tunReadableCount.set(0)
        tunReadZeroCount.set(0)
        upstreamConsecutiveFailures.set(0)
        lastUpstreamSuccessAtMs.set(0)
        lastUpstreamFailureAtMs.set(0)
        lastResetReason = STATE_STOPPED
        lastResetAtMs = 0
        resetCount.set(0)
        resetSequence.set(0)
        resetBackoffMs.set(0)
        resetPending.set(false)
        resetInFlight.set(false)
        resetRetryScheduled.set(false)
        stopNetworkMonitor()
        stopScreenMonitor()
        val worker = workerThread
        worker?.interrupt()
        joinThread(worker, "packetLoop")
        workerThread = null
        wakeupPipe?.close()
        wakeupPipe = null
        val writer = responseWriter
        writer?.interrupt()
        joinThread(writer, "responseWriter")
        responseWriter = null
        val watchdog = responseWatchdog
        watchdog?.interrupt()
        joinThread(watchdog, "responseWatchdog")
        responseWatchdog = null
        synchronized(upstreamResetLock) {
            shutdownUpstreamLocked()
        }
        vpnFd?.close()
        vpnFd = null
        ruleMatcher = null
        processor = null
        requestQueue = null
        responseQueue = null
        metrics = DnsMetrics(false)
        dnsCache = null
        lastPacketAtMs = 0
        lastResponseWriteAtMs = 0
        lastResponseEnqueueAtMs = 0
        responseWriterStallCount.set(0)
        fatalStopRequested = false
        stopForeground(true)
        updateState(STATE_STOPPED, "stop")
        isRunning = false
        stopSelf()
    }

    private fun reloadAllowlist() {
        ruleMatcher?.updateAllowlist(loadAllowlist())
    }

    private fun createWakeupPipe(): WakeupPipe? {
        return try {
            WakeupPipe.create()
        } catch (error: Exception) {
            // WHY: Fall back to legacy loop if the control pipe cannot be created.
            Log.w(TAG, "Wakeup pipe create failed: ${error.message}")
            null
        }
    }

    private fun runPacketLoop(
        vpnInterface: ParcelFileDescriptor,
        sockets: List<DatagramSocket>,
        matcher: DomainRuleMatcher,
        metrics: DnsMetrics
    ) {
        val output = FileOutputStream(vpnInterface.fileDescriptor)
        val buffer = ByteArray(PACKET_BUFFER_SIZE)
        val processor = DnsPacketProcessor(
            dnsServer = DNS_SERVER_INT,
            matcher = matcher
        )
        this.processor = processor
        // WHY: Bound queues prevent unbounded memory growth during bursts.
        val requestQueue = ArrayBlockingQueue<DnsPacketProcessor.UpstreamJob>(UPSTREAM_QUEUE_CAPACITY)
        val responseQueue = ArrayBlockingQueue<ByteArray>(RESPONSE_QUEUE_CAPACITY)
        this.requestQueue = requestQueue
        this.responseQueue = responseQueue
        startResponseWriter(output, responseQueue)
        startResponseWatchdog(metrics)
        startUpstreamWorkers(sockets, requestQueue, responseQueue, processor, metrics)

        val usePoll = USE_POLL_LOOP && wakeupPipe != null
        val input = if (usePoll) null else FileInputStream(vpnInterface.fileDescriptor)
        try {
            if (usePoll) {
                runPacketLoopPoll(
                    vpnInterface.fileDescriptor,
                    wakeupPipe!!,
                    buffer,
                    processor,
                    requestQueue,
                    responseQueue
                )
                return
            }
            runPacketLoopLegacy(input!!, buffer, processor, requestQueue, responseQueue)
        } finally {
            if (!stopSignal.get() || fatalStopRequested) {
                Log.w(TAG, "VPN loop stopped unexpectedly; stopping service.")
                stopVpn()
            }
        }
    }

    private fun runPacketLoopLegacy(
        input: FileInputStream,
        buffer: ByteArray,
        processor: DnsPacketProcessor,
        requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>,
        responseQueue: BlockingQueue<ByteArray>
    ) {
        var zeroReadCount = 0L
        var lastZeroReadReportAtMs = System.currentTimeMillis()
        while (!stopSignal.get()) {
            val length = try {
                input.read(buffer)
            } catch (error: IOException) {
                Log.w(TAG, "VPN read failed: ${error.message}")
                break
            }
            if (length < 0) {
                Log.w(TAG, "VPN read returned EOF; stopping")
                break
            }
            if (length == 0) {
                zeroReadCount += 1
                if (DEBUG_LOGS) {
                    val nowMs = System.currentTimeMillis()
                    if (nowMs - lastZeroReadReportAtMs >= ZERO_READ_REPORT_INTERVAL_MS) {
                        // WHY: Periodic sampling avoids log spam while surfacing busy-loop signals.
                        Log.d(
                            TAG,
                            "packetLoop zeroReadCount=$zeroReadCount intervalMs=${nowMs - lastZeroReadReportAtMs}"
                        )
                        zeroReadCount = 0
                        lastZeroReadReportAtMs = nowMs
                    }
                }
                val nowMs = System.currentTimeMillis()
                recordTunRead(length, nowMs)
                maybeReportTunStats(nowMs, "legacy")
                try { Thread.sleep(100) } catch (_: InterruptedException) { break }
                continue
            }
            val nowMs = System.currentTimeMillis()
            tunReadableCount.incrementAndGet()
            recordTunRead(length, nowMs)
            maybeReportTunStats(nowMs, "legacy")
            if (!handlePacketRead(length, buffer, processor, requestQueue, responseQueue)) {
                return
            }
        }
    }

    private fun runPacketLoopPoll(
        tunFd: FileDescriptor,
        wakeupPipe: WakeupPipe,
        buffer: ByteArray,
        processor: DnsPacketProcessor,
        requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>,
        responseQueue: BlockingQueue<ByteArray>
    ) {
        val pollFds = arrayOf(
            StructPollfd().apply {
                fd = tunFd
                events = (
                    OsConstants.POLLIN or
                        OsConstants.POLLERR or
                        OsConstants.POLLHUP or
                        OsConstants.POLLNVAL
                    ).toShort()
            },
            StructPollfd().apply {
                fd = wakeupPipe.readFd
                events = (
                    OsConstants.POLLIN or
                        OsConstants.POLLERR or
                        OsConstants.POLLHUP or
                        OsConstants.POLLNVAL
                    ).toShort()
            }
        )
        val pollErrorMask = OsConstants.POLLERR or OsConstants.POLLHUP or OsConstants.POLLNVAL
        var pollTimeouts = 0L
        var pollWakeups = 0L
        var pollTunReadable = 0L
        var pollErrors = 0L
        var readZeroAfterReadable = 0L
        var lastPollReportAtMs = System.currentTimeMillis()

        fun reportIfNeeded(nowMs: Long) {
            if (!DEBUG_LOGS) return
            if (nowMs - lastPollReportAtMs < ZERO_READ_REPORT_INTERVAL_MS) return
            Log.d(
                TAG,
                "packetLoop pollStats timeouts=$pollTimeouts wakeups=$pollWakeups " +
                    "tunReadable=$pollTunReadable errors=$pollErrors " +
                    "readZeroAfterReadable=$readZeroAfterReadable " +
                    "intervalMs=${nowMs - lastPollReportAtMs}"
            )
            pollTimeouts = 0
            pollWakeups = 0
            pollTunReadable = 0
            pollErrors = 0
            readZeroAfterReadable = 0
            lastPollReportAtMs = nowMs
        }

        while (!stopSignal.get()) {
            val ready = try {
                Os.poll(pollFds, POLL_TIMEOUT_MS)
            } catch (error: ErrnoException) {
                if (error.errno == OsConstants.EINTR) {
                    continue
                }
                Log.w(TAG, "poll failed errno=${error.errno}")
                break
            }
            val nowMs = System.currentTimeMillis()
            if (ready == 0) {
                pollTimeouts += 1
                reportIfNeeded(nowMs)
                maybeReportTunStats(nowMs, "poll")
                maybeTriggerTunStallReset(nowMs)
                continue
            }
            val controlRevents = pollFds[1].revents.toInt()
            if (controlRevents and pollErrorMask != 0) {
                pollErrors += 1
                Log.w(TAG, "poll ctrl error revents=$controlRevents")
                break
            }
            if (controlRevents and OsConstants.POLLIN != 0) {
                pollWakeups += 1
                try {
                    wakeupPipe.drain()
                } catch (error: ErrnoException) {
                    Log.w(TAG, "wakeup drain failed errno=${error.errno}")
                    break
                }
            }
            val tunRevents = pollFds[0].revents.toInt()
            if (tunRevents and pollErrorMask != 0) {
                pollErrors += 1
                Log.w(TAG, "poll tun error revents=$tunRevents")
                break
            }
            if (tunRevents and OsConstants.POLLIN != 0) {
                pollTunReadable += 1
                tunReadableCount.incrementAndGet()
                val length = try {
                    Os.read(tunFd, buffer, 0, buffer.size)
                } catch (error: ErrnoException) {
                    if (error.errno == OsConstants.EAGAIN || error.errno == OsConstants.EINTR) {
                        reportIfNeeded(nowMs)
                        maybeReportTunStats(nowMs, "poll")
                        continue
                    }
                    Log.w(TAG, "VPN read failed errno=${error.errno}")
                    break
                }
                if (length <= 0) {
                    readZeroAfterReadable += 1
                    recordTunRead(length, nowMs)
                } else {
                    recordTunRead(length, nowMs)
                    if (!handlePacketRead(length, buffer, processor, requestQueue, responseQueue)) {
                        return
                    }
                }
            }
            reportIfNeeded(nowMs)
            maybeReportTunStats(nowMs, "poll")
            maybeTriggerTunStallReset(nowMs)
        }
    }

    private fun handlePacketRead(
        length: Int,
        buffer: ByteArray,
        processor: DnsPacketProcessor,
        requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>,
        responseQueue: BlockingQueue<ByteArray>
    ): Boolean {
        lastPacketAtMs = System.currentTimeMillis()
        updateIdleModeIfNeeded("packet")
        if (pendingNetworkReset) {
            pendingNetworkReset = false
            requestNetworkReset("pending_network_reset", forceImmediate = true)
        }
        val outcome = processor.handlePacket(buffer, length) ?: return true
        when (outcome) {
            is DnsPacketProcessor.Outcome.Immediate -> enqueueResponse(responseQueue, outcome.response)
            is DnsPacketProcessor.Outcome.Upstream -> {
                if (upstreamSockets.isEmpty()) {
                    val responsePayload = processor.buildServfailResponse(outcome.job.query)
                    val response = processor.buildUdpResponse(outcome.job.packetInfo, responsePayload)
                    enqueueResponse(responseQueue, response)
                    val count = servfailCount.incrementAndGet()
                    if (DEBUG_LOGS) {
                        Log.d(TAG, "servfail no-upstream count=$count requestQueueSize=${requestQueue.size}")
                    }
                    return true
                }
                // WHY: Bound the offer wait to keep latency predictable under load.
                val offered = try {
                    requestQueue.offer(outcome.job, REQUEST_QUEUE_WAIT_MS, TimeUnit.MILLISECONDS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return false
                }
                if (!offered) {
                    // WHY: Prefer timely SERVFAIL over long queue backlogs.
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
        return true
    }

    private fun startResponseWriter(
        output: FileOutputStream,
        responseQueue: BlockingQueue<ByteArray>
    ) {
        lastResponseWriteAtMs = System.currentTimeMillis()
        responseWriterStallCount.set(0)
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
                        lastResponseWriteAtMs = System.currentTimeMillis()
                        responseWriterStallCount.set(0)
                    }
                } catch (error: IOException) {
                    if (!stopSignal.get()) {
                        requestFatalStop("VPN書き込み失敗: ${error.message}", error)
                    }
                    break
                }
            }
        }.apply {
            name = "responseWriter"
            start()
        }
    }

    private fun startResponseWatchdog(metrics: DnsMetrics) {
        responseWatchdog = Thread {
            while (!stopSignal.get()) {
                val nowMs = System.currentTimeMillis()
                metrics.onWatchdogWake()
                // WHY: Reuse the watchdog tick to avoid introducing a new reporting timer.
                metrics.maybeReport("watchdog", nowMs)
                updateIdleModeIfNeeded("watchdog", nowMs)
                maybeTriggerTunStallReset(nowMs)
                val writer = responseWriter
                if (writer == null || !writer.isAlive) {
                    requestFatalStop("responseWriter thread is not alive")
                    break
                }
                val queue = responseQueue
                if (queue == null || queue.isEmpty()) {
                    responseWriterStallCount.set(0)
                    metrics.onWatchdogQueueEmpty()
                    // WHY: Avoid long-wait notify churn when the queue empties briefly during bursts.
                    val idleMs = nowMs - lastResponseEnqueueAtMs
                    val shouldLongWait = idleMs >= RESPONSE_WATCHDOG_IDLE_ENTER_MS
                    val waitMs = if (shouldLongWait) {
                        RESPONSE_WATCHDOG_EMPTY_INTERVAL_MS
                    } else {
                        RESPONSE_WATCHDOG_ACTIVE_INTERVAL_MS
                    }
                    if (!awaitWatchdog(waitMs, shouldLongWait)) {
                        break
                    }
                    continue
                }
                // WHY: Require consecutive stalled checks to avoid single-blip false positives.
                val lastWriteAtMs = lastResponseWriteAtMs
                if (lastWriteAtMs > 0 && nowMs - lastWriteAtMs >= RESPONSE_WRITE_STALL_MS) {
                    val misses = responseWriterStallCount.incrementAndGet()
                    if (misses >= RESPONSE_WATCHDOG_MAX_MISSES) {
                        requestFatalStop(
                            "responseWriter stalled for ${nowMs - lastWriteAtMs}ms with pending responses"
                        )
                        break
                    }
                } else {
                    responseWriterStallCount.set(0)
                }
                if (!awaitWatchdog(RESPONSE_WATCHDOG_ACTIVE_INTERVAL_MS, false)) {
                    break
                }
            }
        }.apply {
            name = "responseWatchdog"
            start()
        }
    }

    private fun startUpstreamWorkers(
        sockets: List<DatagramSocket>,
        requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>,
        responseQueue: BlockingQueue<ByteArray>,
        processor: DnsPacketProcessor,
        metrics: DnsMetrics
    ) {
        upstreamWorkers = sockets.mapIndexed { index, socket ->
            Thread {
                val resolver = UpstreamResolver(socket, UPSTREAM_DNS, metrics)
                var consecutiveFailures = 0
                while (!stopSignal.get()) {
                    val job = try {
                        requestQueue.take()
                    } catch (_: InterruptedException) {
                        break
                    }
                    val cacheKey = processor.cacheKey(job.query)
                    val nowMs = System.currentTimeMillis()
                    val cache = dnsCache
                    if (cache != null) {
                        val cachedPayload = cache.get(cacheKey, job.query.id, nowMs)
                        if (cachedPayload != null) {
                            val response = processor.buildUdpResponse(job.packetInfo, cachedPayload)
                            enqueueResponse(responseQueue, response)
                            continue
                        }
                    }
                    updateIdleModeIfNeeded("upstream")
                    if (isIdleMode) {
                        if (requestQueue.size >= IDLE_QUEUE_DROP_THRESHOLD) {
                            // WHY: Idle mode favors freshness over backlog on background traffic.
                            val responsePayload = processor.buildServfailResponse(job.query)
                            val response = processor.buildUdpResponse(job.packetInfo, responsePayload)
                            enqueueResponse(responseQueue, response)
                            if (DEBUG_LOGS) {
                                Log.d(TAG, "idle drop requestQueueSize=${requestQueue.size}")
                            }
                            continue
                        }
                        try {
                            Thread.sleep(IDLE_UPSTREAM_DELAY_MS)
                        } catch (_: InterruptedException) {
                            Thread.currentThread().interrupt()
                            break
                        }
                    }
                    lastUpstreamSendAtMs = nowMs
                    val resolvedPayload = resolver.resolve(job.queryPayload)
                    val finishMs = System.currentTimeMillis()
                    if (resolvedPayload == null) {
                        consecutiveFailures += 1
                        upstreamConsecutiveFailures.set(consecutiveFailures)
                        lastUpstreamFailureAtMs.set(finishMs)
                        if (consecutiveFailures >= UPSTREAM_FAILURE_RESET_THRESHOLD) {
                            // WHY: Detect stuck upstream and trigger a network reset recovery.
                            consecutiveFailures = 0
                            upstreamConsecutiveFailures.set(0)
                            updateState(STATE_UPSTREAM_DOWN, "upstream_failures")
                            Log.w(TAG, "Upstream failures reached $UPSTREAM_FAILURE_RESET_THRESHOLD; scheduling reset")
                            requestNetworkReset("upstream_failures")
                        }
                    } else {
                        if (consecutiveFailures > 0) {
                            consecutiveFailures = 0
                            upstreamConsecutiveFailures.set(0)
                            updateState(STATE_RUNNING_OK, "upstream_recovered")
                        }
                        lastUpstreamSuccessAtMs.set(finishMs)
                    }
                    val response = if (resolvedPayload == null) {
                        val responsePayload = processor.buildServfailResponse(job.query)
                        processor.buildUdpResponse(job.packetInfo, responsePayload)
                    } else {
                        cache?.put(cacheKey, resolvedPayload.buffer.copyOf(resolvedPayload.length), nowMs)
                        processor.buildUdpResponse(job.packetInfo, resolvedPayload.buffer, resolvedPayload.length)
                    }
                    enqueueResponse(responseQueue, response)
                }
            }.apply {
                name = "upstreamWorker#$index"
                start()
            }
        }
    }

    private fun enqueueResponse(queue: BlockingQueue<ByteArray>, response: ByteArray) {
        val wasEmpty = queue.isEmpty()
        lastResponseEnqueueAtMs = System.currentTimeMillis()
        if (queue.offer(response)) {
            if (wasEmpty) {
                signalResponseWatchdog()
            }
            return
        }
        // WHY: Prefer freshest DNS replies over backlogged responses under pressure.
        queue.poll()
        val count = responseDropCount.incrementAndGet()
        if (DEBUG_LOGS) {
            Log.d(TAG, "response drop count=$count responseQueueSize=${queue.size}")
        }
        if (!queue.offer(response)) {
            requestFatalStop("responseQueue stuck (size=${queue.size})")
            return
        }
        if (wasEmpty) {
            signalResponseWatchdog()
        }
    }

    private fun awaitWatchdog(timeoutMs: Long, isLongWait: Boolean): Boolean {
        synchronized(responseWatchdogLock) {
            responseWatchdogLongWait = isLongWait
            try {
                (responseWatchdogLock as java.lang.Object).wait(timeoutMs)
                return true
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return false
            } finally {
                responseWatchdogLongWait = false
            }
        }
    }

    private fun signalResponseWatchdog() {
        synchronized(responseWatchdogLock) {
            if (!responseWatchdogLongWait) return
            // WHY: Avoid waking the watchdog during short active waits.
            (responseWatchdogLock as java.lang.Object).notifyAll()
        }
    }

    private fun startScreenMonitor() {
        if (screenStateReceiver != null) return
        val powerManager = powerManager ?: (getSystemService(Context.POWER_SERVICE) as PowerManager)
        val nowMs = System.currentTimeMillis()
        val screenOn = isScreenInteractive(powerManager)
        screenInteractive = screenOn
        if (screenOn) {
            lastScreenOnAtMs = nowMs
        } else {
            lastScreenOffAtMs = nowMs
        }
        updateIdleModeIfNeeded("screen_init", nowMs)
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                val action = intent.action ?: return
                val timestamp = System.currentTimeMillis()
                when (action) {
                    Intent.ACTION_SCREEN_ON -> {
                        lastScreenOnAtMs = timestamp
                        screenInteractive = true
                        updateIdleModeIfNeeded("screen_on", timestamp)
                    }
                    Intent.ACTION_SCREEN_OFF -> {
                        lastScreenOffAtMs = timestamp
                        screenInteractive = false
                        updateIdleModeIfNeeded("screen_off", timestamp)
                    }
                }
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        registerReceiver(receiver, filter)
        screenStateReceiver = receiver
    }

    private fun stopScreenMonitor() {
        val receiver = screenStateReceiver ?: return
        try {
            unregisterReceiver(receiver)
        } catch (_: IllegalArgumentException) {
            // WHY: Receiver may already be unregistered during teardown races.
        }
        screenStateReceiver = null
        isIdleMode = false
        screenInteractive = false
        lastScreenOnAtMs = 0
        lastScreenOffAtMs = 0
    }

    private fun updateIdleModeIfNeeded(reason: String, nowMs: Long = System.currentTimeMillis()) {
        if (screenInteractive) {
            if (isIdleMode) {
                isIdleMode = false
                if (DEBUG_LOGS) {
                    Log.d(TAG, "Idle mode exit reason=$reason")
                }
            }
            return
        }
        val idleSinceMs = when {
            lastPacketAtMs > 0 -> lastPacketAtMs
            lastScreenOffAtMs > 0 -> lastScreenOffAtMs
            else -> nowMs
        }
        val shouldIdle = nowMs - idleSinceMs >= IDLE_ENTER_MS
        if (shouldIdle != isIdleMode) {
            isIdleMode = shouldIdle
            if (DEBUG_LOGS) {
                val state = if (shouldIdle) "enter" else "exit"
                Log.d(TAG, "Idle mode $state reason=$reason idleForMs=${nowMs - idleSinceMs}")
            }
        }
    }

    private fun recordTunRead(length: Int, nowMs: Long) {
        if (length > 0) {
            tunPacketsInWindow.incrementAndGet()
            lastTunPacketAtMs = nowMs
        } else {
            tunReadZeroCount.incrementAndGet()
        }
    }

    private fun maybeReportTunStats(nowMs: Long, source: String) {
        if (!DEBUG_LOGS) return
        if (lastTunStatsReportAtMs == 0L) {
            lastTunStatsReportAtMs = nowMs
            return
        }
        val elapsedMs = nowMs - lastTunStatsReportAtMs
        if (elapsedMs < TUN_STATS_REPORT_INTERVAL_MS) return
        val tunPkts = tunPacketsInWindow.getAndSet(0)
        val tunReadable = tunReadableCount.getAndSet(0)
        val readZero = tunReadZeroCount.getAndSet(0)
        val lastTunAgoMs = if (lastTunPacketAtMs > 0) nowMs - lastTunPacketAtMs else -1L
        Log.d(
            TAG,
            "TUN stats source=$source intervalMs=$elapsedMs tunPkts=$tunPkts " +
                "tunReadable=$tunReadable read0=$readZero lastTunAgoMs=$lastTunAgoMs"
        )
        lastTunStatsReportAtMs = nowMs
    }

    private fun updateState(
        newState: String,
        reason: String,
        detail: String? = null,
        nowMs: Long = System.currentTimeMillis()
    ) {
        if (currentState == newState) return
        val previous = currentState
        currentState = newState
        lastStateChangeAtMs = nowMs
        if (!DEBUG_LOGS) return
        val detailSuffix = if (detail.isNullOrBlank()) "" else " $detail"
        Log.i(TAG, "STATE $previous -> $newState reason=$reason$detailSuffix")
    }

    private fun requestNetworkReset(reason: String, forceImmediate: Boolean = false) {
        if (!isRunning || stopSignal.get()) return
        lastResetReason = reason
        val seq = resetSequence.incrementAndGet()
        if (DEBUG_LOGS) {
            Log.i(TAG, "RESET request seq=$seq reason=$reason force=$forceImmediate")
        }
        scheduleNetworkReset(forceImmediate)
    }

    private fun scheduleNetworkResetDelayed(reason: String, delayMs: Long) {
        if (!isRunning || stopSignal.get()) return
        lastResetReason = reason
        if (DEBUG_LOGS) {
            Log.i(TAG, "RESET scheduled reason=$reason delayMs=$delayMs")
        }
        updateState(STATE_WAIT_RETRY, "reset_scheduled", "delayMs=$delayMs")
        if (!resetRetryScheduled.compareAndSet(false, true)) return
        val scheduler = getResetScheduler()
        scheduler.schedule(
            {
                resetRetryScheduled.set(false)
                scheduleNetworkReset(forceImmediate = true)
            },
            delayMs,
            TimeUnit.MILLISECONDS
        )
    }

    private fun logDiagnosticSnapshot(trigger: String) {
        if (!DEBUG_LOGS) return
        val nowMs = System.currentTimeMillis()
        val manager = connectivityManager
        val network = currentNetwork
        val caps = if (network != null) manager?.getNetworkCapabilities(network) else null
        val linkProps = if (network != null) manager?.getLinkProperties(network) else null
        val transports = caps?.let { describeTransports(it) } ?: "unknown"
        val validated = caps?.let { isValidatedCapability(it) }
        val dnsServers = formatDnsServers(linkProps)
        val tunLastAgoMs = if (lastTunPacketAtMs > 0) nowMs - lastTunPacketAtMs else -1L
        val upstreamOkAgoMs = run {
            val lastOk = lastUpstreamSuccessAtMs.get()
            if (lastOk > 0) nowMs - lastOk else -1L
        }
        val upstreamFailAgoMs = run {
            val lastFail = lastUpstreamFailureAtMs.get()
            if (lastFail > 0) nowMs - lastFail else -1L
        }
        val resetAgoMs = if (lastResetAtMs > 0) nowMs - lastResetAtMs else -1L
        val requestQueueSize = requestQueue?.size ?: -1
        val responseQueueSize = responseQueue?.size ?: -1
        Log.i(
            TAG,
            "DIAG trigger=$trigger state=$currentState netId=$network transports=$transports " +
                "validated=$validated dns=$dnsServers tunLastAgoMs=$tunLastAgoMs " +
                "upstreamOkAgoMs=$upstreamOkAgoMs upstreamFailAgoMs=$upstreamFailAgoMs " +
                "upstreamConsecutiveFailures=${upstreamConsecutiveFailures.get()} resets=${resetCount.get()} " +
                "lastResetReason=$lastResetReason lastResetAgoMs=$resetAgoMs backoffMs=${resetBackoffMs.get()} " +
                "queues=request=$requestQueueSize/response=$responseQueueSize idle=$isIdleMode " +
                "screenInteractive=$screenInteractive"
        )
    }

    private fun logNetworkEvent(
        manager: ConnectivityManager,
        event: String,
        network: Network,
        caps: NetworkCapabilities? = null,
        wasValidated: Boolean? = null
    ) {
        if (!DEBUG_LOGS) return
        val resolvedCaps = caps ?: manager.getNetworkCapabilities(network)
        val transports = resolvedCaps?.let { describeTransports(it) } ?: "unknown"
        val validated = resolvedCaps?.let { isValidatedCapability(it) }
        val hasInternet = resolvedCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        val notMetered = resolvedCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        val captivePortal = resolvedCaps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
        val dnsServers = formatDnsServers(manager.getLinkProperties(network))
        val wasValidatedText = wasValidated?.toString() ?: "unknown"
        Log.i(
            TAG,
            "NET $event netId=$network transports=$transports validated=$validated " +
                "wasValidated=$wasValidatedText internet=$hasInternet notMetered=$notMetered " +
                "captivePortal=$captivePortal dns=$dnsServers"
        )
    }

    private fun describeTransports(caps: NetworkCapabilities): String {
        val transports = ArrayList<String>(4)
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) transports.add("CELL")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) transports.add("WIFI")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) transports.add("ETH")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) transports.add("VPN")
        if (caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH)) transports.add("BT")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI_AWARE)) transports.add("WIFI_AWARE")
        }
        return if (transports.isEmpty()) "none" else transports.joinToString(",")
    }

    private fun formatDnsServers(linkProps: android.net.LinkProperties?): String {
        val servers = linkProps?.dnsServers ?: return "unknown"
        if (servers.isEmpty()) return "none"
        return servers.joinToString(",")
    }

    private fun isScreenInteractive(powerManager: PowerManager): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT_WATCH) {
            powerManager.isInteractive
        } else {
            @Suppress("DEPRECATION")
            powerManager.isScreenOn
        }
    }

    private fun startNetworkMonitor() {
        val manager = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        currentNetwork = selectUpstreamNetwork(manager)
        getNetworkValidated(manager, currentNetwork)?.let { validated ->
            currentNetwork?.let { networkValidated[it] = validated }
        }
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                lastNetworkAvailableAtMs = System.currentTimeMillis()
                logNetworkEvent(manager, "available", network)
                updateCurrentNetwork("available")
            }

            override fun onLost(network: Network) {
                lastNetworkLostAtMs = System.currentTimeMillis()
                networkValidated.remove(network)
                logNetworkEvent(manager, "lost", network)
                updateCurrentNetwork("lost")
            }

            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) {
                val validated = isValidatedCapability(networkCapabilities)
                val wasValidated = networkValidated.put(network, validated)
                logNetworkEvent(manager, "capChanged", network, networkCapabilities, wasValidated)
                updateCurrentNetwork("capabilities")
                if (network == currentNetwork) {
                    if (wasValidated == false && validated) {
                        Log.i(TAG, "Network validated again; forcing VPN reset network=$network")
                        requestNetworkReset("validated_recovered", forceImmediate = true)
                    }
                }
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
        currentNetwork = null
        networkValidated.clear()
        lastNetworkAvailableAtMs = 0
        lastNetworkLostAtMs = 0
    }

    private fun updateCurrentNetwork(reason: String) {
        val manager = connectivityManager ?: return
        val selected = selectUpstreamNetwork(manager)
        if (currentNetwork == selected) return
        // WHY: Avoid binding upstream sockets to VPN transport networks.
        currentNetwork = selected
        getNetworkValidated(manager, selected)?.let { validated ->
            selected?.let { networkValidated[it] = validated }
        }
        if (DEBUG_LOGS) {
            Log.d(TAG, "Upstream network updated reason=$reason selected=$selected")
        }
        requestNetworkReset("network_$reason")
    }

    private fun selectUpstreamNetwork(manager: ConnectivityManager): Network? {
        val networks = manager.allNetworks
        if (networks.isEmpty()) return null
        var fallback: Network? = null
        for (network in networks) {
            val caps = manager.getNetworkCapabilities(network) ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                if (DEBUG_LOGS) {
                    Log.d(TAG, "Skip VPN network=$network")
                }
                continue
            }
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val validated = Build.VERSION.SDK_INT >= Build.VERSION_CODES.M &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            if (validated) {
                return network
            }
            if (fallback == null) {
                fallback = network
            }
        }
        return fallback
    }

    private fun scheduleNetworkReset(forceImmediate: Boolean = false) {
        if (!isRunning || stopSignal.get()) return
        if (forceImmediate) {
            pendingNetworkReset = false
            enqueueNetworkResetCoalesced()
            return
        }
        val lastActiveAtMs = lastPacketAtMs
        val nowMs = System.currentTimeMillis()
        val isActive = lastActiveAtMs > 0 &&
            (nowMs - lastActiveAtMs) <= NETWORK_IDLE_RESET_THRESHOLD_MS
        if (isActive) {
            pendingNetworkReset = false
            enqueueNetworkReset()
            return
        }
        // WHY: Defer socket resets while idle to avoid waking workers on churn.
        pendingNetworkReset = true
    }

    private fun enqueueNetworkReset() {
        if (!isRunning || stopSignal.get()) return
        resetPending.set(true)
        if (resetInFlight.get()) return
        val scheduler = getResetScheduler()
        scheduler.execute {
            runNetworkReset()
        }
    }

    private fun enqueueNetworkResetCoalesced() {
        if (!isRunning || stopSignal.get()) return
        resetPending.set(true)
        if (resetInFlight.get()) return
        if (!resetCoalesceScheduled.compareAndSet(false, true)) return
        val scheduler = getResetScheduler()
        scheduler.schedule(
            {
                resetCoalesceScheduled.set(false)
                enqueueNetworkReset()
            },
            FORCE_RESET_COALESCE_MS,
            TimeUnit.MILLISECONDS
        )
    }

    private fun computeResetBackoffMs(): Long {
        val previous = resetBackoffMs.get()
        val next = if (previous <= 0) {
            RESET_RETRY_BASE_MS
        } else {
            (previous * 2).coerceAtMost(RESET_RETRY_MAX_MS)
        }
        resetBackoffMs.set(next)
        return next
    }

    private fun runNetworkReset() {
        if (!resetInFlight.compareAndSet(false, true)) return
        val nowMs = System.currentTimeMillis()
        lastResetAtMs = nowMs
        resetCount.incrementAndGet()
        updateState(STATE_RESETTING, "reset_run", "reason=$lastResetReason", nowMs)
        try {
            while (resetPending.getAndSet(false)) {
                handleNetworkChange()
                if (!isRunning || stopSignal.get()) {
                    return
                }
            }
        } finally {
            resetInFlight.set(false)
        }
    }

    private fun getResetScheduler(): ScheduledExecutorService {
        val existing = resetScheduler
        if (existing != null) return existing
        synchronized(resetSchedulerLock) {
            val current = resetScheduler
            if (current != null) return current
            val created = Executors.newSingleThreadScheduledExecutor { runnable ->
                Thread(runnable, "networkReset").apply { isDaemon = true }
            }
            resetScheduler = created
            return created
        }
    }

    private fun maybeTriggerTunStallReset(nowMs: Long) {
        if (!isRunning || stopSignal.get()) return
        if (isIdleMode) return
        if (!hasUpstreamNetwork()) return
        val lastPacketMs = lastPacketAtMs
        if (lastPacketMs <= 0) return
        val idleMs = nowMs - lastPacketMs
        if (idleMs < TUN_STALL_RESET_MS) return
        val lastUpstreamMs = lastUpstreamSendAtMs
        val hasRecentUpstream = lastUpstreamMs > 0 &&
            (nowMs - lastUpstreamMs) <= TUN_STALL_RECENT_UPSTREAM_MS
        if (!screenInteractive && !hasRecentUpstream) return
        val lastResetMs = lastTunStallResetAtMs
        if (lastResetMs > 0 && nowMs - lastResetMs < TUN_STALL_RESET_COOLDOWN_MS) return
        lastTunStallResetAtMs = nowMs
        updateState(STATE_TUN_SILENT, "tun_silent", "lastTunAgoMs=$idleMs", nowMs)
        Log.w(TAG, "No TUN traffic for ${idleMs}ms; forcing VPN reset")
        requestNetworkReset("tun_silent", forceImmediate = true)
    }

    private fun hasUpstreamNetwork(): Boolean {
        val network = currentNetwork ?: return false
        val manager = connectivityManager ?: return true
        val caps = manager.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun isValidatedCapability(caps: NetworkCapabilities): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun getNetworkValidated(
        manager: ConnectivityManager,
        network: Network?
    ): Boolean? {
        if (network == null) return null
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        val caps = manager.getNetworkCapabilities(network) ?: return null
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
    }

    private fun handleNetworkChange() {
        if (!isRunning || stopSignal.get()) return
        val currentProcessor = processor ?: return
        val currentRequestQueue = requestQueue ?: return
        val currentResponseQueue = responseQueue ?: return
        if (DEBUG_LOGS) {
            Log.d(TAG, "Network change detected. Resetting upstream. currentNetwork=$currentNetwork")
        }
        synchronized(upstreamResetLock) {
            if (!isRunning || stopSignal.get()) return
            val sockets = createUpstreamSockets(currentNetwork)
            if (sockets.isEmpty()) {
                val delayMs = computeResetBackoffMs()
                Log.w(TAG, "Upstream socket creation failed; retrying in ${delayMs}ms")
                scheduleNetworkResetDelayed("upstream_socket_failed", delayMs)
                return
            }
            resetBackoffMs.set(0)
            // WHY: Clear queues to drop stale requests before switching sockets.
            currentResponseQueue.clear()
            // WHY: Stale requests after network switches are likely obsolete; drop to reduce latency.
            currentRequestQueue.clear()
            shutdownUpstreamLocked()
            upstreamSockets = sockets
            startUpstreamWorkers(sockets, currentRequestQueue, currentResponseQueue, currentProcessor, metrics)
            updateState(STATE_RUNNING_OK, "reset_complete")
        }
    }

    private fun createUpstreamSockets(network: Network?): List<DatagramSocket> {
        val sockets = mutableListOf<DatagramSocket>()
        val attempt = upstreamCreateAttempt.incrementAndGet()
        var bindFailures = 0
        repeat(UPSTREAM_WORKER_COUNT) { index ->
            val socket = DatagramSocket().apply {
                soTimeout = UPSTREAM_TIMEOUT_MS
            }
            if (!protect(socket)) {
                Log.w(TAG, "UP attempt=$attempt idx=$index protect=fail netId=$network")
                socket.close()
                sockets.forEach { it.close() }
                return emptyList()
            }
            if (network != null) {
                try {
                    network.bindSocket(socket)
                    if (DEBUG_LOGS) {
                        Log.d(TAG, "UP attempt=$attempt idx=$index bind=ok netId=$network")
                    }
                } catch (error: Exception) {
                    bindFailures += 1
                    Log.w(TAG, "UP attempt=$attempt idx=$index bind=fail netId=$network error=${error.message}")
                }
            } else if (DEBUG_LOGS) {
                Log.d(TAG, "UP attempt=$attempt idx=$index bind=skip netId=null")
            }
            sockets.add(socket)
        }
        if (DEBUG_LOGS) {
            Log.d(
                TAG,
                "UP attempt=$attempt netId=$network sockets=${sockets.size} bindFailures=$bindFailures"
            )
        }
        return sockets
    }

    private fun shutdownUpstreamLocked() {
        val workers = upstreamWorkers
        upstreamWorkers = emptyList()
        workers.forEach { it.interrupt() }
        upstreamSockets.forEach { it.close() }
        upstreamSockets = emptyList()
        workers.forEachIndexed { index, worker ->
            joinThread(worker, "upstreamWorker#$index")
        }
    }

    private fun joinThread(thread: Thread?, label: String) {
        if (thread == null || thread === Thread.currentThread()) return
        try {
            thread.join(THREAD_JOIN_TIMEOUT_MS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            return
        }
        if (thread.isAlive) {
            Log.w(TAG, "$label thread did not stop within ${THREAD_JOIN_TIMEOUT_MS}ms state=${thread.state}")
        }
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

    private fun requestFatalStop(reason: String, error: Throwable? = null) {
        if (!isRunning) return
        if (error == null) {
            Log.w(TAG, reason)
        } else {
            Log.w(TAG, reason, error)
        }
        // WHY: Cooldown avoids rapid restart loops after fatal writer failures.
        val nowMs = System.currentTimeMillis()
        lastFatalStopAtMs = nowMs
        restartAllowedAtMs = nowMs + FATAL_RESTART_COOLDOWN_MS
        val responseQueueSize = responseQueue?.size ?: -1
        val requestQueueSize = requestQueue?.size ?: -1
        val lastPacketDeltaMs = if (lastPacketAtMs > 0) nowMs - lastPacketAtMs else -1
        val lastWriteDeltaMs = if (lastResponseWriteAtMs > 0) nowMs - lastResponseWriteAtMs else -1
        val lastAvailableDeltaMs = if (lastNetworkAvailableAtMs > 0) nowMs - lastNetworkAvailableAtMs else -1
        val lastLostDeltaMs = if (lastNetworkLostAtMs > 0) nowMs - lastNetworkLostAtMs else -1
        val writerState = responseWriter?.state?.name ?: "null"
        val networkPresent = currentNetwork != null
        val errorType = error?.javaClass?.simpleName ?: "none"
        val powerManager = powerManager ?: return
        val isPowerSave = powerManager.isPowerSaveMode
        val isIdle = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            powerManager.isDeviceIdleMode
        } else {
            false
        }
        Log.w(
            TAG,
            "fatal stop detail reason=$reason errorType=$errorType responseQueueSize=$responseQueueSize " +
                "requestQueueSize=$requestQueueSize lastPacketDeltaMs=$lastPacketDeltaMs " +
                "lastWriteDeltaMs=$lastWriteDeltaMs writerState=$writerState " +
                "currentNetworkPresent=$networkPresent lastOnAvailableDeltaMs=$lastAvailableDeltaMs " +
                "lastOnLostDeltaMs=$lastLostDeltaMs powerSave=$isPowerSave idle=$isIdle"
        )
        // WHY: Ensure the read loop observes a fatal stop after responseWriter failures.
        fatalStopRequested = true
        stopSignal.set(true)
        wakeupPipe?.wake()
        try {
            vpnFd?.close()
        } catch (closeError: IOException) {
            Log.w(TAG, "VPN fd close failed after $reason: ${closeError.message}")
        }
        workerThread?.interrupt()
        val worker = workerThread
        if (worker == null || !worker.isAlive) {
            stopVpn()
        }
    }

    private class WakeupPipe private constructor(
        val readFd: FileDescriptor,
        val writeFd: FileDescriptor
    ) {
        fun wake() {
            try {
                Os.write(writeFd, WAKE_SIGNAL, 0, WAKE_SIGNAL.size)
            } catch (_: ErrnoException) {
                // WHY: Best-effort wake; poll timeout provides a fallback.
            }
        }

        @Throws(ErrnoException::class)
        fun drain() {
            val buffer = ByteArray(WAKE_DRAIN_BUFFER_SIZE)
            Os.read(readFd, buffer, 0, buffer.size)
        }

        fun close() {
            try {
                Os.close(readFd)
            } catch (_: ErrnoException) {
            }
            try {
                Os.close(writeFd)
            } catch (_: ErrnoException) {
            }
        }

        companion object {
            fun create(): WakeupPipe {
                val fds = Os.pipe()
                return WakeupPipe(fds[0], fds[1])
            }

            private val WAKE_SIGNAL = byteArrayOf(1)
            private const val WAKE_DRAIN_BUFFER_SIZE = 32
        }
    }

    companion object {
        const val ACTION_START = "com.example.android_adblocker.action.START"
        const val ACTION_STOP = "com.example.android_adblocker.action.STOP"
        const val ACTION_RELOAD_RULES = "com.example.android_adblocker.action.RELOAD_RULES"
        const val ACTION_DIAG = "com.example.android_adblocker.action.DIAG"
        const val NOTIFICATION_CHANNEL_ID = "adblocker_vpn"
        const val NOTIFICATION_ID = 1001

        private const val TAG = "DnsVpnService"

        private const val VPN_ADDRESS = "10.0.0.2"
        private const val DNS_SERVER = "10.0.0.1"
        private const val DNS_SERVER_INT = 0x0A000001
        private val UPSTREAM_DNS = InetSocketAddress("1.1.1.1", 53)
        private const val UPSTREAM_TIMEOUT_MS = 2000
        private const val UPSTREAM_WORKER_COUNT = 2
        private const val UPSTREAM_FAILURE_RESET_THRESHOLD = 20
        private const val UPSTREAM_QUEUE_CAPACITY = 512
        private const val RESPONSE_QUEUE_CAPACITY = 512
        private const val RESPONSE_DRAIN_MAX = 32
        private const val RESPONSE_WATCHDOG_ACTIVE_INTERVAL_MS = 10000L
        private const val RESPONSE_WATCHDOG_EMPTY_INTERVAL_MS = 60000L
        // WHY: Require sustained idle before switching to long waits.
        private const val RESPONSE_WATCHDOG_IDLE_ENTER_MS = 3000L
        private const val RESPONSE_WRITE_STALL_MS = 15000L
        private const val RESPONSE_WATCHDOG_MAX_MISSES = 3
        private const val IDLE_ENTER_MS = 15000L
        private const val IDLE_UPSTREAM_DELAY_MS = 500L
        private const val IDLE_QUEUE_DROP_THRESHOLD = 128
        private const val THREAD_JOIN_TIMEOUT_MS = 500L
        private const val BLOCKLIST_ASSET = "blocklist.txt"
        private const val PACKET_BUFFER_SIZE = 32767
        private const val REQUEST_QUEUE_WAIT_MS = 10L
        private const val NETWORK_IDLE_RESET_THRESHOLD_MS = 5000L
        private const val FATAL_RESTART_COOLDOWN_MS = 15000L
        private const val TUN_STALL_RESET_MS = 30_000L
        private const val TUN_STALL_RESET_COOLDOWN_MS = 30_000L
        private const val TUN_STALL_RECENT_UPSTREAM_MS = 30_000L
        private const val FORCE_RESET_COALESCE_MS = 300L
        private const val RESET_RETRY_BASE_MS = 2000L
        private const val RESET_RETRY_MAX_MS = 15000L
        // WHY: Keep cache small and short-lived to reduce staleness and memory overhead.
        private const val DNS_CACHE_MAX_ENTRIES = 1024
        private const val DNS_CACHE_TTL_MS = 60000L
        private const val ZERO_READ_REPORT_INTERVAL_MS = 1000L
        // NOTE: Set false to fall back to the legacy FileInputStream read loop.
        private const val USE_POLL_LOOP = true
        private const val POLL_TIMEOUT_MS = 1000
        private const val TUN_STATS_REPORT_INTERVAL_MS = 10_000L
        private val DEBUG_LOGS = BuildConfig.DEBUG

        private const val STATE_STOPPED = "STOPPED"
        private const val STATE_RUNNING_OK = "RUNNING_OK"
        private const val STATE_TUN_SILENT = "TUN_SILENT"
        private const val STATE_UPSTREAM_DOWN = "UPSTREAM_DOWN"
        private const val STATE_RESETTING = "RESETTING"
        private const val STATE_WAIT_RETRY = "WAIT_RETRY"

        @Volatile
        var isRunning: Boolean = false
            private set

        @Volatile
        var lastFatalStopAtMs: Long = 0

        @Volatile
        var restartAllowedAtMs: Long = 0

        @JvmStatic
        fun cooldownRemainingMs(nowMs: Long): Long {
            val remainingMs = restartAllowedAtMs - nowMs
            return if (remainingMs > 0) remainingMs else 0
        }
    }

    private var vpnFd: ParcelFileDescriptor? = null
    private var workerThread: Thread? = null
    private var responseWriter: Thread? = null
    private var responseWatchdog: Thread? = null
    private var upstreamWorkers: List<Thread> = emptyList()
    private var upstreamSockets: List<DatagramSocket> = emptyList()
    private var ruleMatcher: DomainRuleMatcher? = null
    private var processor: DnsPacketProcessor? = null
    private var requestQueue: BlockingQueue<DnsPacketProcessor.UpstreamJob>? = null
    private var responseQueue: BlockingQueue<ByteArray>? = null
    private var dnsCache: DnsCache? = null
    private var metrics: DnsMetrics = DnsMetrics(false)
    private var wakeupPipe: WakeupPipe? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var powerManager: PowerManager? = null
    @Volatile
    private var currentNetwork: Network? = null
    private val networkValidated = ConcurrentHashMap<Network, Boolean>()
    @Volatile
    private var isIdleMode: Boolean = false
    @Volatile
    private var screenInteractive: Boolean = false
    @Volatile
    private var lastScreenOnAtMs: Long = 0
    @Volatile
    private var lastScreenOffAtMs: Long = 0
    @Volatile
    private var lastNetworkAvailableAtMs: Long = 0
    @Volatile
    private var lastNetworkLostAtMs: Long = 0
    @Volatile
    private var lastPacketAtMs: Long = 0
    @Volatile
    private var lastResponseWriteAtMs: Long = 0
    @Volatile
    private var lastResponseEnqueueAtMs: Long = 0
    @Volatile
    private var pendingNetworkReset: Boolean = false
    @Volatile
    private var lastTunStallResetAtMs: Long = 0
    @Volatile
    private var lastUpstreamSendAtMs: Long = 0
    @Volatile
    private var lastTunPacketAtMs: Long = 0
    @Volatile
    private var lastTunStatsReportAtMs: Long = 0
    private val tunPacketsInWindow = AtomicLong(0)
    private val tunReadableCount = AtomicLong(0)
    private val tunReadZeroCount = AtomicLong(0)
    private val upstreamConsecutiveFailures = AtomicInteger(0)
    private val lastUpstreamSuccessAtMs = AtomicLong(0)
    private val lastUpstreamFailureAtMs = AtomicLong(0)
    private val resetSequence = AtomicInteger(0)
    private val resetCount = AtomicInteger(0)
    @Volatile
    private var lastResetReason: String = STATE_STOPPED
    @Volatile
    private var lastResetAtMs: Long = 0
    @Volatile
    private var currentState: String = STATE_STOPPED
    @Volatile
    private var lastStateChangeAtMs: Long = 0
    private val upstreamCreateAttempt = AtomicInteger(0)
    private val resetPending = AtomicBoolean(false)
    private val resetInFlight = AtomicBoolean(false)
    private val resetRetryScheduled = AtomicBoolean(false)
    private val resetCoalesceScheduled = AtomicBoolean(false)
    private val resetBackoffMs = AtomicLong(0)
    private val resetSchedulerLock = Any()
    @Volatile
    private var resetScheduler: ScheduledExecutorService? = null
    @Volatile
    private var fatalStopRequested: Boolean = false
    private val responseWatchdogLock = Any()
    @Volatile
    private var responseWatchdogLongWait: Boolean = false
    private val upstreamResetLock = Any()
    private val servfailCount = AtomicInteger(0)
    private val responseDropCount = AtomicInteger(0)
    private val responseWriterStallCount = AtomicInteger(0)
    private val stopSignal = AtomicBoolean(false)
}
