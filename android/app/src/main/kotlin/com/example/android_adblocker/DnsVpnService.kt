package com.example.android_adblocker

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.ServiceInfo
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.BlockingQueue
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

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
        val sockets = mutableListOf<DatagramSocket>()
        repeat(UPSTREAM_WORKER_COUNT) {
            val socket = DatagramSocket().apply {
                soTimeout = UPSTREAM_TIMEOUT_MS
            }
            if (!protect(socket)) {
                socket.close()
                sockets.forEach { it.close() }
                vpnInterface.close()
                return
            }
            sockets.add(socket)
        }
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

        workerThread = Thread {
            runPacketLoop(vpnInterface, sockets, matcher)
        }.apply { start() }

        // WHY: FGS開始猶予を超えないよう、重いブロックリスト読込は別スレッドで行う。
        Thread {
            val blocklist = loadBlocklist()
            if (!stopSignal.get()) {
                matcher.updateBlocklist(blocklist)
            }
        }.start()
    }

    private fun stopVpn() {
        if (!isRunning) return
        stopSignal.set(true)
        workerThread?.interrupt()
        workerThread = null
        responseWriter?.interrupt()
        responseWriter = null
        upstreamWorkers.forEach { it.interrupt() }
        upstreamWorkers = emptyList()
        upstreamSockets.forEach { it.close() }
        upstreamSockets = emptyList()
        vpnFd?.close()
        vpnFd = null
        ruleMatcher = null
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
        // WHY: 上流遅延時に無制限に溜めないよう、キューは上限を設ける。
        val requestQueue = ArrayBlockingQueue<DnsPacketProcessor.UpstreamJob>(UPSTREAM_QUEUE_CAPACITY)
        val responseQueue = ArrayBlockingQueue<ByteArray>(RESPONSE_QUEUE_CAPACITY)
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
                        if (!requestQueue.offer(outcome.job)) {
                            // WHY: 読み取りスレッドを塞がないため、即時に失敗応答を返す。
                            val responsePayload = processor.buildServfailResponse(outcome.job.query)
                            val response = processor.buildUdpResponse(outcome.job.packetInfo, responsePayload)
                            enqueueResponse(responseQueue, response)
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
            while (!stopSignal.get()) {
                val response = try {
                    responseQueue.take()
                } catch (_: InterruptedException) {
                    break
                }
                try {
                    output.write(response)
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

    private fun loadBlocklist(): Set<String> {
        val set = mutableSetOf<String>()
        try {
            assets.open(BLOCKLIST_ASSET).bufferedReader().useLines { lines ->
                lines.forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || trimmed.startsWith("#")) return@forEach
                    val tokens = trimmed.split(Regex("\\s+"), limit = 3)
                    val domain = if (tokens.size >= 2 && looksLikeIp(tokens[0])) {
                        tokens[1]
                    } else {
                        tokens[0]
                    }
                    val normalized = normalizeDomain(domain)
                    if (normalized.isNotEmpty()) {
                        set.add(normalized)
                    }
                }
            }
        } catch (error: IOException) {
            Log.w(TAG, "ブロックリスト読み込み失敗: ${error.message}")
        }
        return set
    }

    private fun looksLikeIp(value: String): Boolean {
        return value.all { it.isDigit() || it == '.' || it == ':' }
    }

    private fun normalizeDomain(value: String): String {
        val trimmed = value.trim().trimEnd('.').lowercase()
        return if (trimmed == ".") "" else trimmed
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
        private const val BLOCKLIST_ASSET = "blocklist.txt"
        private const val PACKET_BUFFER_SIZE = 32767

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
    private val stopSignal = AtomicBoolean(false)
}

internal object VpnPreferences {
    const val NAME = "adblocker_prefs"
    const val KEY_ALLOWLIST = "allowlist_domains"
}

private class DomainRuleMatcher(
    @Volatile private var blocklist: Set<String>,
    @Volatile private var allowlist: Set<String>
) {
    fun updateBlocklist(newBlocklist: Set<String>) {
        blocklist = newBlocklist
    }

    fun updateAllowlist(newAllowlist: Set<String>) {
        allowlist = newAllowlist
    }

    fun shouldBlock(domain: String): Boolean {
        if (domain.isEmpty()) return false
        if (matches(domain, allowlist)) return false
        return matches(domain, blocklist)
    }

    private fun matches(domain: String, rules: Set<String>): Boolean {
        var current = domain
        while (true) {
            if (rules.contains(current)) return true
            val nextDot = current.indexOf('.')
            if (nextDot == -1) return false
            current = current.substring(nextDot + 1)
        }
    }
}

private class UpstreamResolver(
    private val socket: DatagramSocket,
    private val upstream: InetSocketAddress
) {
    // WHY: ワーカーごとにバッファ/パケットを再利用して割り当てを抑える。
    private val responseBuffer = ByteArray(1500)
    private val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
    private val requestPacket = DatagramPacket(ByteArray(0), 0, upstream)

    fun resolve(query: ByteArray): ByteArray? {
        return try {
            requestPacket.setData(query, 0, query.size)
            socket.send(requestPacket)
            socket.receive(responsePacket)
            responseBuffer.copyOf(responsePacket.length)
        } catch (_: IOException) {
            null
        }
    }
}

private class DnsPacketProcessor(
    private val dnsServer: Int,
    private val matcher: DomainRuleMatcher
) {
    sealed class Outcome {
        data class Immediate(val response: ByteArray) : Outcome()
        data class Upstream(val job: UpstreamJob) : Outcome()
    }

    data class UpstreamJob(
        val queryPayload: ByteArray,
        val packetInfo: PacketInfo,
        val query: DnsQuery
    )

    fun handlePacket(packet: ByteArray, length: Int): Outcome? {
        if (length < IPV4_HEADER_MIN_LEN) return null
        val version = (packet[0].toInt() ushr 4) and 0x0F
        if (version != 4) return null
        val headerLength = (packet[0].toInt() and 0x0F) * 4
        if (length < headerLength + UDP_HEADER_LEN) return null
        val protocol = packet[9].toInt() and 0xFF
        if (protocol != UDP_PROTOCOL) return null

        val srcAddress = readIpv4(packet, IPV4_SRC_ADDR_OFFSET)
        val destAddress = readIpv4(packet, IPV4_DEST_ADDR_OFFSET)
        if (destAddress != dnsServer) return null

        val srcPort = readU16(packet, headerLength)
        val destPort = readU16(packet, headerLength + 2)
        if (destPort != DNS_PORT) return null

        val udpLength = readU16(packet, headerLength + 4)
        if (udpLength <= UDP_HEADER_LEN) return null
        val dnsOffset = headerLength + UDP_HEADER_LEN
        val dnsLength = min(length - dnsOffset, udpLength - UDP_HEADER_LEN)
        if (dnsLength <= 0) return null

        val query = parseQuery(packet, dnsOffset, dnsLength) ?: return null
        val normalized = query.domain
        val packetInfo = PacketInfo(
            srcAddress = srcAddress,
            destAddress = destAddress,
            srcPort = srcPort,
            destPort = destPort
        )
        return if (matcher.shouldBlock(normalized)) {
            val responsePayload = buildBlockedResponse(query)
            Outcome.Immediate(buildUdpResponse(packetInfo, responsePayload))
        } else {
            val queryPayload = packet.copyOfRange(dnsOffset, dnsOffset + dnsLength)
            Outcome.Upstream(UpstreamJob(queryPayload, packetInfo, query))
        }
    }

    fun buildUdpResponse(packetInfo: PacketInfo, dnsPayload: ByteArray): ByteArray {
        val udpLength = UDP_HEADER_LEN + dnsPayload.size
        val totalLength = IPV4_HEADER_MIN_LEN + udpLength
        val buffer = ByteArray(totalLength)

        buffer[0] = 0x45.toByte()
        buffer[1] = 0
        writeU16(buffer, 2, totalLength)
        writeU16(buffer, 4, 0)
        writeU16(buffer, 6, 0)
        buffer[8] = 64
        buffer[9] = UDP_PROTOCOL.toByte()

        writeIpv4(buffer, IPV4_SRC_ADDR_OFFSET, packetInfo.destAddress)
        writeIpv4(buffer, IPV4_DEST_ADDR_OFFSET, packetInfo.srcAddress)
        val checksum = ipv4Checksum(buffer, 0, IPV4_HEADER_MIN_LEN)
        writeU16(buffer, 10, checksum)

        writeU16(buffer, IPV4_HEADER_MIN_LEN, packetInfo.destPort)
        writeU16(buffer, IPV4_HEADER_MIN_LEN + 2, packetInfo.srcPort)
        writeU16(buffer, IPV4_HEADER_MIN_LEN + 4, udpLength)
        // WHY: IPv4のUDPチェックサムは省略可能で、フィルタ専用の負荷を抑えるため0にする。
        writeU16(buffer, IPV4_HEADER_MIN_LEN + 6, 0)
        System.arraycopy(dnsPayload, 0, buffer, IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN, dnsPayload.size)

        return buffer
    }

    fun buildServfailResponse(query: DnsQuery): ByteArray {
        return buildErrorResponse(query, DNS_RCODE_SERVFAIL)
    }

    private fun parseQuery(packet: ByteArray, offset: Int, length: Int): DnsQuery? {
        if (length < DNS_HEADER_LEN) return null
        val end = offset + length
        if (end > packet.size) return null
        val id = readU16(packet, offset)
        val flags = readU16(packet, offset + 2)
        val qdCount = readU16(packet, offset + 4)
        if (qdCount < 1) return null

        var index = offset + DNS_HEADER_LEN
        val domainBuilder = StringBuilder()
        while (index < end) {
            val labelLength = packet[index].toInt() and 0xFF
            if (labelLength == 0) {
                index += 1
                break
            }
            if ((labelLength and 0xC0) != 0) return null
            if (index + 1 + labelLength > end) return null
            if (domainBuilder.isNotEmpty()) {
                domainBuilder.append('.')
            }
            domainBuilder.append(decodeLabelLowercase(packet, index + 1, labelLength))
            index += 1 + labelLength
        }

        if (index + 4 > end) return null
        val questionEnd = index + 4
        val question = packet.copyOfRange(offset + DNS_HEADER_LEN, questionEnd)
        if (question.isEmpty()) return null

        return DnsQuery(
            id = id,
            flags = flags,
            question = question,
            domain = domainBuilder.toString()
        )
    }

    private fun buildBlockedResponse(query: DnsQuery): ByteArray {
        return buildErrorResponse(query, DNS_RCODE_NXDOMAIN)
    }

    private fun buildErrorResponse(query: DnsQuery, rcode: Int): ByteArray {
        val response = ByteArray(DNS_HEADER_LEN + query.question.size)
        writeU16(response, 0, query.id)
        val responseFlags = 0x8000 or (query.flags and 0x0100) or 0x0080 or rcode
        writeU16(response, 2, responseFlags)
        writeU16(response, 4, 1)
        writeU16(response, 6, 0)
        writeU16(response, 8, 0)
        writeU16(response, 10, 0)
        System.arraycopy(query.question, 0, response, DNS_HEADER_LEN, query.question.size)
        return response
    }

    private fun readU16(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)
    }

    private fun decodeLabelLowercase(packet: ByteArray, offset: Int, length: Int): String {
        var hasNonAscii = false
        for (i in 0 until length) {
            if ((packet[offset + i].toInt() and 0x80) != 0) {
                hasNonAscii = true
                break
            }
        }
        // WHY: ほとんどのDNSラベルはASCIIのため、UTF-8デコードを避けて割り当てを抑える。
        if (!hasNonAscii) {
            val chars = CharArray(length)
            for (i in 0 until length) {
                val value = packet[offset + i].toInt() and 0xFF
                chars[i] = if (value in ASCII_UPPER_A..ASCII_UPPER_Z) {
                    (value + ASCII_CASE_OFFSET).toChar()
                } else {
                    value.toChar()
                }
            }
            return String(chars)
        }
        val label = String(packet, offset, length, Charsets.UTF_8)
        var hasUpper = false
        for (ch in label) {
            if (ch in 'A'..'Z') {
                hasUpper = true
                break
            }
        }
        if (!hasUpper) return label
        val chars = CharArray(label.length)
        for (i in label.indices) {
            val ch = label[i]
            chars[i] = if (ch in 'A'..'Z') (ch.code + ASCII_CASE_OFFSET).toChar() else ch
        }
        return String(chars)
    }

    private fun readIpv4(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 24) or
            ((packet[offset + 1].toInt() and 0xFF) shl 16) or
            ((packet[offset + 2].toInt() and 0xFF) shl 8) or
            (packet[offset + 3].toInt() and 0xFF)
    }

    private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value shr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private fun writeIpv4(packet: ByteArray, offset: Int, address: Int) {
        packet[offset] = (address shr 24).toByte()
        packet[offset + 1] = (address shr 16).toByte()
        packet[offset + 2] = (address shr 8).toByte()
        packet[offset + 3] = address.toByte()
    }

    private fun ipv4Checksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0
        var index = offset
        while (index < offset + length) {
            if (index == offset + 10) {
                index += 2
                continue
            }
            val word = ((packet[index].toInt() and 0xFF) shl 8) or (packet[index + 1].toInt() and 0xFF)
            sum += word
            sum = (sum and 0xFFFF) + (sum ushr 16)
            index += 2
        }
        sum = sum.inv() and 0xFFFF
        return sum
    }

    data class PacketInfo(
        val srcAddress: Int,
        val destAddress: Int,
        val srcPort: Int,
        val destPort: Int
    )

    data class DnsQuery(
        val id: Int,
        val flags: Int,
        val question: ByteArray,
        val domain: String
    )

    private companion object {
        const val IPV4_HEADER_MIN_LEN = 20
        const val IPV4_SRC_ADDR_OFFSET = 12
        const val IPV4_DEST_ADDR_OFFSET = 16
        const val UDP_HEADER_LEN = 8
        const val DNS_HEADER_LEN = 12
        const val DNS_PORT = 53
        const val UDP_PROTOCOL = 17
        const val DNS_RCODE_NXDOMAIN = 0x0003
        const val DNS_RCODE_SERVFAIL = 0x0002
        const val ASCII_UPPER_A = 0x41
        const val ASCII_UPPER_Z = 0x5A
        const val ASCII_CASE_OFFSET = 0x20
    }
}
