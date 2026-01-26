package com.example.android_adblocker.net

import android.util.Log
import com.example.android_adblocker.BuildConfig
import com.example.android_adblocker.core.DnsMetrics
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

internal class UpstreamResolver(
    private val socket: DatagramSocket,
    private val upstream: InetSocketAddress,
    private val metrics: DnsMetrics
) {
    // WHY: ワーカーごとにバッファ/パケットを再利用して割り当てを抑える。
    private val responseBuffer = ByteArray(1500)
    private val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
    private val requestPacket = DatagramPacket(ByteArray(0), 0, upstream)
    // WHY: レスポンスはワーカースレッド単位で扱い、都度のラッパー生成を避ける。
    private val responseView = UpstreamResponse(responseBuffer, 0)

    fun resolve(query: ByteArray): UpstreamResponse? {
        return try {
            val startNs = System.nanoTime()
            metrics.onUpstreamSend()
            requestPacket.setData(query, 0, query.size)
            socket.send(requestPacket)
            if (DEBUG_LOGS) {
                Log.d(TAG, "upstream recv before length=${responsePacket.length}")
            }
            // WHY: 受信後に縮んだlengthを戻さないと応答が途中で切れる。
            responsePacket.length = responseBuffer.size
            socket.receive(responsePacket)
            if (DEBUG_LOGS) {
                val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
                Log.d(TAG, "upstream recv after length=${responsePacket.length} elapsedMs=$elapsedMs")
            }
            metrics.onUpstreamSuccess()
            responseView.length = responsePacket.length
            responseView
        } catch (_: IOException) {
            metrics.onUpstreamFailure()
            null
        }
    }

    internal data class UpstreamResponse(val buffer: ByteArray, var length: Int)

    private companion object {
        private const val TAG = "UpstreamResolver"
        private val DEBUG_LOGS = BuildConfig.DEBUG
    }
}
