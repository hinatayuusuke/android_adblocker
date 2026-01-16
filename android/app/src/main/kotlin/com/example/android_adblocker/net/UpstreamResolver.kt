package com.example.android_adblocker.net

import android.util.Log
import com.example.android_adblocker.BuildConfig
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress

internal class UpstreamResolver(
    private val socket: DatagramSocket,
    private val upstream: InetSocketAddress
) {
    // WHY: ワーカーごとにバッファ/パケットを再利用して割り当てを抑える。
    private val responseBuffer = ByteArray(1500)
    private val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
    private val requestPacket = DatagramPacket(ByteArray(0), 0, upstream)

    fun resolve(query: ByteArray): ByteArray? {
        return try {
            val startNs = System.nanoTime()
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
            responseBuffer.copyOf(responsePacket.length)
        } catch (_: IOException) {
            null
        }
    }

    private companion object {
        private const val TAG = "UpstreamResolver"
        private val DEBUG_LOGS = BuildConfig.DEBUG
    }
}
