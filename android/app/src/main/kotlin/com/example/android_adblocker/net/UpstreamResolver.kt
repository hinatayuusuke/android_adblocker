package com.example.android_adblocker.net

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
            requestPacket.setData(query, 0, query.size)
            socket.send(requestPacket)
            socket.receive(responsePacket)
            responseBuffer.copyOf(responsePacket.length)
        } catch (_: IOException) {
            null
        }
    }
}
