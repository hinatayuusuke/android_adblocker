package com.example.android_adblocker.core

import kotlin.math.min

internal class DnsPacketProcessor(
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
        return buildUdpResponse(packetInfo, dnsPayload, dnsPayload.size)
    }

    fun buildUdpResponse(packetInfo: PacketInfo, dnsPayload: ByteArray, dnsLength: Int): ByteArray {
        val udpLength = UDP_HEADER_LEN + dnsLength
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
        System.arraycopy(dnsPayload, 0, buffer, IPV4_HEADER_MIN_LEN + UDP_HEADER_LEN, dnsLength)

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

    private fun readIpv4(packet: ByteArray, offset: Int): Int {
        return ((packet[offset].toInt() and 0xFF) shl 24) or
            ((packet[offset + 1].toInt() and 0xFF) shl 16) or
            ((packet[offset + 2].toInt() and 0xFF) shl 8) or
            (packet[offset + 3].toInt() and 0xFF)
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
