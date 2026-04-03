package com.example.android_adblocker.net

import android.os.SystemClock
import android.util.Log
import com.example.android_adblocker.BuildConfig
import com.example.android_adblocker.core.DnsMetrics
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException

internal data class UpstreamEndpoint(
    val address: InetSocketAddress,
    val name: String
)

internal class UpstreamResolver(
    private val socket: DatagramSocket,
    private val upstreams: List<UpstreamEndpoint>,
    private val timeoutMs: Int,
    private val metrics: DnsMetrics
) {
    // WHY: Reuse a fixed buffer so timeout/failover paths do not add per-query allocations.
    private val responseBuffer = ByteArray(1500)
    private val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)
    private val requestPacket = DatagramPacket(ByteArray(0), 0)
    // WHY: Reuse the response wrapper because one worker owns one resolver instance.
    private val responseView = ResolveResult.Success(responseBuffer, 0, "")
    private var connectedEndpoint: UpstreamEndpoint? = null

    fun resolve(
        query: ByteArray,
        expectedQueryId: Int,
        expectedName: String,
        expectedQtype: Int,
        expectedQclass: Int
    ): ResolveResult {
        if (upstreams.isEmpty()) {
            return ResolveResult.Failure("unconfigured", null)
        }

        val deadlineAtMs = SystemClock.elapsedRealtime() + timeoutMs.toLong()
        var lastResult: ResolveResult = ResolveResult.Timeout(upstreams.last().name)
        for (index in upstreams.indices) {
            val remainingMs = deadlineAtMs - SystemClock.elapsedRealtime()
            if (remainingMs <= 0) break
            val endpoint = upstreams[index]
            if (index > 0 && DEBUG_LOGS) {
                Log.w(
                    TAG,
                    "UPSTREAM_FAILOVER from=${upstreams[index - 1].name} to=${endpoint.name} " +
                        "remainingMs=$remainingMs"
                )
            }
            val attemptTimeoutMs = computeAttemptTimeoutMs(remainingMs, upstreams.size - index)
            lastResult = resolveViaEndpoint(
                endpoint = endpoint,
                query = query,
                expectedQueryId = expectedQueryId,
                expectedName = expectedName,
                expectedQtype = expectedQtype,
                expectedQclass = expectedQclass,
                attemptTimeoutMs = attemptTimeoutMs
            )
            if (lastResult is ResolveResult.Success) {
                return lastResult
            }
        }
        if (DEBUG_LOGS) {
            Log.w(
                TAG,
                "UPSTREAM_FAIL_FINAL attempts=${upstreams.size} result=${lastResult.javaClass.simpleName}"
            )
        }
        return lastResult
    }

    private fun resolveViaEndpoint(
        endpoint: UpstreamEndpoint,
        query: ByteArray,
        expectedQueryId: Int,
        expectedName: String,
        expectedQtype: Int,
        expectedQclass: Int,
        attemptTimeoutMs: Int
    ): ResolveResult {
        try {
            ensureConnected(endpoint)
            metrics.onUpstreamSend()
            requestPacket.setData(query, 0, query.size)
            // WHY: Some Android DatagramSocket implementations retain the previous packet destination
            // across sends; keep the packet address aligned with the connected endpoint on failover.
            requestPacket.setSocketAddress(endpoint.address)
            socket.send(requestPacket)
            val startNs = System.nanoTime()
            val attemptDeadlineAtMs = SystemClock.elapsedRealtime() + attemptTimeoutMs.toLong()
            var discardCount = 0
            while (true) {
                val remainingMs = attemptDeadlineAtMs - SystemClock.elapsedRealtime()
                if (remainingMs <= 0) {
                    throw SocketTimeoutException("deadline exhausted")
                }
                socket.soTimeout = remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                responsePacket.length = responseBuffer.size
                socket.receive(responsePacket)
                val mismatch = responseMismatchReason(
                    payload = responseBuffer,
                    length = responsePacket.length,
                    expectedQueryId = expectedQueryId,
                    expectedName = expectedName,
                    expectedQtype = expectedQtype,
                    expectedQclass = expectedQclass
                )
                if (mismatch == null) {
                    if (DEBUG_LOGS) {
                        val elapsedMs = (System.nanoTime() - startNs) / 1_000_000
                        Log.d(
                            TAG,
                            "UPSTREAM_OK endpoint=${endpoint.name} length=${responsePacket.length} " +
                                "elapsedMs=$elapsedMs discardCount=$discardCount"
                        )
                    }
                    metrics.onUpstreamSuccess()
                    responseView.length = responsePacket.length
                    responseView.endpointName = endpoint.name
                    return responseView
                }
                discardCount += 1
                if (DEBUG_LOGS) {
                    Log.w(
                        TAG,
                        "UPSTREAM_STALE_RESPONSE_DISCARD endpoint=${endpoint.name} " +
                            "reason=$mismatch discardCount=$discardCount"
                    )
                }
            }
        } catch (error: SocketTimeoutException) {
            metrics.onUpstreamFailure()
            if (DEBUG_LOGS) {
                Log.w(TAG, "UPSTREAM_TIMEOUT endpoint=${endpoint.name} timeoutMs=$attemptTimeoutMs")
            }
            return ResolveResult.Timeout(endpoint.name)
        } catch (error: IOException) {
            metrics.onUpstreamFailure()
            if (DEBUG_LOGS) {
                val local = try {
                    "${socket.localAddress}:${socket.localPort}"
                } catch (_: Exception) {
                    "?"
                }
                Log.w(
                    TAG,
                    "UPSTREAM_FAIL local=$local endpoint=${endpoint.name} upstream=${endpoint.address} " +
                        "error=${error.javaClass.simpleName}:${error.message}"
                )
            }
            return ResolveResult.Failure(endpoint.name, error)
        } catch (error: IllegalArgumentException) {
            metrics.onUpstreamFailure()
            if (DEBUG_LOGS) {
                Log.w(
                    TAG,
                    "UPSTREAM_FAIL endpoint=${endpoint.name} error=${error.javaClass.simpleName}:${error.message}"
                )
            }
            return ResolveResult.Failure(endpoint.name, null)
        }
        return ResolveResult.Timeout(endpoint.name)
    }

    private fun ensureConnected(endpoint: UpstreamEndpoint) {
        if (connectedEndpoint == endpoint) return
        socket.disconnect()
        socket.connect(endpoint.address)
        connectedEndpoint = endpoint
    }

    private fun computeAttemptTimeoutMs(remainingMs: Long, remainingAttempts: Int): Int {
        if (remainingAttempts <= 1) {
            return remainingMs.coerceAtMost(Int.MAX_VALUE.toLong()).coerceAtLeast(1L).toInt()
        }
        val sliceMs = remainingMs / remainingAttempts.toLong()
        return sliceMs.coerceAtMost(Int.MAX_VALUE.toLong()).coerceAtLeast(1L).toInt()
    }

    private fun responseMismatchReason(
        payload: ByteArray,
        length: Int,
        expectedQueryId: Int,
        expectedName: String,
        expectedQtype: Int,
        expectedQclass: Int
    ): String? {
        if (length < DNS_HEADER_LEN) return "short_packet"
        val actualQueryId = readU16(payload, 0)
        if (actualQueryId != expectedQueryId) return "id_mismatch"
        val qdCount = readU16(payload, DNS_QDCOUNT_OFFSET)
        if (qdCount < 1) return "qdcount_missing"
        val question = parseQuestion(payload, length) ?: return "question_parse"
        if (question.name != expectedName) return "question_name_mismatch"
        if (question.qtype != expectedQtype) return "question_type_mismatch"
        if (question.qclass != expectedQclass) return "question_class_mismatch"
        return null
    }

    private fun parseQuestion(payload: ByteArray, length: Int): ParsedQuestion? {
        val name = parseName(payload, DNS_HEADER_LEN, length) ?: return null
        if (name.nextOffset + DNS_QUESTION_SUFFIX_LEN > length) return null
        return ParsedQuestion(
            name = name.value,
            qtype = readU16(payload, name.nextOffset),
            qclass = readU16(payload, name.nextOffset + 2)
        )
    }

    private fun parseName(payload: ByteArray, offset: Int, length: Int): ParsedName? {
        if (offset >= length) return null
        val labels = StringBuilder()
        var currentOffset = offset
        var nextOffset = -1
        var jumps = 0
        while (currentOffset < length) {
            val labelLength = payload[currentOffset].toInt() and 0xFF
            when {
                labelLength == 0 -> {
                    if (nextOffset < 0) {
                        nextOffset = currentOffset + 1
                    }
                    return ParsedName(labels.toString(), nextOffset)
                }
                (labelLength and DNS_POINTER_MASK) == DNS_POINTER_MASK -> {
                    if (currentOffset + 1 >= length) return null
                    if (nextOffset < 0) {
                        nextOffset = currentOffset + 2
                    }
                    val pointer = ((labelLength and DNS_POINTER_VALUE_MASK) shl 8) or
                        (payload[currentOffset + 1].toInt() and 0xFF)
                    if (pointer >= length) return null
                    currentOffset = pointer
                    jumps += 1
                    // WHY: Bound pointer chasing so malformed packets cannot loop forever.
                    if (jumps > DNS_POINTER_MAX_JUMPS) return null
                }
                (labelLength and DNS_POINTER_MASK) != 0 -> return null
                else -> {
                    val labelStart = currentOffset + 1
                    val labelEnd = labelStart + labelLength
                    if (labelEnd > length) return null
                    if (labels.isNotEmpty()) {
                        labels.append('.')
                    }
                    appendLowercaseLabel(labels, payload, labelStart, labelLength)
                    currentOffset = labelEnd
                }
            }
        }
        return null
    }

    private fun appendLowercaseLabel(
        builder: StringBuilder,
        payload: ByteArray,
        offset: Int,
        length: Int
    ) {
        for (index in 0 until length) {
            val value = payload[offset + index].toInt() and 0xFF
            val normalized = if (value in ASCII_UPPER_A..ASCII_UPPER_Z) {
                value + ASCII_CASE_OFFSET
            } else {
                value
            }
            builder.append(normalized.toChar())
        }
    }

    private fun readU16(payload: ByteArray, offset: Int): Int {
        return ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
    }

    private data class ParsedName(val value: String, val nextOffset: Int)

    private data class ParsedQuestion(val name: String, val qtype: Int, val qclass: Int)

    internal sealed class ResolveResult {
        class Success(
            val buffer: ByteArray,
            var length: Int,
            var endpointName: String
        ) : ResolveResult()

        data class Timeout(val endpointName: String) : ResolveResult()

        data class Failure(val endpointName: String, val error: IOException?) : ResolveResult()
    }

    private companion object {
        private const val TAG = "UpstreamResolver"
        private const val DNS_HEADER_LEN = 12
        private const val DNS_QDCOUNT_OFFSET = 4
        private const val DNS_QUESTION_SUFFIX_LEN = 4
        private const val DNS_POINTER_MASK = 0xC0
        private const val DNS_POINTER_VALUE_MASK = 0x3F
        private const val DNS_POINTER_MAX_JUMPS = 16
        private const val ASCII_UPPER_A = 0x41
        private const val ASCII_UPPER_Z = 0x5A
        private const val ASCII_CASE_OFFSET = 0x20
        private val DEBUG_LOGS = BuildConfig.DEBUG
    }
}
