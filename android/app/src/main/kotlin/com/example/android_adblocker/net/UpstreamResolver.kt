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

    fun resolve(query: ByteArray, expectedQueryId: Int, expectedQuestion: ByteArray): ResolveResult {
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
                expectedQuestion = expectedQuestion,
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
        expectedQuestion: ByteArray,
        attemptTimeoutMs: Int
    ): ResolveResult {
        try {
            ensureConnected(endpoint)
            metrics.onUpstreamSend()
            requestPacket.setData(query, 0, query.size)
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
                    expectedQuestion = expectedQuestion
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
        expectedQuestion: ByteArray
    ): String? {
        if (length < DNS_HEADER_LEN) return "short_packet"
        val actualQueryId = readU16(payload, 0)
        if (actualQueryId != expectedQueryId) return "id_mismatch"
        val qdCount = readU16(payload, DNS_QDCOUNT_OFFSET)
        if (qdCount < 1) return "qdcount_missing"
        val questionEnd = findQuestionEnd(payload, length) ?: return "question_parse"
        val questionLength = questionEnd - DNS_HEADER_LEN
        if (questionLength != expectedQuestion.size) return "question_mismatch"
        for (index in expectedQuestion.indices) {
            if (payload[DNS_HEADER_LEN + index] != expectedQuestion[index]) {
                return "question_mismatch"
            }
        }
        return null
    }

    private fun findQuestionEnd(payload: ByteArray, length: Int): Int? {
        var index = DNS_HEADER_LEN
        while (index < length) {
            val labelLength = payload[index].toInt() and 0xFF
            if (labelLength == 0) {
                index += 1
                break
            }
            if ((labelLength and DNS_POINTER_MASK) != 0) return null
            index += 1 + labelLength
            if (index > length) return null
        }
        val questionEnd = index + DNS_QUESTION_SUFFIX_LEN
        return if (questionEnd <= length) questionEnd else null
    }

    private fun readU16(payload: ByteArray, offset: Int): Int {
        return ((payload[offset].toInt() and 0xFF) shl 8) or (payload[offset + 1].toInt() and 0xFF)
    }

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
        private val DEBUG_LOGS = BuildConfig.DEBUG
    }
}
