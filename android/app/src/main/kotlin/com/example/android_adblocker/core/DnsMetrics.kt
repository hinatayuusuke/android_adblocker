package com.example.android_adblocker.core

import android.os.Build
import android.os.Debug
import android.util.Log
import com.example.android_adblocker.BuildConfig
import java.util.concurrent.atomic.AtomicLong

internal class DnsMetrics(
    private val enabled: Boolean = BuildConfig.DEBUG
) {
    private val watchdogWakeups = AtomicLong(0)
    private val watchdogQueueEmpty = AtomicLong(0)
    private val upstreamSends = AtomicLong(0)
    private val upstreamSuccesses = AtomicLong(0)
    private val upstreamFailures = AtomicLong(0)

    private val reportLock = Any()
    private var lastReportAtMs: Long = 0
    private var lastGcCount: Long = 0
    private var lastGcTimeMs: Long = 0
    private var hasGcBaseline: Boolean = false

    fun onWatchdogWake() {
        if (!enabled) return
        watchdogWakeups.incrementAndGet()
    }

    fun onWatchdogQueueEmpty() {
        if (!enabled) return
        watchdogQueueEmpty.incrementAndGet()
    }

    fun onUpstreamSend() {
        if (!enabled) return
        upstreamSends.incrementAndGet()
    }

    fun onUpstreamSuccess() {
        if (!enabled) return
        upstreamSuccesses.incrementAndGet()
    }

    fun onUpstreamFailure() {
        if (!enabled) return
        upstreamFailures.incrementAndGet()
    }

    fun maybeReport(reason: String, nowMs: Long) {
        if (!enabled) return
        synchronized(reportLock) {
            if (lastReportAtMs == 0L) {
                lastReportAtMs = nowMs
                primeGcBaseline()
                return
            }
            val elapsedMs = nowMs - lastReportAtMs
            if (elapsedMs < REPORT_INTERVAL_MS) return
            lastReportAtMs = nowMs

            val wakeups = watchdogWakeups.getAndSet(0)
            val queueEmpty = watchdogQueueEmpty.getAndSet(0)
            val upstreamSend = upstreamSends.getAndSet(0)
            val upstreamSuccess = upstreamSuccesses.getAndSet(0)
            val upstreamFailure = upstreamFailures.getAndSet(0)

            val gcDelta = readGcDelta()
            // NOTE: Use -1 when runtime stats are unavailable to keep log parsing stable.
            val gcCountDelta = gcDelta?.first ?: -1L
            val gcTimeDelta = gcDelta?.second ?: -1L

            Log.d(
                TAG,
                "metrics reason=$reason intervalMs=$elapsedMs " +
                    "watchdogWakeups=$wakeups watchdogQueueEmpty=$queueEmpty " +
                    "upstreamSend=$upstreamSend upstreamSuccess=$upstreamSuccess " +
                    "upstreamFailure=$upstreamFailure gcCountDelta=$gcCountDelta gcTimeDeltaMs=$gcTimeDelta"
            )
        }
    }

    private fun primeGcBaseline() {
        val stats = readGcStats() ?: return
        lastGcCount = stats.first
        lastGcTimeMs = stats.second
        hasGcBaseline = true
    }

    private fun readGcDelta(): Pair<Long, Long>? {
        val stats = readGcStats() ?: return null
        val gcCount = stats.first
        val gcTimeMs = stats.second
        if (!hasGcBaseline) {
            lastGcCount = gcCount
            lastGcTimeMs = gcTimeMs
            hasGcBaseline = true
            return null
        }
        val gcCountDelta = gcCount - lastGcCount
        val gcTimeDelta = gcTimeMs - lastGcTimeMs
        lastGcCount = gcCount
        lastGcTimeMs = gcTimeMs
        return gcCountDelta to gcTimeDelta
    }

    private fun readGcStats(): Pair<Long, Long>? {
        // NOTE: Runtime stats are only available on API 23+.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
        val stats = Debug.getRuntimeStats()
        val gcCount = stats[GC_COUNT_KEY]?.toLongOrNull() ?: return null
        val gcTimeMs = stats[GC_TIME_KEY]?.toLongOrNull() ?: return null
        return gcCount to gcTimeMs
    }

    private companion object {
        private const val TAG = "DnsMetrics"
        private const val REPORT_INTERVAL_MS = 60_000L
        private const val GC_COUNT_KEY = "art.gc.gc-count"
        private const val GC_TIME_KEY = "art.gc.gc-time"
    }
}
