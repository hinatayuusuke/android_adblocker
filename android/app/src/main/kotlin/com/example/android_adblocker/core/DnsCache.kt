package com.example.android_adblocker.core

import java.util.LinkedHashMap

internal class DnsCache(
    private val maxEntries: Int,
    private val ttlMs: Long
) {
    private data class Entry(val payload: ByteArray, val expiresAtMs: Long)

    private val lock = Any()
    private val map = object : LinkedHashMap<String, Entry>(maxEntries, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Entry>): Boolean {
            return size > maxEntries
        }
    }

    fun get(key: String, queryId: Int, nowMs: Long): ByteArray? {
        synchronized(lock) {
            val entry = map[key] ?: return null
            if (entry.expiresAtMs <= nowMs) {
                map.remove(key)
                return null
            }
            // WHY: DNS transaction ID differs per query, so patch a copy per hit.
            if (entry.payload.size < 2) return null
            val copy = entry.payload.copyOf()
            writeU16(copy, 0, queryId)
            return copy
        }
    }

    fun put(key: String, payload: ByteArray, nowMs: Long) {
        if (payload.size < 2) return
        val expiresAtMs = nowMs + ttlMs
        synchronized(lock) {
            map[key] = Entry(payload, expiresAtMs)
        }
    }

    private fun writeU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value shr 8).toByte()
        packet[offset + 1] = value.toByte()
    }
}
