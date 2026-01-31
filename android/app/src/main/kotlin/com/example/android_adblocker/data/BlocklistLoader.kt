package com.example.android_adblocker.data

import android.content.Context
import android.util.Log
import com.example.android_adblocker.BuildConfig
import java.io.IOException

internal object BlocklistLoader {
    private const val TAG = "BlocklistLoader"

    fun load(context: Context, assetName: String): Set<String> {
        val startMs = System.currentTimeMillis()
        if (BuildConfig.DEBUG) {
            Log.d(TAG, "blocklist load start asset=$assetName")
        }
        val set = mutableSetOf<String>()
        try {
            context.assets.open(assetName).bufferedReader().useLines { lines ->
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
        if (BuildConfig.DEBUG) {
            val elapsedMs = System.currentTimeMillis() - startMs
            Log.d(TAG, "blocklist load done asset=$assetName entries=${set.size} elapsedMs=$elapsedMs")
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
}
