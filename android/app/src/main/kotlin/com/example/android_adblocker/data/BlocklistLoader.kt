package com.example.android_adblocker.data

import android.content.Context
import android.util.Log
import java.io.IOException

internal object BlocklistLoader {
    private const val TAG = "BlocklistLoader"

    fun load(context: Context, assetName: String): Set<String> {
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
