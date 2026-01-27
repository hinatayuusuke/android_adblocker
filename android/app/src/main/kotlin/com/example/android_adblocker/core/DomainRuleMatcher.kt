package com.example.android_adblocker.core

internal class DomainRuleMatcher(
    blocklist: Set<String>,
    allowlist: Set<String>
) {
    @Volatile
    private var blocklistTrie = DomainSuffixTrie(blocklist)
    @Volatile
    private var allowlistTrie = DomainSuffixTrie(allowlist)
    private val cacheLock = Any()
    private val decisionCache = object : LinkedHashMap<String, Boolean>(CACHE_MAX_ENTRIES, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>): Boolean {
            return size > CACHE_MAX_ENTRIES
        }
    }

    fun updateBlocklist(newBlocklist: Set<String>) {
        blocklistTrie = DomainSuffixTrie(newBlocklist)
        clearCache()
    }

    fun updateAllowlist(newAllowlist: Set<String>) {
        allowlistTrie = DomainSuffixTrie(newAllowlist)
        clearCache()
    }

    fun shouldBlock(domain: String): Boolean {
        if (domain.isEmpty()) return false
        synchronized(cacheLock) {
            decisionCache[domain]?.let { return it }
        }
        val result = if (allowlistTrie.matches(domain)) {
            false
        } else {
            blocklistTrie.matches(domain)
        }
        synchronized(cacheLock) {
            // PERF: DNS lookups are repetitive; cache cuts repeated trie walks.
            decisionCache[domain] = result
        }
        return result
    }

    private fun clearCache() {
        synchronized(cacheLock) {
            decisionCache.clear()
        }
    }

    private companion object {
        private const val CACHE_MAX_ENTRIES = 4096
    }
}
