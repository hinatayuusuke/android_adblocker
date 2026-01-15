package com.example.android_adblocker.core

internal class DomainRuleMatcher(
    blocklist: Set<String>,
    allowlist: Set<String>
) {
    @Volatile
    private var blocklistTrie = DomainSuffixTrie(blocklist)
    @Volatile
    private var allowlistTrie = DomainSuffixTrie(allowlist)

    fun updateBlocklist(newBlocklist: Set<String>) {
        blocklistTrie = DomainSuffixTrie(newBlocklist)
    }

    fun updateAllowlist(newAllowlist: Set<String>) {
        allowlistTrie = DomainSuffixTrie(newAllowlist)
    }

    fun shouldBlock(domain: String): Boolean {
        if (domain.isEmpty()) return false
        if (allowlistTrie.matches(domain)) return false
        return blocklistTrie.matches(domain)
    }
}
