package com.example.android_adblocker.core

internal class DomainSuffixTrie(rules: Set<String>) {
    private val root = Node()

    init {
        rules.forEach { rule -> addRule(rule) }
    }

    fun matches(domain: String): Boolean {
        var node = root
        var index = domain.length - 1
        while (index >= 0) {
            val next = node.children[domain[index]] ?: return false
            node = next
            index -= 1
            if (node.isTerminal) {
                // WHY: ラベル境界以外の一致は許可しないため、直前が'.'か終端のみ対象にする。
                if (index < 0 || domain[index] == '.') return true
            }
        }
        return false
    }

    private fun addRule(rule: String) {
        if (rule.isEmpty()) return
        var node = root
        for (index in rule.length - 1 downTo 0) {
            val label = rule[index]
            val next = node.children[label]
            if (next == null) {
                val created = Node()
                node.children[label] = created
                node = created
            } else {
                node = next
            }
        }
        node.isTerminal = true
    }

    private class Node {
        val children: MutableMap<Char, Node> = HashMap()
        var isTerminal: Boolean = false
    }
}
