/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
 *
 * This file is part of xkey-android.
 *
 * xkey-android is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */

package com.automatethethings.xkey.testing

/**
 * Stub: the old sweep logic, which counts a crypto call as gated when a gate
 * call opens within [GATE_WINDOW] lines above it.
 */
class GateScopeScanner(source: String, private val gateNames: List<String>) {

    data class Call(val line: Int, val offset: Int, val arguments: List<String>) {
        val keyId: String get() = arguments.firstOrNull().orEmpty()
    }

    data class Gate(val name: String, val keyId: String, val line: Int)

    data class Function(val name: String, val isPrivate: Boolean)

    private val text = source
    private val lines = source.lines()

    val gates: List<Gate> = emptyList()

    fun calls(pattern: Regex): List<Call> = pattern.findAll(text).map {
        Call(text.substring(0, it.range.first).count { c -> c == '\n' }, it.range.first, emptyList())
    }.toList()

    fun isGated(call: Call, keyMatches: (String, String) -> Boolean = ::sameKey): Boolean =
        (maxOf(0, call.line - GATE_WINDOW)..call.line).any { l -> gateNames.any { "$it(" in lines[l] } }

    fun enclosingFunction(offset: Int): Function? = null

    fun isGatedThroughHelper(call: Call): Boolean = isGated(call)

    companion object {
        const val GATE_WINDOW = 4

        fun sameKey(gate: String, call: String): Boolean = gate.trim() == call.trim()
    }
}
