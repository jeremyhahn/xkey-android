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
 * Reads a Kotlin source for the key-use gate sweeps: where each gate call's
 * block starts and ends, and which key it opened.
 *
 * A gate is a call of one of [gateNames] with a block: its trailing lambda,
 * or its last argument when that is a lambda. The block is found by matching
 * braces in the code with comments, strings and char literals blanked, so a
 * brace in any of them never ends it. The gate's key id is its first
 * argument, trimmed, with any `name =` dropped.
 *
 * A crypto call is gated only when it lies inside the block of a gate whose
 * key id matches the call's first argument. A call after a closed gate block,
 * or inside a gate on another key, is ungated however close it sits.
 */
class GateScopeScanner(private val source: String, gateNames: List<String>) {

    /** A call matched by [calls]: its 0-based [line], its [offset] and its arguments as written. */
    data class Call(val line: Int, val offset: Int, val arguments: List<String>) {
        /** The first argument, trimmed, with any `name =` dropped. */
        val keyId: String get() = arguments.firstOrNull()?.let(::unnamed).orEmpty()
    }

    /** A gate call; [body] is the offsets of its block, braces included. */
    data class Gate(val name: String, val keyId: String, val line: Int, val offset: Int, val body: IntRange)

    /** A function declaration with a body; [body] is the offsets of that body. */
    data class Function(val name: String, val offset: Int, val body: IntRange, val isPrivate: Boolean)

    private val masker = Masker(source)

    /** The source with comments, strings and chars blanked: same offsets, same line breaks. */
    private val code: String = String(masker.code)

    /** The source with only comments blanked, for argument text. */
    private val commentless: String = String(masker.commentless)

    private val lineStarts: IntArray = buildList {
        add(0)
        source.forEachIndexed { i, c -> if (c == '\n') add(i + 1) }
    }.toIntArray()

    val gates: List<Gate> = gateNames.flatMap(::findGates).sortedBy { it.offset }

    val functions: List<Function> = findFunctions()

    /** Every match of [pattern] in the code (never in a comment or a string), with its call's arguments. */
    fun calls(pattern: Regex): List<Call> = pattern.findAll(code).map { m ->
        val open = if (code[m.range.last] == '(') m.range.last else nextOnLine(m.range.last + 1).takeIf { it < code.length && code[it] == '(' }
        Call(lineOf(m.range.first), m.range.first, open?.let { arguments(it).ranges.map(::text) }.orEmpty())
    }.toList()

    /** The gates whose block holds [offset], outermost first. */
    fun gatesAround(offset: Int): List<Gate> = gates.filter { offset in it.body }

    /** Whether [call] lies in the block of a gate whose key id [keyMatches] the call's (gate key, call key). */
    fun isGated(call: Call, keyMatches: (String, String) -> Boolean = ::sameKey): Boolean =
        gatesAround(call.offset).any { keyMatches(it.keyId, call.keyId) }

    /** The innermost function whose body holds [offset]. */
    fun enclosingFunction(offset: Int): Function? =
        functions.filter { offset in it.body }.minByOrNull { it.body.last - it.body.first }

    /**
     * Whether [call] sits in a private helper whose every call is in the block
     * of a gate on a key the helper call is passed. A helper never called, or
     * referenced as a value (`::helper`), is not gated.
     */
    fun isGatedThroughHelper(call: Call): Boolean {
        val helper = enclosingFunction(call.offset)?.takeIf { it.isPrivate } ?: return false
        val name = Regex.escape(helper.name)
        if (Regex("""::\s*$name\b""").containsMatchIn(code)) return false
        val uses = Regex("""\b$name\s*\(""").findAll(code)
            .filter { it.range.first !in helper.body && !isDeclared(it.range.first) }
            .toList()
        return uses.isNotEmpty() && uses.all { use ->
            val passed = arguments(use.range.last).ranges.map { unnamed(text(it)) }
            gatesAround(use.range.first).any { gate -> passed.any { sameKey(gate.keyId, it) } }
        }
    }

    private class Arguments(val ranges: List<IntRange>, val close: Int)

    /** The arguments of the call whose `(` is at [open]: split at its top-level commas. */
    private fun arguments(open: Int): Arguments {
        val ranges = mutableListOf<IntRange>()
        var depth = 0
        var start = open + 1
        for (i in open until code.length) {
            when (code[i]) {
                '(', '[', '{' -> depth++
                ')', ']', '}' -> {
                    depth--
                    if (depth == 0) {
                        if (code.substring(start, i).isNotBlank()) ranges += start until i
                        return Arguments(ranges, i)
                    }
                }
                ',' -> if (depth == 1) {
                    ranges += start until i
                    start = i + 1
                }
            }
        }
        return Arguments(ranges, code.length - 1)
    }

    private fun findGates(name: String): List<Gate> =
        Regex("""\b${Regex.escape(name)}\s*(<[^(){}]*>)?\s*\(""").findAll(code).mapNotNull { m ->
            if (isDeclared(m.range.first)) return@mapNotNull null
            val args = arguments(m.range.last)
            val after = nextOnLine(args.close + 1)
            val lastArg = args.ranges.lastOrNull()?.let { nextSpace(it.first) }
            val body = when {
                after < code.length && code[after] == '{' -> after..matchingBrace(after)
                lastArg != null && code[lastArg] == '{' -> lastArg..matchingBrace(lastArg)
                else -> return@mapNotNull null
            }
            Gate(name, unnamed(args.ranges.firstOrNull()?.let(::text).orEmpty()), lineOf(m.range.first), m.range.first, body)
        }.toList()

    private fun findFunctions(): List<Function> =
        Regex("""\bfun\s+(<[^>]*>\s*)?(?:[\w.<>?, ]+\.)?`?(\w+)`?\s*\(""").findAll(code).mapNotNull { m ->
            val body = bodyAfter(arguments(m.range.last).close + 1) ?: return@mapNotNull null
            val lineStart = code.lastIndexOf('\n', m.range.first) + 1
            val isPrivate = Regex("""\bprivate\b""").containsMatchIn(code.substring(lineStart, m.range.first))
            Function(m.groupValues[2], m.range.first, body, isPrivate)
        }.toList()

    /** The body after a function's parameter list closes at [from] - 1: a block, an expression, or none. */
    private fun bodyAfter(from: Int): IntRange? {
        var depth = 0
        var i = from
        while (i < code.length) {
            val c = code[i]
            when {
                c == '(' -> depth++
                c == ')' -> depth--
                depth > 0 -> Unit
                c == '{' -> return i..matchingBrace(i)
                c == '=' && code.getOrNull(i + 1) != '=' -> return i..expressionEnd(i + 1)
                c == '}' || c == ';' -> return null
                c == '\n' -> {
                    val next = nextSpace(i)
                    if (next >= code.length || code[next] !in "{=:" && !code.startsWith("where", next)) return null
                }
            }
            i++
        }
        return null
    }

    /** The last offset of an expression body starting at [from]. */
    private fun expressionEnd(from: Int): Int {
        var depth = 0
        var seen = false
        var i = from
        while (i < code.length) {
            val c = code[i]
            when {
                c in "([{" -> depth++
                c in ")]}" -> if (--depth < 0) return i - 1
                c == '\n' && depth == 0 && seen -> {
                    val next = nextSpace(i)
                    if (next >= code.length || code[next] !in ".?:&|+-*/") return i - 1
                }
            }
            if (!c.isWhitespace()) seen = true
            i++
        }
        return code.length - 1
    }

    /** The offset of the `}` closing the `{` at [open]. */
    private fun matchingBrace(open: Int): Int {
        var depth = 0
        for (i in open until code.length) {
            when (code[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return i
            }
        }
        return code.length - 1
    }

    /** Whether the name at [start] is being declared (`fun name`, `fun <T> Recv.name`), not called. */
    private fun isDeclared(start: Int): Boolean =
        Regex("""\bfun\s+(<[^>]*>\s*)?([\w.<>?, ]+\.)?$""").containsMatchIn(code.substring(maxOf(0, start - 200), start))

    private fun nextOnLine(from: Int): Int {
        var i = from
        while (i < code.length && (code[i] == ' ' || code[i] == '\t')) i++
        return i
    }

    private fun nextSpace(from: Int): Int {
        var i = from
        while (i < code.length && code[i].isWhitespace()) i++
        return i
    }

    private fun text(range: IntRange): String = commentless.substring(range.first, range.last + 1).trim()

    private fun lineOf(offset: Int): Int {
        val at = lineStarts.binarySearch(offset)
        return if (at >= 0) at else -at - 2
    }

    /** Blanks comments (nested block comments too), strings (templates included) and char literals. */
    private class Masker(private val s: String) {
        val code = s.toCharArray()
        val commentless = s.toCharArray()

        init {
            scanCode(0, template = false)
        }

        private fun blank(from: Int, to: Int, comment: Boolean) {
            for (k in from until minOf(to, s.length)) {
                if (s[k] == '\n') continue
                code[k] = ' '
                if (comment) commentless[k] = ' '
            }
        }

        /** Scans code from [start]; in a [template], returns the offset after the `}` that closes it. */
        private fun scanCode(start: Int, template: Boolean): Int {
            var depth = 0
            var i = start
            while (i < s.length) {
                val c = s[i]
                when {
                    s.startsWith("//", i) -> {
                        val end = s.indexOf('\n', i).let { if (it < 0) s.length else it }
                        blank(i, end, comment = true)
                        i = end
                    }
                    s.startsWith("/*", i) -> {
                        val end = blockCommentEnd(i)
                        blank(i, end, comment = true)
                        i = end
                    }
                    s.startsWith("\"\"\"", i) -> {
                        val end = rawStringEnd(i + 3)
                        blank(i, end, comment = false)
                        i = end
                    }
                    c == '"' -> {
                        val end = stringEnd(i + 1)
                        blank(i, end, comment = false)
                        i = end
                    }
                    c == '\'' -> {
                        val end = charEnd(i + 1)
                        blank(i, end, comment = false)
                        i = end
                    }
                    c == '{' -> {
                        depth++
                        i++
                    }
                    c == '}' -> {
                        if (template && depth == 0) return i + 1
                        depth--
                        i++
                    }
                    else -> i++
                }
            }
            return s.length
        }

        private fun blockCommentEnd(start: Int): Int {
            var depth = 0
            var i = start
            while (i < s.length) {
                when {
                    s.startsWith("/*", i) -> {
                        depth++
                        i += 2
                    }
                    s.startsWith("*/", i) -> {
                        i += 2
                        if (--depth == 0) return i
                    }
                    else -> i++
                }
            }
            return s.length
        }

        private fun stringEnd(start: Int): Int {
            var i = start
            while (i < s.length) {
                when {
                    s[i] == '\\' -> i += 2
                    s[i] == '"' -> return i + 1
                    s[i] == '\n' -> return i
                    s.startsWith("\${", i) -> i = scanCode(i + 2, template = true)
                    else -> i++
                }
            }
            return s.length
        }

        private fun rawStringEnd(start: Int): Int {
            var i = start
            while (i < s.length) {
                when {
                    s.startsWith("\"\"\"", i) -> {
                        var end = i + 3
                        while (end < s.length && s[end] == '"') end++
                        return end
                    }
                    s.startsWith("\${", i) -> i = scanCode(i + 2, template = true)
                    else -> i++
                }
            }
            return s.length
        }

        private fun charEnd(start: Int): Int {
            var i = start
            if (i < s.length && s[i] == '\\') i += 2
            while (i < s.length && s[i] != '\'' && s[i] != '\n') i++
            return minOf(i + 1, s.length)
        }
    }

    companion object {
        /** Whether a gate's key id and a call's first argument are the same expression, spacing aside. */
        fun sameKey(gate: String, call: String): Boolean =
            gate.filterNot(Char::isWhitespace) == call.filterNot(Char::isWhitespace)

        private fun unnamed(argument: String): String = argument.replace(Regex("""^\w+\s*=(?!=)\s*"""), "").trim()
    }
}
