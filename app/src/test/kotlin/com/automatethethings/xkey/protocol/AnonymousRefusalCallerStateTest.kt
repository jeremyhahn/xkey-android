/*
 * Copyright (c) 2025 Jeremy Hahn
 * Copyright (c) 2025 Automate The Things, LLC
 *
 * This file is part of xKey.
 *
 * xKey is dual-licensed:
 *
 * 1. GNU Affero General Public License v3.0 (AGPL-3.0)
 *    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
 *
 * 2. Commercial License
 *    Contact licensing@automatethethings.com for commercial licensing options.
 */
package com.automatethethings.xkey.protocol

import java.io.File
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The instrumented protocol suites connect a paired peer before every test.
 * A test that asserts a refusal for an anonymous, unpaired or unconfirmed
 * caller must set that caller state itself, before its first refusal
 * assertion, or the shared fixture's peer passes the check it means to test.
 */
class AnonymousRefusalCallerStateTest {

    private val protocolTests: File = listOf(
        File("src/androidTest/kotlin/com/automatethethings/xkey/protocol"),
        File("app/src/androidTest/kotlin/com/automatethethings/xkey/protocol")
    ).first { it.isDirectory }

    private class Case(val file: String, val name: String, val doc: String, val body: String)

    private val testHeader = Regex("""@Test(?:\([^)]*\))?\s+fun\s+(\w+)\s*\(""")

    /** Names or KDoc that say the caller is anonymous, unpaired or has no confirmed peer. */
    private val callerless = Regex(
        """anonymous|unpaired|unconfirmed|no\s*(confirmed\s*)?peer|without\s*a?\s*(confirmed\s*)?peer""",
        RegexOption.IGNORE_CASE
    )

    private val refusal = Regex("""ErrorCodes\.(OPERATION_DENIED|PAIRING_REQUIRED)\b""")

    private val callerState = Regex("""setConnectedDevicePublicKeyHex\(|\bservedPeer\s*=|setSessionId\(""")

    private val cases: List<Case> by lazy {
        protocolTests.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { file ->
            val text = file.readText()
            testHeader.findAll(text).map { match ->
                val open = text.indexOf('{', match.range.last)
                var depth = 0
                var end = open
                while (end < text.length) {
                    when (text[end]) {
                        '{' -> depth++
                        '}' -> if (--depth == 0) break
                    }
                    end++
                }
                val body = text.substring(open, end).lines()
                    .filterNot { it.trimStart().startsWith("//") }
                    .joinToString("\n")
                Case(file.name, match.groupValues[1], kdocBefore(text, match.range.first), body)
            }.toList()
        }.toList()
    }

    /** The KDoc directly above the test as one line of text, or empty when none. */
    private fun kdocBefore(text: String, testAt: Int): String {
        val start = text.lastIndexOf("/**", testAt)
        if (start < 0) return ""
        val close = text.indexOf("*/", start)
        if (close < 0 || close > testAt) return ""
        if (text.substring(close + 2, testAt).isNotBlank()) return ""
        return text.substring(start + 3, close).lines().joinToString(" ") { it.trimStart().removePrefix("*").trim() }
    }

    private fun Case.isCallerlessRefusal(): Boolean =
        (callerless.containsMatchIn(name) || callerless.containsMatchIn(doc)) && refusal.containsMatchIn(body)

    @Test
    fun theScanFindsTheKnownCallerlessRefusalCases() {
        val names = cases.filter { it.isCallerlessRefusal() }.map { it.name }.toSet()
        for (known in listOf(
            "setKeyPolicyRefusesToWidenAKeyWithoutTheOwnersApproval",
            "sharingWithoutAConfirmedPeerIsDenied",
            "cosignRequestRefusesASessionWithNoConfirmedPeer"
        )) {
            assertTrue("the scan must see $known; found $names", known in names)
        }
    }

    @Test
    fun everyCallerlessRefusalSetsItsCallerStateBeforeItsFirstRefusal() {
        val offenders = cases.filter { it.isCallerlessRefusal() }.filter { case ->
            val firstState = callerState.find(case.body)?.range?.first ?: Int.MAX_VALUE
            val firstRefusal = refusal.find(case.body)!!.range.first
            firstState > firstRefusal
        }.map { "${it.file}: ${it.name}" }
        assertTrue(
            "these tests assert an anonymous or unpaired refusal under the shared paired-peer fixture " +
                "without setting their own caller state first: $offenders",
            offenders.isEmpty()
        )
    }
}
