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
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Key use goes through the pairing gate, isDeviceAttestationCurrent(forKeyUse = true).
 * Fails when a gated handler reads its params before the gate, or when an
 * instrumented suite that calls a gated method builds its RequestHandler without
 * a paired-device store, so its key-use calls would stop at the gate.
 */
class KeyUseGateChokePointTest {

    private val srcDir: File =
        listOf(File("src"), File("app/src")).first { File(it, "main/kotlin").isDirectory }

    private val gatedHandlers = listOf(
        "handleLocalSign",
        "handleLocalDecrypt",
        "handleLocalSymmetricEncrypt",
        "handleLocalSymmetricDecrypt",
        "handleLocalHMAC",
        "handleLocalECDH",
        "handleLocalGetPublicKey",
    )

    private val gatedMethods = listOf(
        "local.sign",
        "local.decrypt",
        "local.symmetricEncrypt",
        "local.symmetricDecrypt",
        "local.hmac",
        "local.ecdh",
        "local.getPublicKey",
    )

    private val nextMember = Regex("\n    (?:private |internal |public |override |protected )*(?:suspend )?fun ")

    /** Body of the named member function, up to the next member at class indent. */
    private fun functionBody(source: String, name: String): String {
        val start = source.indexOf("fun $name(")
        assertTrue("Handler.kt has no fun $name(", start >= 0)
        val end = nextMember.find(source, start + 1)?.range?.first ?: source.length
        return source.substring(start, end)
    }

    @Test
    fun everyGatedHandlerChecksThePairingGateBeforeItsParams() {
        val handler = File(srcDir, "main/kotlin/com/automatethethings/xkey/protocol/Handler.kt").readText()
        val ungated = gatedHandlers.filter { name ->
            val body = functionBody(handler, name)
            val gate = body.indexOf("isDeviceAttestationCurrent(forKeyUse = true)")
            val params = body.indexOf("request.params")
            gate < 0 || (params in 0 until gate)
        }
        assertEquals("key-use handlers that read params before the pairing gate", emptyList<String>(), ungated)
    }

    /** Argument lists of each `RequestHandler(` constructor call, matched by balanced parentheses. */
    private fun constructorArgs(source: String): List<String> {
        val calls = mutableListOf<String>()
        val call = Regex("(?<![A-Za-z0-9_.])RequestHandler\\(")
        for (match in call.findAll(source)) {
            val open = match.range.last
            var depth = 0
            var i = open
            while (i < source.length) {
                when (source[i]) {
                    '(' -> depth++
                    ')' -> {
                        depth--
                        if (depth == 0) break
                    }
                }
                i++
            }
            calls += source.substring(open + 1, minOf(i, source.length))
        }
        return calls
    }

    @Test
    fun everyInstrumentedKeyUseFixtureHasAPairedDeviceStore() {
        val androidTest = File(srcDir, "androidTest")
        val unpaired = androidTest.walkTopDown()
            .filter { it.isFile && it.extension == "kt" }
            .filter { file ->
                val text = file.readText()
                gatedMethods.any { "\"$it\"" in text } &&
                    constructorArgs(text).any { "pairedDeviceRepository =" !in it }
            }
            .map { it.name }
            .sorted()
            .toList()
        assertEquals(
            "instrumented suites calling a gated key-use method with an unpaired RequestHandler",
            emptyList<String>(),
            unpaired
        )
    }
}
