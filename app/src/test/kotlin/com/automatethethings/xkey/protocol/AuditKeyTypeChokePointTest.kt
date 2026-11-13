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
import org.junit.Assert.fail
import org.junit.Test

/**
 * Key-use audit entries in Handler.kt go through one choke point,
 * `RequestHandler.logKeyUse`:
 *
 * - its keyType comes from `auditKeyType` (the key's stored type, which the
 *   audit screen filters on), never a literal;
 * - its algorithm is the one the operation executed, never the key's stored
 *   metadata (an unvalidated name such as "HMAC-SHA384" ran as SHA-256).
 *
 * This scan fails when a sign, decrypt, encrypt, HMAC or ECDH AuditLogger call
 * sits outside `logKeyUse`, when `logKeyUse` takes keyType from anywhere but
 * `auditKeyType`, or when a `logKeyUse` call passes an algorithm that is not
 * one of the executed-algorithm sources below.
 */
class AuditKeyTypeChokePointTest {

    private val keyUseCall = Regex(
        """AuditLogger\.log(Signing|Decryption|Encryption|Hmac|KeyDerivation)Request\("""
    )

    /**
     * Where an executed algorithm comes from: the validated request algorithm
     * the sign path ran (signWithAlgorithm refuses any other), the HmacResult
     * of the Keystore HMAC, the SoftwareKeyOps mapping the software HMAC
     * runs, and KeystoreManager's names of its fixed transformations.
     */
    private val executedSources = listOf(
        Regex("""^signAlgorithm$"""),
        Regex("""^hmac\.algorithm$"""),
        Regex("""^com\.automatethethings\.xkey\.crypto\.SoftwareKeyOps\.hmacAlgorithm\(|^SoftwareKeyOps\.hmacAlgorithm\("""),
        Regex("""^(com\.automatethethings\.xkey\.crypto\.)?KeystoreManager\.EXECUTED_[A-Z_]+$""")
    )

    @Test
    fun `key-use audit calls sit only in logKeyUse, keyType from auditKeyType`() {
        val source = handlerSource()
        val helper = Regex("""private (suspend )?fun logKeyUse\(""").find(source)
            ?: return fail("RequestHandler.logKeyUse is gone; is the scan stale?")
        val helperBody = bodyRange(source, helper.range.last)

        val calls = keyUseCall.findAll(source).toList()
        assertTrue("no key-use audit calls found; is the scan stale?", calls.size >= 5)

        val offenders = calls.mapNotNull { match ->
            val where = "line ${lineOf(source, match.range.first)}: ${match.value}"
            if (match.range.first !in helperBody) return@mapNotNull "$where outside logKeyUse"
            val keyTypeArg = Regex("""keyType\s*=\s*([^,\n)]+)""")
                .find(argumentList(source, match.range.last))?.groupValues?.get(1)?.trim()
            if (keyTypeArg != "keyType") "$where keyType = $keyTypeArg" else null
        }
        val helperText = source.substring(helperBody.first, helperBody.last)
        val keyTypeSource = Regex("""val keyType\s*=\s*([^\n]+)""").find(helperText)
            ?.groupValues?.get(1)?.trim()
        val keyTypeOffender = if (keyTypeSource?.startsWith("auditKeyType(") == true) {
            emptyList()
        } else {
            listOf("logKeyUse keyType = $keyTypeSource, not auditKeyType(...)")
        }

        val all = offenders + keyTypeOffender
        if (all.isNotEmpty()) fail("key-use audit calls bypass the choke point:\n" + all.joinToString("\n"))
    }

    @Test
    fun `every logKeyUse call passes the algorithm the operation executed`() {
        val source = handlerSource()
        val calls = Regex("""(?<!fun )\blogKeyUse\(""").findAll(source).toList()
        assertTrue("expected the sign, decrypt, encrypt, HMAC and ECDH call sites", calls.size >= 7)

        val offenders = calls.mapNotNull { match ->
            val args = argumentList(source, match.range.last)
            val alg = Regex("""executedAlgorithm\s*=\s*([^,\n]+)""").find(args)
                ?.groupValues?.get(1)?.trim()
            if (alg == null || executedSources.none { it.containsMatchIn(alg) }) {
                "line ${lineOf(source, match.range.first)}: executedAlgorithm = $alg"
            } else {
                null
            }
        }
        if (offenders.isNotEmpty()) {
            fail("logKeyUse calls pass an algorithm that did not execute:\n" + offenders.joinToString("\n"))
        }
    }

    @Test
    fun `every key-use entry names the device captured at request entry`() {
        val source = handlerSource()
        val helper = Regex("""private (suspend )?fun logKeyUse\(""").find(source)
            ?: return fail("RequestHandler.logKeyUse is gone; is the scan stale?")
        val offenders = mutableListOf<String>()

        // logKeyUse takes the device only from the request's AuditCaller.
        val params = argumentList(source, helper.range.last)
        if (!Regex("""\bcaller\s*:\s*AuditCaller\b""").containsMatchIn(params)) {
            offenders += "logKeyUse takes no caller: AuditCaller parameter"
        }
        if (Regex("""\bdevice(Id|Name)\s*:""").containsMatchIn(params)) {
            offenders += "logKeyUse takes a deviceId/deviceName parameter"
        }
        val helperBody = bodyRange(source, helper.range.last)
        keyUseCall.findAll(source).filter { it.range.first in helperBody }.forEach { match ->
            val args = argumentList(source, match.range.last)
            val id = Regex("""deviceId\s*=\s*([^,\n)]+)""").find(args)?.groupValues?.get(1)?.trim()
            val name = Regex("""deviceName\s*=\s*([^,\n)]+)""").find(args)?.groupValues?.get(1)?.trim()
            if (id != "caller.peerPublicKeyHex" || name != "caller.deviceName") {
                offenders += "line ${lineOf(source, match.range.first)}: deviceId = $id, deviceName = $name"
            }
        }

        // Each call passes the caller its handler captured on entry, before
        // any prompt or crypto call can suspend it.
        val calls = Regex("""(?<!fun )\blogKeyUse\(""").findAll(source).toList()
        assertTrue("expected the sign, decrypt, encrypt, HMAC and ECDH call sites", calls.size >= 7)
        calls.forEach { match ->
            val where = "line ${lineOf(source, match.range.first)}"
            val args = argumentList(source, match.range.last)
            if (!Regex("""\bcaller\s*=\s*caller\b""").containsMatchIn(args)) {
                offenders += "$where passes no caller = caller"
            }
            if (Regex("""\bdevice(Id|Name)\s*=""").containsMatchIn(args)) {
                offenders += "$where passes its own deviceId/deviceName"
            }
            val fn = Regex("""private suspend fun (\w+)\(""").findAll(source)
                .lastOrNull { it.range.first < match.range.first }
            if (fn == null) {
                offenders += "$where has no enclosing handler"
                return@forEach
            }
            val upToCall = source.substring(fn.range.first, match.range.first)
            val capture = upToCall.indexOf("val caller = auditCaller()")
            val firstSuspend = listOf("keystoreManager.", "biometricLauncher.", "SoftwareKeyOps.")
                .map { upToCall.indexOf(it) }.filter { it >= 0 }.minOrNull() ?: Int.MAX_VALUE
            if (capture < 0 || capture > firstSuspend) {
                offenders += "$where: ${fn.groupValues[1]} does not capture auditCaller() before its first prompt or crypto call"
            }
        }
        if (offenders.isNotEmpty()) {
            fail("key-use audit entries bypass the request's device:\n" + offenders.joinToString("\n"))
        }
    }

    /** The text between the call's opening parenthesis at [open] and its match. */
    private fun argumentList(source: String, open: Int): String {
        var depth = 0
        for (i in open until source.length) {
            when (source[i]) {
                '(' -> depth++
                ')' -> if (--depth == 0) return source.substring(open + 1, i)
            }
        }
        fail("unbalanced call at offset $open")
        return ""
    }

    /** Offsets of the function body whose parameter list opens at [open]. */
    private fun bodyRange(source: String, open: Int): IntRange {
        val afterParams = open + argumentList(source, open).length + 1
        val brace = source.indexOf('{', afterParams)
        var depth = 0
        for (i in brace until source.length) {
            when (source[i]) {
                '{' -> depth++
                '}' -> if (--depth == 0) return brace..i
            }
        }
        fail("unbalanced body at offset $brace")
        return IntRange.EMPTY
    }

    private fun lineOf(source: String, offset: Int): Int =
        source.substring(0, offset).count { it == '\n' } + 1

    private fun handlerSource(): String {
        val rel = "src/main/kotlin/com/automatethethings/xkey/protocol/Handler.kt"
        val file = listOf(File(rel), File("app/$rel")).firstOrNull { it.isFile }
            ?: error("Handler.kt not found from ${File(".").absolutePath}")
        return file.readText()
    }
}
