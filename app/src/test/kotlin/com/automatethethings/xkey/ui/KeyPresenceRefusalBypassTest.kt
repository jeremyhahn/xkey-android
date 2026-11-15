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
package com.automatethethings.xkey.ui

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * #255 review r7, the bypass check: a key read through the resolver
 * ([com.automatethethings.xkey.crypto.KeystoreManager.resolveKey] and every
 * read built on it) throws
 * [com.automatethethings.xkey.crypto.KeyPresenceUnreadableException] while a
 * key store cannot be read. No screen lets it escape: every such read in
 * ui/ runs inside a try that catches it (or a supertype), or inside
 * `runCatching` or the screens' refusing read
 * ([com.automatethethings.xkey.storage.readRefusingUnreadable]), and never in
 * a listener or coroutine that the enclosing try does not cover. The request
 * handler maps it to a refusal at its one dispatch. A generated key's cleanup
 * never passes the presence guard: it deletes its own alias
 * ([com.automatethethings.xkey.crypto.KeystoreManager.discardGeneratedKey]).
 *
 * A source scan, so a new screen read that bypasses the refusal fails here.
 */
class KeyPresenceRefusalBypassTest {

    private val main: File by lazy {
        listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
    }

    private fun sources(dir: String): List<File> =
        File(main, "com/automatethethings/xkey/$dir").walkTopDown()
            .filter { it.isFile && it.extension == "kt" }.toList()

    @Test
    fun theScannerFlagsAnUncoveredReadAndAcceptsCoveredOnes() {
        val source = """
            class S {
                fun bare() { val k = keystoreManager.getPublicKeyDER(id, kind) }
                fun inListener() { try { button.setOnClickListener { keystoreManager.soleKind(id) } } catch (e: Exception) { } }
                fun inLaunch() { try { scope.launch(Dispatchers.IO) { keystore.holdsUserKey(id, kind) } } catch (e: Exception) { } }
                fun narrowCatch() { try { keystoreManager.resolveKey(id, kind) } catch (e: IllegalStateException) { } }
                fun caught() { try { withContext(io) { keystoreManager.getPublicKeyPEM(id, kind) } } catch (e: Exception) { } }
                fun caughtSecond() { try { keystoreManager.exportKind(id) } catch (e: IOException) { } catch (e: java.security.GeneralSecurityException) { } }
                fun refusing() { readRefusingUnreadable { keystoreManager.getPublicKeyDER(id, kind) } }
                fun ran() { runCatching { keystoreManager.keyExists(id, kind) } }
                // keystoreManager.getPublicKeyDER(id, kind) in a comment
            }
        """.trimIndent()
        val flagged = uncoveredReads(source).map { it.substringBefore("(") }
        assertEquals(
            listOf(
                "keystoreManager.getPublicKeyDER", "keystoreManager.soleKind", "keystore.holdsUserKey",
                "keystoreManager.resolveKey"
            ),
            flagged
        )
    }

    @Test
    fun noScreenLetsAnUnreadableKeyStoreEscape() {
        val entries = ENTRY_DIRS.flatMap { sources(it) }.filterNot { CALLED in it.invariantSeparatorsPath }
        val reads = entries.flatMap { file -> readsIn(stripComments(file.readText())).map { file.name } }
        assertTrue("the scan finds the entry points' key reads: $reads", reads.size >= 8)
        val bypassing = entries.flatMap { file ->
            uncoveredReads(file.readText()).map { "${file.name}: $it" }
        }
        assertTrue(
            "screen key reads an unreadable key store can throw out of (wrap in readRefusingUnreadable or a try): $bypassing",
            bypassing.isEmpty()
        )
    }

    /**
     * #255 verify r3 (ruling 554): every screen takes a refusing read's
     * result through the one choke point, `orRefuse`, which shows the
     * refusal and gives no value: no screen matches on the read's outcomes
     * itself (where a branch could put a stand-in, the key id, in place of
     * a value it could not read, as the co-sign QR did).
     */
    @Test
    fun everyScreenTakesARefusingReadThroughTheChokePoint() {
        val outcomes = Regex("""\bKeyRead\.(Value|Unavailable|Unreadable)\b|\bOwnPublicKeyRead\b""")
        val reads = Regex("""\b(readRefusingUnreadable\s*\{|readOwnPublicKey(Der)?\()""")
        val found = mutableListOf<String>()
        val bypassing = mutableListOf<String>()
        for (file in ENTRY_DIRS.flatMap { sources(it) }) {
            val text = stripComments(file.readText())
            outcomes.findAll(text).forEach { bypassing += "${file.name}: ${it.value}" }
            for (read in reads.findAll(text)) {
                found += file.name
                val end = closing(text, read.range.last)
                if (!text.substring(end + 1).trimStart().startsWith(".orRefuse(")) bypassing += "${file.name}: ${read.value}"
            }
        }
        assertTrue("the scan finds the screens' refusing reads: $found", found.size >= 5)
        assertTrue("a screen takes a refusing read around orRefuse: $bypassing", bypassing.isEmpty())
    }

    @Test
    fun theChokePointScannerFlagsAMatchOnTheReadsOutcome() {
        val text = "val k = when (val r = keystoreManager.readOwnPublicKeyDer(id, kind)) { is KeyRead.Value -> r.value; else -> id }"
        val end = closing(text, text.indexOf("readOwnPublicKeyDer(") + "readOwnPublicKeyDer(".length - 1)
        assertTrue(!text.substring(end + 1).trimStart().startsWith(".orRefuse("))
        val ok = "val k = keystoreManager.readOwnPublicKeyDer(id, f(kind))\n    .orRefuse(R.string.x) { show(it) } ?: return"
        val okEnd = closing(ok, ok.indexOf("readOwnPublicKeyDer(") + "readOwnPublicKeyDer(".length - 1)
        assertTrue(ok.substring(okEnd + 1).trimStart().startsWith(".orRefuse("))
    }

    @Test
    fun theRequestHandlerRefusesAnUnreadableKeyStoreAtItsDispatch() {
        val handler = File(main, "com/automatethethings/xkey/protocol/Handler.kt").readText()
        val refusal = handler.indexOf("catch (e: com.automatethethings.xkey.crypto.KeyPresenceUnreadableException)")
        assertTrue("the dispatch catches an unreadable key store", refusal >= 0)
        val body = handler.substring(refusal, handler.indexOf("} catch", refusal + 1))
        assertTrue("the dispatch refuses it as operation denied", "ErrorCodes.OPERATION_DENIED" in body)
        val generic = handler.indexOf("} catch (e: Exception)", refusal)
        assertTrue("the refusal comes before the dispatch's generic catch", generic > refusal)
    }

    @Test
    fun aGeneratedKeysCleanupNeverPassesThePresenceGuard() {
        val guarded = Regex("""\b(deleteKey|deleteGeneralKey|holdsUserKey|resolveKey|resolveKeystoreAlias|keyExists|soleKind)\(""")
        val leaks = mutableListOf<String>()
        for (file in sources("crypto") + sources("protocol")) {
            val text = stripComments(file.readText())
            for (opener in Regex("""\bfinally\s*\{|\bdiscard\s*=\s*\{""").findAll(text)) {
                val open = opener.range.last
                val block = text.substring(open, matchingClose(text, open))
                guarded.find(block)?.let { leaks += "${file.name}: ${opener.value} ${it.value}" }
            }
        }
        assertTrue("a cleanup passes the cross-backend presence guard: $leaks", leaks.isEmpty())

        val handler = stripComments(File(main, "com/automatethethings/xkey/protocol/Handler.kt").readText())
        val discards = Regex("""\bdiscard\s*=\s*\{""").findAll(handler).toList()
        assertTrue("the handler's generated-key discards are found: ${discards.size}", discards.size >= 3)
        for (discard in discards) {
            val block = handler.substring(discard.range.last, matchingClose(handler, discard.range.last))
            assertTrue("a discard deletes its own alias: $block", "discardGeneratedKey(" in block)
        }
        val encryptor = stripComments(File(main, "com/automatethethings/xkey/crypto/FileEncryptor.kt").readText())
        assertTrue("the ephemeral key's cleanup deletes its own alias", "discardGeneratedKey(ephemeralAlias)" in encryptor)
    }

    private companion object {
        /** Reads through the resolver: each throws while a key store cannot be read. */
        val READ = Regex(
            """\b\w*[Kk]ey[Ss]tore\w*\??\.(sign|signWithAlgorithm|signWithoutBiometric|getPublicKeyDER|getPublicKeyPEM|""" +
                """getPublicKeySSH|getPublicKey|getCOSEPublicKey|getAttestationChain|keyExists|resolveKey|resolveKeystoreAlias|""" +
                """holdsUserKey|soleKind|exportKind|userKeyIdInUse|holdsAnyKey|holdsInternalKey|userKeyGeneration|""" +
                """userKeyPresence)\(|\b(withUsableKey|requireUsable|readShareable)\(|(?<!fun )\bforgetKey\(|""" +
                // The credential provider's handlers, checked at the screens and service that call them.
                """\b(createHandler|getHandler)\.handle\w*\("""
        )

        /** The entry points: screens, the media signing service, the credential provider. */
        val ENTRY_DIRS = listOf("ui", "media", "credential")

        /** Code that the entry points call, which throws to them by design. */
        const val CALLED = "/credential/handler/"

        /** Catches that take the exception: it and its supertypes. */
        val CATCHING = setOf(
            "Exception", "Throwable", "GeneralSecurityException", "KeyStoreException", "KeyPresenceUnreadableException"
        )

        /** Blocks that run later, outside any try around their creation. */
        val DEFERRED = Regex("""\b(launch|async|post|postDelayed|runOnUiThread|setOn\w+Listener|addOn\w+Listener|registerForActivityResult|Runnable|Thread)\b[^{};]*$""")

        /** A function's own body: a try outside it is its caller's. */
        val FUNCTION = Regex("""\bfun\b[^{};=]*$""")

        val COVERING = Regex("""\b(runCatching|readRefusingUnreadable)\s*(\([^{};]*\))?$""")

        fun readsIn(text: String): List<MatchResult> = READ.findAll(text).toList()

        /** The reads in [source] that an unreadable key store can throw out of. */
        fun uncoveredReads(source: String): List<String> {
            val text = stripComments(source)
            return readsIn(text).filterNot { covered(text, it.range.first) }.map { it.value }
        }

        fun covered(text: String, at: Int): Boolean {
            var pos = at
            while (true) {
                val open = enclosingOpen(text, pos) ?: return false
                val prefix = text.substring(0, open).trimEnd()
                when {
                    prefix.endsWith("try") && Regex("""\btry$""").containsMatchIn(prefix) -> {
                        if (catchTypes(text, matchingClose(text, open)).any { it in CATCHING }) return true
                    }
                    COVERING.containsMatchIn(prefix) -> return true
                    DEFERRED.containsMatchIn(prefix) -> return false
                    FUNCTION.containsMatchIn(prefix) -> return false
                }
                pos = open
            }
        }

        /** The `{` that opens the innermost block around [pos], or null at top level. */
        fun enclosingOpen(text: String, pos: Int): Int? {
            var depth = 0
            var i = pos - 1
            while (i >= 0) {
                when (text[i]) {
                    '}' -> depth++
                    '{' -> if (depth == 0) return i else depth--
                }
                i--
            }
            return null
        }

        /** The index of the `)` or `}` closing the `(` or `{` at [open]. */
        fun closing(text: String, open: Int): Int {
            var depth = 0
            for (i in open until text.length) {
                when (text[i]) {
                    '(', '{' -> depth++
                    ')', '}' -> if (--depth == 0) return i
                }
            }
            return text.length - 1
        }

        /** The index of the `}` closing the `{` at [open]. */
        fun matchingClose(text: String, open: Int): Int {
            var depth = 0
            for (i in open until text.length) {
                when (text[i]) {
                    '{' -> depth++
                    '}' -> if (--depth == 0) return i
                }
            }
            return text.length - 1
        }

        /** The simple type names of the catch clauses after a try block closing at [close]. */
        fun catchTypes(text: String, close: Int): List<String> {
            val types = mutableListOf<String>()
            var pos = close + 1
            val clause = Regex("""\G\s*catch\s*\(\s*\w+\s*:\s*([\w.]+)\s*\)\s*\{""")
            while (true) {
                val match = clause.find(text, pos) ?: return types
                types += match.groupValues[1].substringAfterLast('.')
                pos = matchingClose(text, match.range.last) + 1
            }
        }

        /** [source] with comments and brace char literals blanked, offsets kept. */
        fun stripComments(source: String): String {
            val blank = { m: MatchResult -> m.value.replace(Regex("""[^\n]"""), " ") }
            return source
                .replace(Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL), blank)
                .replace(Regex("""(?m)^\s*//[^\n]*"""), blank)
                .replace(Regex("""(?<![:"])//[^\n"]*$""", RegexOption.MULTILINE), blank)
                .replace(Regex("""'[{}]'"""), blank)
        }
    }
}
