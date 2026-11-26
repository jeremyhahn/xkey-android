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
package com.automatethethings.xkey.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * #270 verify (ruling 554 sweep): which user key owns an id is read from
 * the material stored under it, at one place,
 * [com.automatethethings.xkey.crypto.KeystoreManager.ownersOf] (and
 * `userKeyOwners`, which reads that material from every backend). A row's
 * type is read only where the material cannot tell (`rowKeyKind`), and no
 * delete, replay or sync caller infers a key's namespace from the row type
 * or from a cached presence probe.
 */
class KeyOwnershipChokePointTest {

    private val main: File by lazy { listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory } }

    private fun source(path: String): String = stripComments(File(main, "com/automatethethings/xkey/$path").readText())

    /** The body of the function [name] declared in [text]: from its declaration to the next one. */
    private fun body(text: String, name: String): String {
        val start = Regex("""fun $name\(""").find(text)?.range?.first
        assertTrue("fun $name is gone", start != null)
        val next = Regex("""\n\s*(?:(?:private|internal|override|suspend|public)\s+)*fun\s""").find(text, start!! + 1)?.range?.first ?: text.length
        return text.substring(start, next)
    }

    @Test
    fun theRowTypeIsReadOnlyByRowKeyKind() {
        val callers = main.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { file ->
            val text = stripComments(file.readText())
            Regex("""userKeyKindOf\(""").findAll(text).map { file.name to lineOf(text, it.range.first) }
        }.toList()
        val manager = source("crypto/KeystoreManager.kt")
        val rowKeyKind = body(manager, "rowKeyKind")
        val inRowKeyKind = Regex("""userKeyKindOf\(""").findAll(rowKeyKind).count()
        assertTrue("rowKeyKind no longer falls back to the row type", inRowKeyKind > 0)
        assertTrue("rowKeyKind reads the row type before the material", "ownersOf(" in rowKeyKind.substringBefore("userKeyKindOf("))
        // Its declaration and rowKeyKind's fallbacks, nothing else.
        assertEquals("row-type reads outside rowKeyKind: $callers", inRowKeyKind + 1, callers.size)
        assertTrue("row-type reads outside KeystoreManager: $callers", callers.all { it.first == "KeystoreManager.kt" })
    }

    @Test
    fun everyResolverReadsOwnersFromTheMaterial() {
        val manager = source("crypto/KeystoreManager.kt")
        for (name in listOf("rowKeyKind", "deleteTarget", "presentKind", "userKeyOwners")) {
            assertTrue("$name does not resolve through ownersOf", "ownersOf(" in body(manager, name))
        }
    }

    @Test
    fun theReplayDecidesInternalKeysFromTheTombstone() {
        val replay = source("storage/KeyDeletionReplay.kt")
        val delete = body(replay, "deleteKeyMaterial")
        assertTrue("the replay does not read the tombstone's owners", "ownersOf(" in delete)
        assertFalse("the replay probes the cached backends for an internal key", "isInternalKey(" in delete)
        assertFalse("the replay probes the cached backends for an internal key", "holdsInternalKey(" in delete)
    }

    @Test
    fun syncDiscoveryReadsOwnersFromEveryBackend() {
        val sync = source("storage/KeyStoreSyncManager.kt")
        assertTrue("discovery does not read the id's owners", "keystoreManager.userKeyOwners(" in sync)
        assertFalse("discovery reads ownership from the Keystore alone", Regex("""fun ownedByUserKey\(keyStore""").containsMatchIn(sync))
    }

    /** #270 verify r2: every row delete hands `rowKeyKind` both encodings of the row's key; a passkey row is COSE only. */
    @Test
    fun everyRowDeleteMatchesTheRowsKeyInEveryEncoding() {
        val manager = source("crypto/KeystoreManager.kt")
        val rowKeyKind = body(manager, "rowKeyKind")
        assertTrue("rowKeyKind does not match through matchRowPublicKey", "matchRowPublicKey(" in rowKeyKind)
        assertTrue("the match ignores the DER key", "getPublicKeyDER(" in rowKeyKind)
        assertTrue("the match ignores the COSE key", "getCOSEPublicKey(" in rowKeyKind)
        val match = body(manager, "matchRowPublicKey")
        assertTrue("the match reads one encoding", "row.der" in match && "row.cose" in match)
        val calls = main.walkTopDown().filter { it.isFile && it.extension == "kt" }.flatMap { file ->
            val text = stripComments(file.readText())
            Regex("""\.rowKeyKind\(""").findAll(text).map { file.name to text.substring(it.range.first, minOf(text.length, it.range.first + 240)) }
        }.toList()
        assertTrue("no row delete calls rowKeyKind", calls.isNotEmpty())
        for ((file, call) in calls) {
            assertTrue("$file hands rowKeyKind no COSE key: $call", Regex("""RowPublicKey\([^)]*publicKeyCose""").containsMatchIn(call))
        }
    }

    /** #270 verify r3: an Ed25519 key's public half is read from its preferences entry, which has no certificate. */
    @Test
    fun theRowMatchReadsEd25519KeysFromTheirBackend() {
        val rowKeyKind = body(source("crypto/KeystoreManager.kt"), "rowKeyKind")
        assertTrue("rowKeyKind reads a legacy Ed25519 private key", "getEd25519PrivateKey(" !in rowKeyKind && "ed25519PublicKeyDer(" !in rowKeyKind)
        assertTrue("rowKeyKind places a legacy Ed25519 key by its entry", "ED25519_ENTRY" in rowKeyKind)
    }

    /** #270 verify r3: a remote (`xkmsd`) key's delete resolves no kind, so it probes no local backend. */
    @Test
    fun aRemoteKeyDeleteResolvesNoLocalKind() {
        val replay = source("storage/KeyDeletionReplay.kt")
        assertFalse("a delete resolves its kind before the source check", "deleteKind(held))" in replay || "deleteKind(held), " in replay)
        val lazy = Regex("""fun readKeyMaterialGeneration\([^)]*kind: \(\) -> UserKeyKind\?""").find(replay)
        assertTrue("readKeyMaterialGeneration takes no lazy kind", lazy != null)
        val read = replay.substring(lazy!!.range.first)
        assertTrue("the kind is read before the source check", read.indexOf("\"xkmsd\"") in 0 until read.indexOf("kind()"))
    }

    private fun lineOf(text: String, offset: Int): Int = text.substring(0, offset).count { it == '\n' } + 1

    private fun stripComments(text: String): String =
        text.replace(Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL)) { m -> m.value.filter { it == '\n' } }
            .replace(Regex("""//[^\n]*"""), "")
}
