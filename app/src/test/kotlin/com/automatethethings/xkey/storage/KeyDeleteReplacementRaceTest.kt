/*
 * Copyright (c) 2026 Jeremy Hahn
 * Copyright (c) 2026 Automate The Things, LLC
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

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.protocol.KeyIdReservations
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Collections

/**
 * A delete's reread of the row it was confirmed for is a snapshot: the row
 * can be deleted and its ID recreated between the read and the delete
 * resuming. The reread, the material removal and the row deletion hold the
 * key's mutation lock, the one every key creation takes, so a replacement
 * never lands inside that window and its row and material survive.
 */
class KeyDeleteReplacementRaceTest {

    private val aliases = Collections.synchronizedSet(hashSetOf("xkey_key_k"))
    private val rows = Collections.synchronizedMap(linkedMapOf<String, KeyEntity>())
    private val keystore = mockk<KeystoreManager>(relaxed = true).also { ks ->
        every { ks.listAllKeystoreAliases() } answers { aliases.toList() }
        every { ks.generalKeyExists(any()) } answers { "xkey_key_${firstArg<String>()}" in aliases }
        every { ks.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { ks.deleteByAlias(any()) } answers { aliases.remove(firstArg<String>()) }
    }
    private val software = mockk<SoftwareKeyStore>(relaxed = true).also {
        every { it.contains(any()) } returns false
    }

    private val original = KeyEntity(
        id = 5, keyId = "k", keyType = "ec", algorithm = "ES256", label = "k", keySizeBits = 256,
        source = "local", materialNamespace = KeyNamespace.GENERAL.stored
    )
    private val replacement = original.copy(id = 6, label = "replacement")

    @Test
    fun aKeyReplacedWhileTheDeleteHoldsItsRereadSurvives() = runBlocking {
        rows["k"] = original
        var replacer: Job? = null
        coroutineScope {
            var raced = false
            val keyDao = mockk<KeyDao>(relaxed = true)
            coEvery { keyDao.exists(any()) } answers { firstArg<String>() in rows }
            coEvery { keyDao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
            coEvery { keyDao.getByKeyId(any()) } coAnswers {
                val snapshot = rows[firstArg<String>()]
                if (!raced) {
                    raced = true
                    // Before the reread's result reaches the delete, another
                    // delete of `k` runs and local.generateKey recreates it,
                    // under the lock local.generateKey takes.
                    val job = launch {
                        keyDao.deleteKeyRow(original, keystore, software)
                        KeyIdReservations.process.withKeyLock("key:k") {
                            aliases += "xkey_key_k"
                            rows["k"] = replacement
                        }
                    }
                    replacer = job
                    withTimeoutOrNull(500) { job.join() }
                }
                snapshot
            }

            keyDao.deleteKeyRow(original, keystore, software)
            replacer?.join()
        }

        assertEquals("the replacement row survives", replacement, rows["k"])
        assertTrue("the replacement's material survives", "xkey_key_k" in aliases)
    }

    /**
     * Every source file that creates key material or a key row takes the
     * key's mutation lock: [withKeyMutation], or the protocol's
     * `withKeyLock` (local.generateKey, the base generateKey).
     */
    @Test
    fun everyKeyCreationPathTakesTheKeyMutationLock() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val creates = Regex(
            """keyDao\.insert\(|\.generate(KeyForAlgorithm|RSAEncryptionKey|SymmetricKey|HMACKey|KeyWithAuthDuration)\(|""" +
                """\.put\(\s*(com\.automatethethings\.xkey\.crypto\.)?SoftwareKey\("""
        )
        val locks = Regex("""withKeyMutation\(|withKeyLock\(""")
        val code = { f: File -> f.readLines().filterNot { it.trimStart().startsWith("*") || it.trimStart().startsWith("//") }.joinToString("\n") }
        val unlocked = root.walkTopDown()
            .filter { it.isFile && it.extension == "kt" && it.name != "KeystoreManager.kt" }
            .filter { f -> code(f).let { creates.containsMatchIn(it) && !locks.containsMatchIn(it) } }
            .map { it.name }.toList()
        assertEquals("key creations outside the mutation lock", emptyList<String>(), unlocked)
    }
}
