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
package com.automatethethings.xkey.ui

import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Collections

/**
 * A key screen's delete reports what happened: a delete refused because
 * material under the key's ID still stands keeps the key listed and says
 * so, never "Key deleted". Both key screens delete through the one report
 * ([deleteKeyForScreen]); neither calls deleteKeyRow and ignores its count.
 */
class KeyScreenDeleteTest {

    private val aliases = Collections.synchronizedSet(hashSetOf("xkey_key_k"))
    private val rows = Collections.synchronizedSet(hashSetOf("k"))
    private val keyDao = mockk<KeyDao>(relaxed = true).also { dao ->
        coEvery { dao.exists(any()) } answers { firstArg<String>() in rows }
        coEvery { dao.getByKeyId(any()) } answers { key.takeIf { firstArg<String>() in rows } }
        coEvery { dao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>())) 1 else 0 }
    }
    private val keystore = mockk<KeystoreManager>(relaxed = true).also { ks ->
        every { ks.generalKeyExists(any()) } answers { "xkey_key_${firstArg<String>()}" in aliases }
        every { ks.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
    }
    private val software = mockk<SoftwareKeyStore>(relaxed = true).also {
        every { it.contains(any()) } returns false
    }
    private val key = KeyEntity(
        keyId = "k", keyType = "signing", algorithm = "ES256", label = "k", keySizeBits = 256, source = "local"
    )

    @Test
    fun aDeletedKeyIsReportedDeleted() = runBlocking {
        assertEquals(R.string.key_deleted, keyDao.deleteKeyForScreen(key, keystore, software, mockk(relaxed = true)))
        assertTrue("k" !in rows)
    }

    @Test
    fun aRefusedDeleteIsReportedAndTheKeyStaysListed() = runBlocking {
        // The Keystore refuses to remove the entry.
        every { keystore.deleteGeneralKey(any()) } returns false

        assertEquals(R.string.key_delete_refused, keyDao.deleteKeyForScreen(key, keystore, software, mockk(relaxed = true)))
        assertTrue("the row stays, so the key stays listed", "k" in rows)
    }

    @Test
    fun noKeyScreenDeletesARowWithoutReportingTheOutcome() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val ui = File(root, "com/automatethethings/xkey/ui")
        val callers = ui.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { f -> f.readLines().any { "deleteKeyRow(" in it && "fun " !in it } }
            .map { it.name }.toList()
        assertEquals("only the report calls deleteKeyRow", listOf("KeyManagementActivity.kt"), callers)
        for (screen in listOf("KeyManagementActivity.kt", "KeyDetailActivity.kt")) {
            assertTrue("$screen deletes through the report", "deleteKeyForScreen(" in File(ui, screen).readText())
        }
    }
}
