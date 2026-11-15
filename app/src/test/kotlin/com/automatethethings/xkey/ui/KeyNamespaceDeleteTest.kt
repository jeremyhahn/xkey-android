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

import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.coVerify
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.io.File
import java.util.Collections

/**
 * A key delete names its namespace from the row picked: a FIDO2 row deletes
 * only its credential alias (`xkey_credential_<id>`) and its metadata, any
 * other row only its general material (`xkey_key_<id>`, the software key, a
 * raw alias). With both namespaces holding ID `k`, neither delete reaches
 * the other's key, and no delete by ID falls back to the other namespace.
 */
class KeyNamespaceDeleteTest {

    private val aliases = Collections.synchronizedSet(hashSetOf("xkey_credential_k", "xkey_key_k"))
    private val metadata = Collections.synchronizedSet(hashSetOf("k"))
    private val rows = Collections.synchronizedSet(hashSetOf("k"))
    private val keyDao = mockk<KeyDao>(relaxed = true).also { dao ->
        coEvery { dao.exists(any()) } answers { firstArg<String>() in rows }
        coEvery { dao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>())) 1 else 0 }
    }
    private val credentials = mockk<CredentialMetadataDao>(relaxed = true).also { dao ->
        coEvery { dao.deleteByCredentialId(any()) } answers { if (metadata.remove(firstArg<String>())) 1 else 0 }
    }
    private val keystore = mockk<KeystoreManager>(relaxed = true).also { ks ->
        every { ks.generalKeyExists(any()) } answers { "xkey_key_${firstArg<String>()}" in aliases }
        every { ks.deleteGeneralKey(any()) } answers { aliases.remove("xkey_key_${firstArg<String>()}") }
        every { ks.deleteByAlias(any()) } answers { aliases.remove(firstArg<String>()) }
        every { ks.deleteKey(any()) } answers {
            aliases.remove("xkey_credential_${firstArg<String>()}") || aliases.remove("xkey_key_${firstArg<String>()}")
        }
    }
    private val software = mockk<SoftwareKeyStore>(relaxed = true).also {
        every { it.contains(any()) } returns false
    }
    private val credential = KeyEntity(
        keyId = "k", keyType = "fido2", algorithm = "ES256", label = "rp", keySizeBits = 256, source = "local"
    )
    private val general = KeyEntity(
        keyId = "k", keyType = "signing", algorithm = "ES256", label = "k", keySizeBits = 256, source = "local"
    )

    @Test
    fun aCredentialDeleteRemovesOnlyTheCredentialAndItsMetadata() = runBlocking {
        assertEquals(R.string.key_deleted, keyDao.deleteKeyForScreen(credential, keystore, software, credentials))
        assertEquals("the general key survives", setOf("xkey_key_k"), aliases.toSet())
        assertEquals("the credential's metadata is gone", emptySet<String>(), metadata.toSet())
        verify(exactly = 0) { keystore.deleteGeneralKey(any()) }
        verify(exactly = 0) { software.delete(any()) }
    }

    @Test
    fun aGeneralDeleteRemovesOnlyTheGeneralKey() = runBlocking {
        assertEquals(R.string.key_deleted, keyDao.deleteKeyForScreen(general, keystore, software, credentials))
        assertEquals("the credential survives", setOf("xkey_credential_k"), aliases.toSet())
        assertEquals("the credential's metadata survives", setOf("k"), metadata.toSet())
        coVerify(exactly = 0) { credentials.deleteByCredentialId(any()) }
    }

    @Test
    fun aCredentialDeleteNeverFallsBackToTheGeneralKey() = runBlocking {
        aliases.remove("xkey_credential_k")
        keyDao.deleteKeyForScreen(credential, keystore, software, credentials)
        assertEquals("the general key is not the credential", setOf("xkey_key_k"), aliases.toSet())
    }

    @Test
    fun aGeneralDeleteNeverFallsBackToTheCredential() = runBlocking {
        aliases.remove("xkey_key_k")
        keyDao.deleteKeyForScreen(general, keystore, software, credentials)
        assertEquals("the credential is not the general key", setOf("xkey_credential_k"), aliases.toSet())
        assertEquals(setOf("k"), metadata.toSet())
    }

    @Test
    fun noKeyScreenDeletesKeyMaterialByIdOutsideTheChokePoint() {
        val root = listOf(File("src/main/kotlin"), File("app/src/main/kotlin")).first { it.isDirectory }
        val ui = File(root, "com/automatethethings/xkey/ui")
        // OathActivity deletes OATH secrets, PivSlotDetailActivity slot keys: neither is a key row by ID.
        val resolving = Regex("""(keystoreManager|keystore)\.(deleteKey|deleteGeneralKey)\(|removeAllKeyMaterial\(""")
        val offenders = ui.walkTopDown().filter { it.isFile && it.extension == "kt" }
            .filter { f -> f.readLines().any { resolving.containsMatchIn(it) } }
            .map { it.name }.toList()
        assertEquals("key screens delete only through deleteKeyForScreen", emptyList<String>(), offenders)
    }
}
