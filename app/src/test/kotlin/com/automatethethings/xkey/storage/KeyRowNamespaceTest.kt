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

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Collections

/**
 * A key delete takes its namespace from where the row's material is stored,
 * not from the row's key type: local.generateKey stores a FIDO2-type key as
 * the general key `xkey_key_<id>`, a FIDO2 credential lives at
 * `xkey_credential_<id>` with its metadata. When the namespace cannot be
 * told, the delete is refused and nothing is removed.
 */
class KeyRowNamespaceTest {

    private val aliases = Collections.synchronizedSet(hashSetOf<String>())
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
        every { ks.listAllKeystoreAliases() } answers { aliases.toList() }
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

    /** A FIDO2-type row as local.generateKey writes it, with no namespace recorded. */
    private val fido2Row = KeyEntity(
        keyId = "k", keyType = "fido2", algorithm = "ES256", label = "k", keySizeBits = 256,
        source = "remote_ble", rpId = "example.com"
    )

    @Test
    fun aFido2TypeKeyFromGenerateKeyIsDeletedAsAGeneralKey() = runBlocking {
        aliases += "xkey_key_k"
        assertEquals(1, keyDao.deleteKeyRow(fido2Row, keystore, software, credentials))
        assertEquals("its general key is gone", emptySet<String>(), aliases.toSet())
        assertEquals("the row is gone", emptySet<String>(), rows.toSet())
    }

    @Test
    fun aFido2CredentialIsDeletedWithItsMetadata() = runBlocking {
        aliases += "xkey_credential_k"
        assertEquals(1, keyDao.deleteKeyRow(fido2Row, keystore, software, credentials))
        assertEquals(emptySet<String>(), aliases.toSet())
        assertEquals("its metadata is gone", emptySet<String>(), metadata.toSet())
    }

    @Test
    fun aRecordedGeneralFido2KeyDeletesOnlyItsGeneralKeyBesideACredentialOfItsId() = runBlocking {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        val recorded = fido2Row.copy(materialNamespace = KeyNamespace.GENERAL.stored)
        assertEquals(1, keyDao.deleteKeyRow(recorded, keystore, software, credentials))
        assertEquals("the credential survives", setOf("xkey_credential_k"), aliases.toSet())
        assertEquals("its metadata survives", setOf("k"), metadata.toSet())
    }

    @Test
    fun aRecordedCredentialDeletesOnlyItsCredentialBesideAGeneralKeyOfItsId() = runBlocking {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        val recorded = fido2Row.copy(materialNamespace = KeyNamespace.CREDENTIAL.stored)
        assertEquals(1, keyDao.deleteKeyRow(recorded, keystore, software, credentials))
        assertEquals("the general key survives", setOf("xkey_key_k"), aliases.toSet())
        assertEquals("its metadata is gone", emptySet<String>(), metadata.toSet())
    }

    @Test
    fun anUnknownRecordedNamespaceRefusesTheDeleteAndRemovesNothing() = runBlocking {
        aliases += "xkey_key_k"
        val unknown = fido2Row.copy(materialNamespace = "elsewhere")
        assertEquals(0, keyDao.deleteKeyRow(unknown, keystore, software, credentials))
        assertEquals(setOf("xkey_key_k"), aliases.toSet())
        assertEquals(setOf("k"), rows.toSet())
    }

    @Test
    fun anUndeterminableNamespaceRefusesTheDeleteAndRemovesNothing() = runBlocking {
        aliases += listOf("xkey_credential_k", "xkey_key_k")
        assertEquals(0, keyDao.deleteKeyRow(fido2Row, keystore, software, credentials))
        assertEquals(setOf("xkey_credential_k", "xkey_key_k"), aliases.toSet())
        assertEquals(setOf("k"), metadata.toSet())
        assertEquals(setOf("k"), rows.toSet())
    }
}
