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

import com.automatethethings.xkey.R
import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.crypto.SoftwareKeyStore
import com.automatethethings.xkey.storage.dao.CredentialMetadataDao
import com.automatethethings.xkey.storage.dao.KeyDao
import com.automatethethings.xkey.storage.entity.KeyEntity
import com.automatethethings.xkey.ui.deleteKeyForScreen
import io.mockk.coEvery
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Collections

/**
 * A delete confirmation names the row it was opened for. When that row is
 * gone by the time the user confirms (the credential deleted and its ID
 * recreated as a general key meanwhile), the delete is refused: the
 * replacement row and its `xkey_key_<id>` material survive.
 */
class KeyDeleteStaleConfirmationTest {

    private val aliases = Collections.synchronizedSet(hashSetOf<String>())
    private val metadata = Collections.synchronizedSet(hashSetOf<String>())
    private val rows = Collections.synchronizedMap(linkedMapOf<String, KeyEntity>())
    private val keyDao = mockk<KeyDao>(relaxed = true).also { dao ->
        coEvery { dao.getByKeyId(any()) } answers { rows[firstArg<String>()] }
        coEvery { dao.exists(any()) } answers { firstArg<String>() in rows }
        coEvery { dao.deleteByKeyId(any()) } answers { if (rows.remove(firstArg<String>()) != null) 1 else 0 }
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

    private val credentialRow = KeyEntity(
        id = 5, keyId = "k", keyType = "fido2", algorithm = "ES256", label = "k", keySizeBits = 256,
        source = "remote_ble", rpId = "example.com", materialNamespace = KeyNamespace.CREDENTIAL.stored
    )
    private val generalRow = KeyEntity(
        id = 6, keyId = "k", keyType = "ec", algorithm = "ES256", label = "k", keySizeBits = 256,
        source = "local", materialNamespace = KeyNamespace.GENERAL.stored
    )

    /** The dialog was opened on the credential; meanwhile it went and `k` came back as a general key. */
    private fun recreateAsGeneralKey() {
        rows.clear()
        metadata.clear()
        aliases.clear()
        rows["k"] = generalRow
        aliases += "xkey_key_k"
    }

    @Test
    fun aConfirmationForARecreatedIdIsRefusedAndTheReplacementSurvives() = runBlocking {
        rows["k"] = credentialRow
        aliases += "xkey_credential_k"
        metadata += "k"
        val captured = rows.getValue("k")
        recreateAsGeneralKey()

        assertEquals(
            "the screen reports the refusal",
            R.string.key_delete_refused,
            keyDao.deleteKeyForScreen(captured, keystore, software, credentials)
        )
        assertEquals("the replacement row survives", generalRow, rows["k"])
        assertEquals("its general key survives", setOf("xkey_key_k"), aliases.toSet())
    }

    @Test
    fun anUnrecordedCapturedRowForARecreatedIdIsRefused() = runBlocking {
        val captured = credentialRow.copy(materialNamespace = null)
        recreateAsGeneralKey()

        assertEquals(0, keyDao.deleteKeyRow(captured, keystore, software, credentials))
        assertEquals(generalRow, rows["k"])
        assertEquals(setOf("xkey_key_k"), aliases.toSet())
    }

    @Test
    fun aConfirmationForAGoneRowRemovesNothing() = runBlocking {
        aliases += "xkey_key_k"
        assertEquals(0, keyDao.deleteKeyRow(generalRow, keystore, software, credentials))
        assertEquals("material with no row of its own is left", setOf("xkey_key_k"), aliases.toSet())
    }

    @Test
    fun aCurrentConfirmationStillDeletes() = runBlocking {
        rows["k"] = generalRow
        aliases += "xkey_key_k"
        assertEquals(
            R.string.key_deleted,
            keyDao.deleteKeyForScreen(rows.getValue("k"), keystore, software, credentials)
        )
        assertEquals(emptyMap<String, KeyEntity>(), rows.toMap())
        assertEquals(emptySet<String>(), aliases.toSet())
    }
}
