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
package com.automatethethings.xkey.crypto

import com.automatethethings.xkey.storage.FakeKeyPolicyTables
import com.automatethethings.xkey.storage.KeyPolicyStore
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import com.automatethethings.xkey.storage.materialDelete
import io.mockk.coVerify
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

/**
 * #255 review r4: file decryption takes its key agreement inside the key's
 * use gate. A key whose delete was acknowledged, its material delete still
 * owed, decrypts nothing: the gate refuses it before any ECDH.
 */
class FileDecryptDeletedKeyTest {

    @Test
    fun aKeyWhoseDeleteWasAcknowledgedDecryptsNothing() = runTest {
        val tables = FakeKeyPolicyTables()
        val store = tables.store()
        val row = tables.addKey(KEY_ID, SharingPolicyType.PRIVATE)
        // The delete is acknowledged; its material delete fails and is owed.
        assertTrue(store.deleteKey(KEY_ID, row, materialDelete { false }))
        assertTrue("the material delete is owed", store.isDeletionPending(KEY_ID))
        val keystore = mockk<KeystoreManager>(relaxed = true)
        val output = ByteArrayOutputStream()

        val failure = runCatching {
            FileEncryptor(keystore, store).decryptWithKey(KEY_ID, ByteArrayInputStream(header()), output)
        }.exceptionOrNull()

        assertTrue("a deleted key decrypted: $failure", failure is KeyPolicyStore.KeyDeletedException)
        coVerify(exactly = 0) { keystore.performECDH(any(), any()) }
        assertEquals("no plaintext written", 0, output.size())
    }

    /** A well-formed `.xkeyenc` header (version, ephemeral key, salt, IV) and a body. */
    private fun header(): ByteArray {
        val ephemeral = ByteArray(91) { 1 }
        return byteArrayOf(0x01, 0x00, ephemeral.size.toByte()) + ephemeral + ByteArray(32) + ByteArray(12) + ByteArray(32)
    }

    private companion object {
        const val KEY_ID = "file-key"
    }
}
