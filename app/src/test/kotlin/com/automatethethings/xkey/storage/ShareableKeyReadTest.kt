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
import com.automatethethings.xkey.crypto.SoftwareKey
import com.automatethethings.xkey.crypto.UserKeyKind
import com.automatethethings.xkey.storage.entity.SharingPolicyType
import io.mockk.every
import io.mockk.mockk
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * #270 review r8: when the share read resolves an id to its credential and a
 * software key holds the same id, the share sends the resolved credential's
 * public key, never the software key and never nothing.
 */
class ShareableKeyReadTest {

    @Test
    fun aSoftwareKeyBesideTheResolvedCredentialSharesTheCredential() = runTest {
        val keystore = mockk<KeystoreManager>(relaxed = true)
        every { keystore.exportKind(ID) } returns UserKeyKind.CREDENTIAL
        every { keystore.getPublicKeyPEM(ID, UserKeyKind.CREDENTIAL) } returns CREDENTIAL_PEM
        every { keystore.getPublicKeyPEM(ID, UserKeyKind.GENERAL) } returns GENERAL_PEM
        val material = byteArrayOf(1, 2, 3, 4)
        val software = SoftwareKey(ID, "AES", "symmetric", 128, exportable = true, shareable = true, material = material)
        val tables = FakeKeyPolicyTables()
        tables.addKey(ID, SharingPolicyType.ALL_PEERS)

        val shared = tables.store().readShareable(mockk(), ID, keystore, null) { software }

        assertNull("the same-id software key was shared in the credential's place", shared.software)
        assertEquals("the share sends the resolved credential's key", CREDENTIAL_PEM, shared.publicKeyPem)
        assertTrue("the unshared software material is wiped", material.all { it == 0.toByte() })
    }

    private companion object {
        const val ID = "k-shared"
        const val CREDENTIAL_PEM = "credential-pem"
        const val GENERAL_PEM = "general-pem"
    }
}
