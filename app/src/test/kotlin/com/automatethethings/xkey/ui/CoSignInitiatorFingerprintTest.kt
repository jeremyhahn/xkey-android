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

import com.automatethethings.xkey.crypto.KeystoreManager
import com.automatethethings.xkey.media.MediaHasher
import io.mockk.every
import io.mockk.mockk
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The initiator QR names its key by the key's public-key fingerprint, for
 * every key the co-sign screen offers: FIDO2 credentials live under the
 * credential alias, general keys under the general alias.
 */
class CoSignInitiatorFingerprintTest {

    private val credentialDer = ByteArray(91) { 5 }
    private val generalDer = ByteArray(91) { 6 }

    private val keystore = mockk<KeystoreManager> {
        every { resolveKeystoreAlias(CREDENTIAL_ID) } returns "xkey_credential_$CREDENTIAL_ID"
        every { resolveKeystoreAlias(GENERAL_ID) } returns KeystoreManager.generalKeyAlias(GENERAL_ID)
        every { resolveKeystoreAlias(MISSING_ID) } returns null
        every { publicKeyDERAt("xkey_credential_$CREDENTIAL_ID") } returns credentialDer
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(CREDENTIAL_ID)) } returns null
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(GENERAL_ID)) } returns generalDer
        every { publicKeyDERAt(KeystoreManager.generalKeyAlias(MISSING_ID)) } returns null
    }

    @Test
    fun `a credential-namespace key's initiator QR carries its fingerprint`() {
        assertEquals(MediaHasher.hashBytes(credentialDer), initiatorFingerprint(keystore, CREDENTIAL_ID))
    }

    @Test
    fun `a general key's initiator QR carries its fingerprint`() {
        assertEquals(MediaHasher.hashBytes(generalDer), initiatorFingerprint(keystore, GENERAL_ID))
    }

    @Test
    fun `a key with no stored public key is named by its id`() {
        assertEquals(MISSING_ID, initiatorFingerprint(keystore, MISSING_ID))
    }

    private companion object {
        const val CREDENTIAL_ID = "passkey-1"
        const val GENERAL_ID = "general-1"
        const val MISSING_ID = "missing-1"
    }
}
